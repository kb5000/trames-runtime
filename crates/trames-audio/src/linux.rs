// SPDX-License-Identifier: GPL-3.0-or-later
//! ALSA PCM on the calling worker. The existing idle executor drives native
//! poll descriptors; there is no Trames audio thread, timer or sample queue.
use super::Notify;
use libc::{c_char, c_int, c_long, c_uint, c_ulong, c_void, pollfd};
use std::{
    ffi::CString,
    io,
    os::fd::{AsFd, BorrowedFd},
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock, Weak},
};
use trames_shared::{HostEvents, HostSubscription, IoSignal, IoWake, ReadinessDriver};

#[repr(C)]
struct Pcm {
    _opaque: [u8; 0],
}
#[repr(C)]
struct Hw {
    _opaque: [u8; 0],
}
#[repr(C)]
struct Sw {
    _opaque: [u8; 0],
}
#[repr(C)]
struct Status {
    _opaque: [u8; 0],
}
// Values/signatures are checked against the installed ALSA headers in CI. The
// native opaque objects are always allocated/freed by the same loaded library.
const RUNNING: c_uint = 3;
const XRUN: c_uint = 4;
const PAUSED: c_uint = 6;
const SUSPENDED: c_uint = 7;
const DISCONNECTED: c_uint = 8;
macro_rules! api {
    ($($name:ident($($arg:ty),*) -> $ret:ty;)+) => {
        struct Api { _library:libloading::Library, $($name:unsafe extern "C" fn($($arg),*)->$ret,)+ }
        impl Api { fn load()->Result<Self,i64> {
            // SAFETY: the stable ALSA C ABI is verified by scripts/check-alsa-abi.py.
            let library=unsafe{libloading::Library::new("libasound.so.2")}.map_err(|_|-95i64)?;
            $(let $name=*unsafe{library.get::<unsafe extern "C" fn($($arg),*)->$ret>(concat!("snd_pcm_",stringify!($name),"\0").as_bytes())}.map_err(|_|-95i64)?;)+
            Ok(Self{_library:library,$($name,)+})
        }}
    }
}
api! {
    open(*mut *mut Pcm,*const c_char,c_uint,c_int)->c_int;
    close(*mut Pcm)->c_int;
    hw_params_malloc(*mut *mut Hw)->c_int;
    hw_params_free(*mut Hw)->();
    hw_params_any(*mut Pcm,*mut Hw)->c_int;
    hw_params_set_access(*mut Pcm,*mut Hw,c_uint)->c_int;
    hw_params_set_format(*mut Pcm,*mut Hw,c_int)->c_int;
    hw_params_set_channels(*mut Pcm,*mut Hw,c_uint)->c_int;
    hw_params_set_rate_near(*mut Pcm,*mut Hw,*mut c_uint,*mut c_int)->c_int;
    hw_params_set_period_size_near(*mut Pcm,*mut Hw,*mut c_ulong,*mut c_int)->c_int;
    hw_params_set_buffer_size_near(*mut Pcm,*mut Hw,*mut c_ulong)->c_int;
    hw_params(*mut Pcm,*mut Hw)->c_int;
    hw_params_get_rate(*const Hw,*mut c_uint,*mut c_int)->c_int;
    hw_params_get_period_size(*const Hw,*mut c_ulong,*mut c_int)->c_int;
    hw_params_get_buffer_size(*const Hw,*mut c_ulong)->c_int;
    sw_params_malloc(*mut *mut Sw)->c_int;
    sw_params_free(*mut Sw)->();
    sw_params_current(*mut Pcm,*mut Sw)->c_int;
    sw_params_get_boundary(*const Sw,*mut c_ulong)->c_int;
    sw_params_set_start_threshold(*mut Pcm,*mut Sw,c_ulong)->c_int;
    sw_params_set_avail_min(*mut Pcm,*mut Sw,c_ulong)->c_int;
    sw_params(*mut Pcm,*mut Sw)->c_int;
    status_malloc(*mut *mut Status)->c_int;
    status_free(*mut Status)->();
    status(*mut Pcm,*mut Status)->c_int;
    status_get_state(*const Status)->c_uint;
    status_get_delay(*const Status)->c_long;
    status_get_avail(*const Status)->c_ulong;
    state(*mut Pcm)->c_uint;
    start(*mut Pcm)->c_int;
    drop(*mut Pcm)->c_int;
    prepare(*mut Pcm)->c_int;
    pause(*mut Pcm,c_int)->c_int;
    resume(*mut Pcm)->c_int;
    writei(*mut Pcm,*const c_void,c_ulong)->c_long;
    readi(*mut Pcm,*mut c_void,c_ulong)->c_long;
    avail_update(*mut Pcm)->c_long;
    poll_descriptors_count(*mut Pcm)->c_int;
    poll_descriptors(*mut Pcm,*mut pollfd,c_uint)->c_int;
    poll_descriptors_revents(*mut Pcm,*mut pollfd,c_uint,*mut u16)->c_int;
}
fn api() -> Result<&'static Api, i64> {
    static API: OnceLock<Result<Api, i64>> = OnceLock::new();
    API.get_or_init(Api::load).as_ref().map_err(|e| *e)
}
fn checked(n: c_int) -> Result<(), i64> {
    if n < 0 {
        Err(i64::from(n))
    } else {
        Ok(())
    }
}
fn os_error(e: io::Error) -> i64 {
    -i64::from(e.raw_os_error().unwrap_or(libc::EIO))
}
fn io_error(e: i64) -> io::Error {
    io::Error::from_raw_os_error((-e) as c_int)
}
struct Source {
    owner: OnceLock<Weak<Mutex<crate::Stream>>>,
    notify: Notify,
    signal: Arc<IoSignal>,
}
impl ReadinessDriver for Source {
    fn attach(&self, events: Arc<HostEvents>) -> io::Result<()> {
        if let Some(owner) = self.owner.get().and_then(Weak::upgrade) {
            owner
                .lock()
                .unwrap()
                .native
                .attach(events)
                .map_err(io_error)?;
        }
        Ok(())
    }
}
impl IoWake for Source {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        if let Some(owner) = self.owner.get().and_then(Weak::upgrade) {
            owner.lock().unwrap().native.ready();
        }
    }
}
struct Attached {
    hub: Arc<HostEvents>,
    subscriptions: Vec<HostSubscription>,
}
pub struct Stream {
    api: &'static Api,
    pcm: NonNull<Pcm>,
    stats: Option<NonNull<Status>>,
    source: Arc<Source>,
    attached: Vec<Attached>,
    capture: bool,
    frame_bytes: usize,
    rate: u64,
    channels: u64,
    period: u64,
    transferred: u64,
    position: u64,
    xruns: u64,
    in_xrun: bool,
    poll_error: Option<i64>,
}
// SAFETY: all PCM calls, readiness filtering and close use the original outer
// per-stream mutex. The weak source cannot outlive or race its native owner.
unsafe impl Send for Stream {}
impl Stream {
    pub fn new(a: &[u64; 16], notify: Notify) -> Result<Self, i64> {
        let api = api()?;
        let capture = a[1] != 0;
        let key = if capture {
            "TRAMES_AUDIO_INPUT_DEVICE"
        } else {
            "TRAMES_AUDIO_OUTPUT_DEVICE"
        };
        let device = CString::new(std::env::var(key).unwrap_or_else(|_| "default".into()))
            .map_err(|_| -22i64)?;
        let mut pcm = std::ptr::null_mut();
        // SAFETY: initialized out pointer and a NUL-terminated device name.
        checked(unsafe { (api.open)(&mut pcm, device.as_ptr(), c_uint::from(capture), 1) })?;
        let source = Arc::new_cyclic(|weak: &Weak<Source>| {
            let target: Weak<dyn IoWake> = weak.clone();
            Source {
                owner: OnceLock::new(),
                notify,
                signal: IoSignal::new(0, target),
            }
        });
        let mut stream = Self {
            api,
            pcm: NonNull::new(pcm).ok_or(-5i64)?,
            stats: None,
            source,
            attached: vec![],
            capture,
            frame_bytes: a[3] as usize * if a[4] == 0 { 2 } else { 4 },
            rate: a[2],
            channels: a[3],
            period: a[5],
            transferred: 0,
            position: 0,
            xruns: 0,
            in_xrun: false,
            poll_error: None,
        };
        stream.configure(a)?;
        Ok(stream)
    }
    fn configure(&mut self, a: &[u64; 16]) -> Result<(), i64> {
        let api = self.api;
        let p = self.pcm.as_ptr();
        // SAFETY: ALSA owns these opaque parameter objects; every early return
        // below frees them, and Stream::drop closes the partially configured PCM.
        unsafe {
            let mut hw = std::ptr::null_mut();
            checked((api.hw_params_malloc)(&mut hw))?;
            let result: Result<(), i64> = (|| {
                checked((api.hw_params_any)(p, hw))?;
                checked((api.hw_params_set_access)(p, hw, 3))?;
                checked((api.hw_params_set_format)(
                    p,
                    hw,
                    if a[4] == 0 { 2 } else { 14 },
                ))?;
                checked((api.hw_params_set_channels)(p, hw, a[3] as c_uint))?;
                let mut rate = a[2] as c_uint;
                let mut direction = 0;
                checked((api.hw_params_set_rate_near)(
                    p,
                    hw,
                    &mut rate,
                    &mut direction,
                ))?;
                if u64::from(rate) != a[2] || direction != 0 {
                    return Err(-22);
                }
                let mut period = a[5] as c_ulong;
                direction = 0;
                checked((api.hw_params_set_period_size_near)(
                    p,
                    hw,
                    &mut period,
                    &mut direction,
                ))?;
                if period as u64 != a[5] || direction != 0 {
                    return Err(-22);
                }
                let mut buffer = a[6] as c_ulong;
                checked((api.hw_params_set_buffer_size_near)(p, hw, &mut buffer))?;
                if buffer as u64 != a[6] {
                    return Err(-22);
                }
                checked((api.hw_params)(p, hw))?;
                checked((api.hw_params_get_rate)(hw, &mut rate, &mut direction))?;
                if u64::from(rate) != a[2] || direction != 0 {
                    return Err(-22);
                }
                checked((api.hw_params_get_period_size)(
                    hw,
                    &mut period,
                    &mut direction,
                ))?;
                checked((api.hw_params_get_buffer_size)(hw, &mut buffer))?;
                if period as u64 != a[5] || direction != 0 || buffer as u64 != a[6] {
                    return Err(-22);
                }
                Ok(())
            })();
            (api.hw_params_free)(hw);
            result?;
            let mut sw = std::ptr::null_mut();
            checked((api.sw_params_malloc)(&mut sw))?;
            let result: Result<(), i64> = (|| {
                checked((api.sw_params_current)(p, sw))?;
                let mut boundary = 0;
                checked((api.sw_params_get_boundary)(sw, &mut boundary))?;
                checked((api.sw_params_set_start_threshold)(p, sw, boundary))?;
                checked((api.sw_params_set_avail_min)(p, sw, a[5] as c_ulong))?;
                checked((api.sw_params)(p, sw))
            })();
            (api.sw_params_free)(sw);
            result?;
            let mut stats = std::ptr::null_mut();
            checked((api.status_malloc)(&mut stats))?;
            self.stats = Some(NonNull::new(stats).ok_or(-5i64)?);
        }
        Ok(())
    }
    pub fn bind_owner(&mut self, owner: Weak<Mutex<crate::Stream>>) {
        let _ = self.source.owner.set(owner);
    }
    pub fn register(&self) -> Result<(), i64> {
        let driver: Arc<dyn ReadinessDriver> = self.source.clone();
        self.source
            .notify
            .register(Arc::downgrade(&driver))
            .map_err(os_error)?;
        self.source.notify.notify();
        Ok(())
    }
    pub fn capture(&self) -> bool {
        self.capture
    }
    fn descriptors(&self) -> Result<Vec<pollfd>, i64> {
        // SAFETY: same locked live PCM; output is initialized and bounded by count.
        unsafe {
            let count = (self.api.poll_descriptors_count)(self.pcm.as_ptr());
            if count < 0 {
                return Err(i64::from(count));
            }
            let mut fds = vec![
                pollfd {
                    fd: -1,
                    events: 0,
                    revents: 0
                };
                count as usize
            ];
            let count =
                (self.api.poll_descriptors)(self.pcm.as_ptr(), fds.as_mut_ptr(), count as c_uint);
            checked(count)?;
            fds.truncate(count as usize);
            Ok(fds)
        }
    }
    fn subscriptions(&self, hub: &Arc<HostEvents>) -> Result<Vec<HostSubscription>, i64> {
        let mut subscriptions = vec![];
        for fd in self.descriptors()? {
            for write in [false, true] {
                if (fd.events & if write { libc::POLLOUT } else { libc::POLLIN }) == 0 {
                    continue;
                }
                // SAFETY: PCM remains open under the same stream lock throughout
                // duplicate/subscribe, and registrations close before snd_pcm_close.
                let original = unsafe { BorrowedFd::borrow_raw(fd.fd) };
                let owned = original.as_fd().try_clone_to_owned().map_err(os_error)?;
                subscriptions.push(
                    hub.subscribe(owned, write, &self.source.signal)
                        .map_err(os_error)?,
                );
            }
        }
        Ok(subscriptions)
    }
    fn attach(&mut self, hub: Arc<HostEvents>) -> Result<(), i64> {
        self.source.signal.reset();
        if let Some(attached) = self.attached.iter().find(|a| Arc::ptr_eq(&a.hub, &hub)) {
            for subscription in &attached.subscriptions {
                subscription.rearm().map_err(os_error)?;
            }
        } else {
            let subscriptions = self.subscriptions(&hub)?;
            self.attached.push(Attached { hub, subscriptions });
        }
        Ok(())
    }
    fn ready(&mut self) {
        let result = (|| {
            let mut fds = self.descriptors()?;
            // epoll reports the descriptor, ALSA interprets its direction and
            // consumes plugin timer/event FDs. Raw POLLIN is not PCM readiness.
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 0) } < 0 {
                return Err(os_error(io::Error::last_os_error()));
            }
            let mut revents = 0;
            checked(unsafe {
                (self.api.poll_descriptors_revents)(
                    self.pcm.as_ptr(),
                    fds.as_mut_ptr(),
                    fds.len() as _,
                    &mut revents,
                )
            })?;
            Ok(revents
                & (libc::POLLIN | libc::POLLOUT | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                    as u16
                != 0)
        })();
        if let Err(error) = result {
            self.poll_error = Some(self.error(error));
        }
        if result != Ok(false) {
            self.source.notify.notify();
        } else {
            self.source.signal.reset();
            for attached in &self.attached {
                for subscription in &attached.subscriptions {
                    if subscription.rearm().is_err() {
                        self.source.notify.notify();
                        return;
                    }
                }
            }
        }
    }
    fn notify_if_ready(&self) {
        let avail = unsafe { (self.api.avail_update)(self.pcm.as_ptr()) };
        if avail < 0 || avail as u64 >= self.period {
            self.source.notify.notify();
        }
    }
    fn error(&mut self, n: i64) -> i64 {
        if n == -32 && !self.in_xrun {
            self.xruns += 1;
            self.in_xrun = true;
        }
        n
    }
    pub fn transfer(&mut self, bytes: &mut [u8]) -> i64 {
        if let Some(error) = self.poll_error {
            return error;
        }
        let frames = bytes.len() / self.frame_bytes;
        // SAFETY: interleaved format/frame geometry is fixed at open. Native
        // transfer is nonblocking and cannot retain this worker-local scratch.
        // C long is 32 or 64 bits according to the Linux target ABI.
        #[allow(clippy::unnecessary_cast)]
        let result = unsafe {
            if self.capture {
                (self.api.readi)(self.pcm.as_ptr(), bytes.as_mut_ptr().cast(), frames as _)
            } else {
                (self.api.writei)(self.pcm.as_ptr(), bytes.as_ptr().cast(), frames as _)
            }
        } as i64;
        if result < 0 {
            return self.error(result);
        }
        self.transferred = self.transferred.saturating_add(result as u64);
        self.notify_if_ready();
        result * self.frame_bytes as i64
    }
    pub fn control(&mut self, op: u64) -> i64 {
        // ALSA plugins may replace descriptors on prepare/start. Remove old
        // identities first, then rebuild subscriptions for existing waiters.
        for attached in &mut self.attached {
            attached.subscriptions.clear();
        }
        let p = self.pcm.as_ptr();
        let result = unsafe {
            match op {
                3 => match (self.api.state)(p) {
                    RUNNING => 0,
                    PAUSED => (self.api.pause)(p, 0),
                    SUSPENDED => (self.api.resume)(p),
                    _ => (self.api.start)(p),
                },
                4 => (self.api.drop)(p),
                5 => (self.api.prepare)(p),
                8 => (self.api.pause)(p, 1),
                _ => -38,
            }
        };
        if op == 5 && result >= 0 {
            self.transferred = 0;
            self.position = 0;
            self.in_xrun = false;
            self.poll_error = None;
        }
        self.source.signal.reset();
        for i in 0..self.attached.len() {
            match self.subscriptions(&self.attached[i].hub) {
                Ok(subscriptions) => self.attached[i].subscriptions = subscriptions,
                Err(error) => {
                    self.source.notify.notify();
                    return error;
                }
            }
        }
        self.notify_if_ready();
        self.error(i64::from(result))
    }
    pub fn status(&mut self) -> Result<[u64; 8], i64> {
        if let Some(error) = self.poll_error {
            return Err(error);
        }
        let s = self.stats.expect("configured status").as_ptr();
        checked(unsafe { (self.api.status)(self.pcm.as_ptr(), s) })?;
        let state = unsafe { (self.api.status_get_state)(s) };
        match state {
            XRUN => return Err(self.error(-32)),
            SUSPENDED => return Err(-86),
            DISCONNECTED => return Err(-19),
            _ => {}
        }
        #[allow(clippy::unnecessary_cast)]
        let avail = unsafe { (self.api.status_get_avail)(s) } as u64;
        let delay = unsafe { (self.api.status_get_delay)(s) }.max(0) as u64;
        let position = if self.capture {
            self.transferred.saturating_add(avail)
        } else {
            self.transferred.saturating_sub(delay)
        };
        self.position = self.position.max(position);
        if avail >= self.period {
            self.source.notify.notify();
        }
        Ok([
            self.position,
            if self.capture { avail } else { delay },
            avail,
            if self.capture { 0 } else { self.xruns },
            if self.capture { self.xruns } else { 0 },
            self.rate,
            self.channels,
            u64::from(state == RUNNING || state == PAUSED),
        ])
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        // No callback holds a strong stream owner here. Cancel duplicates before
        // native close; late HostEvents batches contain only a weak source.
        self.attached.clear();
        unsafe {
            if let Some(stats) = self.stats {
                (self.api.status_free)(stats.as_ptr());
            }
            (self.api.close)(self.pcm.as_ptr());
        }
    }
}
