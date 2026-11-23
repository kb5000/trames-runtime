// SPDX-License-Identifier: GPL-3.0-or-later
//! Legacy Netfilter socket controls, scoped to the socket's original namespace.
use super::{net, u32_at, Access, CpuMemory, Errno, Linux, Result};
use trames_net::{
    encode_address,
    xtables_abi::{ENTRIES_HEADER, INFO_SIZE, MAX_IMAGE, REPLACE_HEADER},
    NetError,
};
use trames_vfs::{DescriptorFactory, SocketOperation};

pub(super) fn handles(number: u32, args: [u64; 6]) -> bool {
    matches!(args[1] as u32, 0 | 41)
        && matches!((number, args[2] as u32), (208 | 209, 64 | 65) | (209, 80))
}

pub(super) fn control(
    factory: &DescriptorFactory,
    socket: &SocketOperation,
    number: u32,
    args: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64> {
    let family = if args[1] as u32 == 0 { 2 } else { 10 };
    let domain = socket.get_option(1, 39).map_err(net)?;
    if domain != i32::from(family)
        && !(domain == 10 && family == 2 && socket.get_option(1, 3).map_err(net)? != 3)
    {
        return Err(Errno(92));
    }
    let option = args[2] as u32;
    let pointer = args[3];
    let length = args[4];
    if number == 209 && option == 80 {
        let capacity = u32_at(memory, length)?;
        let size = if family == 2 { 16 } else { 28 };
        if capacity < size || capacity > i32::MAX as u32 {
            return Err(Errno(22));
        }
        let address = socket.original_destination(family).map_err(net)?;
        Linux::check(memory, length, 4, Access::Write)?;
        memory
            .write(pointer, &encode_address(address))
            .map_err(|_| Errno(14))?;
        memory
            .write(length, &size.to_le_bytes())
            .map_err(|_| Errno(14))?;
        return Ok(0);
    }
    let capacity = if number == 209 {
        u32_at(memory, length)? as usize
    } else {
        length as u32 as usize
    };
    if !factory
        .local_credentials()
        .has_ns_cap(socket.user_namespace(), trames_vfs::capabilities::NET_ADMIN)
    {
        return Err(Errno(1));
    }
    if number == 209 {
        let header_len = if option == 64 {
            INFO_SIZE
        } else {
            ENTRIES_HEADER
        };
        if capacity < header_len
            || option == 64 && capacity != INFO_SIZE
            || capacity > ENTRIES_HEADER + MAX_IMAGE
        {
            return Err(Errno(22));
        }
        let mut header = [0; INFO_SIZE];
        memory
            .read(pointer, &mut header[..header_len])
            .map_err(|_| Errno(14))?;
        let data = socket
            .xtables_get(family, option, &header[..header_len], capacity)
            .map_err(net)?;
        Linux::check(memory, length, 4, Access::Write)?;
        Linux::check(memory, pointer, data.len(), Access::Write)?;
        memory.write(pointer, &data).map_err(|_| Errno(14))?;
        memory
            .write(length, &(data.len() as u32).to_le_bytes())
            .map_err(|_| Errno(14))?;
    } else {
        let header_len = if option == 64 {
            REPLACE_HEADER
        } else {
            ENTRIES_HEADER
        };
        if !(header_len..=header_len + MAX_IMAGE).contains(&capacity) {
            return Err(Errno(22));
        }
        Linux::check(memory, pointer, capacity, Access::Read)?;
        let mut data = vec![0; capacity];
        memory.read(pointer, &mut data).map_err(|_| Errno(14))?;
        if option == 64 {
            socket
                .xtables_replace(family, &data, |pointer, counters| {
                    Linux::check(memory, pointer, counters.len(), Access::Write)
                        .map_err(|error| NetError(error.0))?;
                    memory.write(pointer, counters).map_err(|_| NetError(14))
                })
                .map_err(net)?;
        } else {
            socket.xtables_add_counters(family, &data).map_err(net)?;
        }
    }
    Ok(0)
}
