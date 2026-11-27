# Android 内存生命周期与自动回收（2026-11-27）

本轮是实施队列领域 05。覆盖 `userfaultfd`、`process_mrelease`、全局内存压力及原版 ART／lmkd 调用；不新增生产协调、服务或计时线程。验证使用既有 Linux ARM64 参考机、解释器和 Mac HVF；未做真机验收。

本轮按约定范围完成实现、原版调用方、两平台检查及性能验收。复用项目和未覆盖边界单独列明；产品配对 pins 由对应产品提交校验。

## 实现与边界

- 原 mm 控制通过既有 checkpoint 和弱请求队列执行。取消不留下后续突变；退休的原 mm 不会被后来同 PID 的地址空间替代。mrelease 接纳排队中的 SIGKILL，要求所有 mm 使用者均在退出，保留共享 backing 和独立物理租约。
- UFFD 实现私有匿名 MISSING、API、REGISTER／UNREGISTER、COPY／ZEROPAGE／WAKE、DONTWAKE、read／readv、poll／epoll、dup 和 SCM_RIGHTS。没有声明 WP、MINOR 或事件特性。fork 新 mm 不继承注册，CLONE_VM 共享；关闭、取消、unmap／remap、discard、exec 和退休解除原等待。同页读写者各保留自己的事件。
- 跨进程 COPY 保留已导入的页数据和原 OFD。原 mm 分配遇到压力时释放借用，在现有资源等待上续接；fd 复用和源页后续变化不会改变已接纳的数据。
- PSI 来自实际分配、回收和宿主分页等待；原 OFD 保留打开时权限和触发器。元数据更新和 ready 检查不在运行队列持锁时回调调度器；触发器使用现有 poll／epoll 截止时间。预览不消费事件，实际交付才确认，直接 poll 原子消费。
- 有界会话使用原 aggregate budget 的实际占用。high 为总额的 1/16，限制在 64 KiB–64 MiB；low／min 分别为 high 的 1/2、1/4。压力分配保留原任务，在既有 mm executor 检查实际驻留页后续接，空扫描不会触发就绪重试；总等待有界为两秒。受保护任务可用 reserve，原硬限额继续有效。
- 同一次分配的扫描续接及预检取消保留原 memstall 阶段和两秒截止时间；只有实际准入、取消或原 guest 执行取得进展才结束阶段。元数据作用域不会清除它。未注册或已关闭 UFFD 的普通访存由原子标记直接跳过空注册表，不进入 TLS 或注册表锁。
- HostManaged 的宿主可用内存保持提示，不另设 guest 硬配额。原宿主分页等待和实际 page-out 完成量接入平台无关资源；Apple 通知留在 Mac 边界。宿主内存压力未在本机上强行制造。
- HostManaged 的 PSI 监测本身不启用 syscall 暂存；真正的原生分页等待保留原续接。API-only UFFD 探测不启用暂存，首次成功注册才启用原 mm 的异步缺页摘要；直接 ioctl 根据原 OFD 类型处理外进程控制，不依赖调用方也有异步缺页。
- 无停顿的调度更新只写原子元数据，实际停顿和观察时在原资源内汇总，不在普通调度路径进入 PSI 锁。均值按相同压力比例合并指数区间；触发器保留最早的绝对截止时间，重复就绪更新不能后推它。HostManaged 普通页释放不发送配额等待通知，原生分页事件仍正常唤醒。
- PSI 使用按 CPU 的近似统计、连续衰减平均和窗口观察，未声称与 Linux 的周期采样时间逐位相同。未提供 CPU／IO PSI、guest swap 或 file LRU；不为它们伪造数值。`VmSwap: 0 kB` 对应当前无 guest swap 的实现，是原版 lmkd 选择目标所需字段。

## 固定输入

产品清单固定 Android 13／API 33、Lineage 20 ARM64 Waydroid，而非 Android 16。system ZIP SHA256 为 `5fb8179ed4455f45919c5a2bfbfdd1591619295994ad321217f03bb1dcfc53a7`。原镜像的程序及库没有替换：

| 输入 | SHA256 |
| --- | --- |
| 原镜像 lmkd | `f732b87f1265800bd8e94bfc8aa87abdda932f2f8a9698b9bb6ab933d10992f8` |
| 原镜像 libart.so | `865b1ed05b8d1030f07fc5784067dfd927b45adf3b28cd0cc9085772c9795942` |
| AOSP 13 r83 reaper.cpp | `537171a9e4b2b2b712ff0de4683ba041cfd0900830ee50130163b7f24cfe9a68` |
| AOSP reaper.h | `e3ff1ab26d9ad1aaf32de8cee53c1d39201c58f97d73b62f662f25e3ffd750bc` |
| AOSP lmkd.cpp | `98af7bc1f8490281f64fead080317d190ca17c92de026057e1256fb2c50935fa` |
| AOSP ART heap.cc | `a857b8bfad86e6877ec7bcc314ad2033f9ea89576ff838289cf0cd566c2b5a50` |

调用依据为 [AOSP Android 13 r83 lmkd](https://android.googlesource.com/platform/system/memory/lmkd/+/refs/tags/android-13.0.0_r83/)、[Linux PSI 实现](https://github.com/torvalds/linux/blob/v7.0/kernel/sched/psi.c)。PSI 写入缓冲区最多导入 32 字节、最后一字节被替换为 NUL；原生对照发现该细节后同步实现。

ART 实际 collector 是 concurrent-copying。post-fork 的 UFFD features=0 协商及六种零长度 ioctl 是能力探测，不能据此称已启用并发压缩或产生 GC 加速。

## 集中验证

最终原始证据位于产品仓库 `target/validation-android-memory-20261127`，Linux 证据位于 `target/local-ci/io/android-memory-20261127`。每阶段有超时、进程组清理、磁盘下限及 JSON 结果；libtest 四并发、每例 30 秒。源码清单为 `runtime-source-final.json`，产物和上游输入均记录 SHA256。

最终生产源码基于 Runtime `88be4442`。Mac 构建快照的 Rust 源码、Cargo manifests／lock 与当时 Mac 主线及本轮桥接逐文件一致；后续 `ae7cb01` 仅更新网络验收记录。P19 源码清单含 1,289 个非文档文件，SHA256 为 `5e812161f4e174e542f3b901c0d9973bb15bf0aa8cec946868d6738c4ad857ac`；文档收尾不触发重建。

| 最终验收产物 | SHA256 |
| --- | --- |
| 解释器 release | `bde314f50cdbb1bf6df8aba7d5a8efa971affe62c5988f2c8d34da5cf954acc0` |
| 签名 HVF release | `9183fba9c06346e833fa21a5aa9b5d8045e31466bf38798573244444dd7627c5` |
| Linux／解释器／HVF 同 ELF 探针 | `1f4f687aab8d3c6eb641ad476b4dbd316d3708f5f279d57e225c08de5e47c426` |
| ART DEX | `95fb77c7fd088672d052ecb7af0d30fd8110a455a5de8f159b35d877a2b425bd` |

| 项目 | 结果／证据 |
| --- | --- |
| Apple 五库资源测试 | **2364 通过／5 既有忽略**，无失败或超时；`apple-units-p19` |
| Linux 五库资源测试 | **2374 通过／5 既有忽略**，无失败或超时；`linux-units-p19` |
| Apple 严格 clippy | 通过；`apple-clippy-p19` |
| Linux 严格 clippy | 五库 P19 通过；`linux-clippy-p19`；复用源文件未变的 `linux-session-p15` |
| Linux 原生同 ELF 生命周期 | 通过；`native-lifecycle-final.stdout` |
| 最终 HVF release 同 ELF 生命周期 | 通过；`hvf-lifecycle-p19` |
| 最终解释器同 ELF 生命周期 | 通过；`interpreter-lifecycle-p19` |
| Apple 组合内核 | **547 通过／3 既有忽略**；复用未变 Kernel／session 路径 `kernel-units-p15` |
| iOS Rust、执行边界 | P19 iOS ARM64 release 及 Runtime 边界通过；产品 pin 校验见配对产品提交 |
| 原版 Zygote／Reaper／自动回收 | P19 组合通过；`android-combined-p19`，自动回收另连续 **10／10** 通过 |
| 原版 ART 安静性能对照 | 三对通过；`art-performance-p19/analysis.json`；GC 暂停与 System.gc 调用时间分别报告 |

同 ELF 探针覆盖 PSI 原 OFD、UFFD 权限／零长度探测、真正 missing 读写、非对齐 COPY、同页多个等待者、DONTWAKE／WAKE、fork、最后关闭、SCM_RIGHTS 外进程处理、USER_MODE_ONLY 内核拷贝 EFAULT、存活 CLONE_VM 使用者及 pidfd／mrelease 退出竞态。

原版 Reaper 组件夹具仅负责创建目标和调用接口，链接未修改 AOSP reaper.cpp 及原镜像平台库；其输入／命令记录于 `reaper-harness-provenance.json`。自动回收另用镜像内 daemon：测试程序只通过原协议注册优先级和实际触页，不发送终止信号。

最终 P19 组合验收中，原 Zygote 创建 uid=1000 子进程，ART 完成 512 MiB 分配并得到 checksum=3145728；子进程活跃时 VmRSS 为 **71,976 KiB**，随后原 mm 退出、`/proc/40/status` 消失。独立 Zygote 子进程会启动 Binder 线程，夹具显式调用 `System.exit(0)` 请求正常进程结束，不把 Java main 返回当作进程退出。

`automatic-release-p19/results.json` 连续 **10／10** 通过。全部由原版 lmkd 选择 adj=900 缓存目标；四个真实 guest 分配线程均完成，分配者退出码 0。可用内存每轮回升 **65,560–65,564 KiB**，FULL 累计 **701,655–708,260 μs**，保持原版 700 ms 阈值。组合验收另一次为 **297,328→362,892 KiB**。这里 exit_mmap 均先赢，原版 mrelease 返回 ESRCH；未修改 AOSP Reaper 的独立组件成功路径也已通过，不强制竞态获胜顺序。

关闭 PSI 的测试仅用于归因；最终 ART 及自动回收均确认原版监测开启。HostManaged 宿主压力未强行制造，十轮自动回收使用真实 384 MiB 有界资源，而非宿主 OOM。

## 已保留的定位证据

- `art-automatic-p6b`／`p7`：原工作线程视图未保留压力源，随后控制文件打开分类遗漏；分别得到 ENOENT／EIO。已修正共享发布和直接打开路径。
- `art-automatic-p8`：运行时停滞，测试有界终止。确认并修正运行队列元数据回调的锁重入路径。采样及调试器附加未成功获取线程栈，不能将其当作栈证据。
- `p10b`：分配者到达原限额，暴露事件被内部预览消费及仅一次扫描的问题。子进程继承输出还会延迟失败结果，夹具已修正。
- `p11`：单分配者 FULL 约 480 ms，未到原版 700 ms 阈值。改用四个真正 guest 分配线程，共 320 MiB，保持原阈值；它们仅是测试负载。
- `p12`：FULL 超过阈值，原版处理事件仍未杀目标；AOSP 调用方要求 VmSwap，缺失会直接丢弃候选。补真实零 swap 字段。
- `p13`：原版 daemon 自选 adj=900 目标、发出 SIGKILL，分配者完成；可用内存 **297368→362928 KiB**。daemon 记录释放目标约 64 MiB RSS。此轮 exit_mmap 先完成，原版 mrelease 返回 ESRCH；原组件的成功回收验收独立保留。
- `p14`：优化 release 暴露扫描续接反复结束 memstall 的生命周期错误，调试产物通过不足以覆盖该路径。已修正为原分配阶段跨重试、元数据预检保持连续，仅原 guest 执行进展清理取消残留；原截止时间不重新计时。`p15` release 连续三轮及组合验收均通过，补相应资源回归。
- `p15` 安静 ART 三对测量：候选耗时中位 451.53 ms、基线 392.55 ms，约 +15%。同一二进制仅在一次性测试 store 关闭 PSI 监测时为 389.21 ms，确认开销来自开启监测的路径。P16 一并修正该门控和 API-only UFFD 探测的过早启用，保留原版默认压力策略；该门控修正未单独消除吞吐差距。
- `p16` 修正门控后，ART 三对测量仍为 445.87／388.10 ms；额外遥测三轮 some 累计仅 1 μs、full=0，确认主要开销不是实际压力。PSI 均值原来每次调度状态变化都执行六次指数衰减；P17 按相同压力比例合并指数区间，只在比例变化及读取统计时计算。新增回归对比 100 次逐步计算与合并结果，绝对误差小于 1e-10；累计时间、触发器窗口、回收和唤醒路径未改。

- `p17`／`p18`：合并均值计算及空闲原子元数据均通过资源测试，但没有单独消除 ART 差距。P18 三轮自动回收中一次失败，FULL 达 1,416,735 μs 而分配者最终 SIGKILL；该轮未记作通过。发现原 PSI 截止时间在反复就绪检查时后移，HostManaged 普通页释放也会无必要地唤醒监测。
- `p19`：同时固定最早截止时间、取消无活动且不足阈值的计时，以及只对有界配额释放发送等待通知。新增确定性回归覆盖截止时间不后移、HostManaged 不发送普通释放通知；原生事件仍唤醒。最终十轮自动回收及三对 ART 验收通过。

原版 gVisor 256 身份检查的初次默认模式结果为每执行器 249 通过／6 跳过／1 版本门槛失败；`PidfdThreadTracksSingleThread` 的 ENOENT 与 Linux 7 原生一致，但上游按所报 uname 6.0 选择旧 EINVAL。P16 产物按既定模式复核：255 默认身份各 249 通过／6 跳过，仅上述身份使用上游 `--test-on-gvisor` 模式通过，合并为两端各 **250 通过／6 跳过**。`gvisor-final-audit.json` 核对全部身份不缺失、不重复、suite ELF hash 一致，未改断言；P17–P19 只改 PSI 监测／统计路径，该固定集合没有启用 PSI 监测，按范围复用结果。未向历史全量累计台账重复增加身份。

## 最终性能对照

`performance-p16/results.json` 使用相同普通负载 ELF、内容校验、2 CPU、APFS 克隆种子，六块交替 AB／BA，每块每版本三次。before 为已交付 cgroup 收尾产物，after 为 P16 release 及已整合的主线产品依赖。guest 单调时钟排除导入／启动；构建及功能回归结束后顺序测量。P17–P19 仅调整已开启 PSI 的统计／唤醒，该普通夹具没有开启监测，按范围复用数据。

| 执行器 | IO | metadata | pipe |
| --- | ---: | ---: | ---: |
| 解释器中位耗时变化 | −0.10% | −3.56% | −1.14% |
| HVF 中位耗时变化 | −0.52% | −0.07% | −0.31% |

配对块原始波动保留，不据这些小差值推断稳定提速。早期无条件 UFFD TLS 导致约 17% pipe 倒退的失败数据也保留，未作为最终结果。

最终 `art-performance-p19/analysis.json` 为三对交替顺序、每次启动一个原版 ART、同一 DEX、4 CPU、HostManaged，PSI 监测始终开启。每次 32 轮、累计分配 512 MiB、保留 8 MiB、checksum=3145728。候选中位耗时 **392.18 ms**，基线 **405.94 ms**，差值 **−3.39%**；三对候选均更快，但样本数不足以宣称 GC 加速。先前约 15% 的倒退未再复现。

| 指标（三次样本，μs） | 基线 | P19 |
| --- | --- | --- |
| System.gc 调用 P95 | 238.625／747.459／608.000 | 293.042／644.375／290.250 |
| ART 自报实际暂停 Max | 1361／77／143 | 214／150／653 |

ART 的 `99% C.I.` 是原 histogram 区间，未将其改称 P99；上表实际暂停 Max 与 Java 调用延迟分别取自各自来源。保留原始 GC count、暂停分布和吞吐记录；未声称零开销、并发压缩已启用或 GC 尾延迟确定改善。

## 重跑入口

产品仓库保存 `tests/fixtures/android-memory-{lifecycle.c,reaper.cpp,automatic.c,zygote.c}`、`AndroidMemoryStress.java` 和 `tests/integration/android-memory.py`。生命周期探针用 ARM64 musl 静态编译；Android C 夹具用 API 33 sysroot 编译，Java 用 `javac --release 8` 和 D8 `--min-api 33` 生成 DEX。Reaper 组件必须链接上述未修改 AOSP 源码和原镜像平台 `libc++.so`／`libprocessgroup.so`；不能使用命名空间不同的 NDK C++ ABI。确切命令、源／库 hash 见 `reaper-harness-provenance.json`。

已导入固定镜像的独立测试 store 可运行：

```sh
python3 tests/integration/android-memory.py \
  --runner target/validation-android-memory-20261127/trames-hvf-android-memory \
  --store target/validation-android-memory-20261127/android-init-store \
  --dex target/local-ci/io/android-memory-20261127/dex/classes.dex \
  --reaper target/validation-android-memory-20261127/lmkd-reaper-harness \
  --zygote-client target/local-ci/io/android-memory-20261127/android-memory-zygote \
  --automatic target/local-ci/io/android-memory-20261127/android-memory-automatic \
  --samples 3 --output target/validation-android-memory-20261127/rerun
```

驱动有界清理其宿主进程，修改测试 store 内的 init／测试文件；本轮没有修改已注册 Android 环境的 store。测试阶段超时和磁盘下限由外层 `stage.py` 负责，单例超时不扩展为整夜等待。
