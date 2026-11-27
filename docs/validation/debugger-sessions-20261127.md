# 真实调试工具验收，2026-11-27

领域 06 按约定范围完成。原版 GDB、gdbserver、strace 在解释器和 Mac HVF 的完整会话均为 **14/14**；两后端的单执行槽复核各 **8/8**。同一工具和夹具在 ARM64 Linux 7.0 对照为 **14/14**。没有新增生产协调／服务线程、轮询消息总线或宿主调试代理。

## 实现

- ptrace 控制及 PEEK／POKE 保留原 tracer **任务**身份，兄弟线程不能凭同一 TGID 操作其 tracee；普通 wait 的线程组语义独立保留。对应 Linux 的 `child->parent == current` 和原 attach 凭据。
- 非 leader exec 交接观察者时，先解锁替代任务的 trace slot，再派发等待通知、退役回调及 stop acknowledgement，避免回调进入运行队列时持有 trace slot。
- SEIZE 自动继承追踪的子任务以 `PTRACE_EVENT_STOP/SIGTRAP` 开始；原有 ATTACH 子任务仍为 SIGSTOP，真实组停止状态仍按其信号报告。否则原版 strace 会将新生任务误判为组停止，进入 LISTEN 等待本不应需要的 SIGCONT。
- 远程内存服务唤醒任务时，保留 ptrace syscall-entry stop 的待执行 SVC，直到 tracer 恢复它。已接受的资源复制可继续完成；尚未接受的 syscall 不产生效果。此前 exec 可能在调试器读取 argv 时提前发生，导致父线程的 strace 记录被隐藏。

使用现有原任务、mm 和执行 worker；普通无待执行 SVC 的路径沿用原停止查询。没有增加全局锁或为原生函数叠加权限策略。

语义依据：[Linux 7.0 ptrace](https://github.com/torvalds/linux/blob/v7.0/kernel/ptrace.c)、[ptrace 手册的 SEIZE 继承语义](https://man7.org/linux/man-pages/man2/ptrace.2.html)。

## 原版会话

输入为官方签名 Alpine v3.22 aarch64 APK：GDB/gdbserver 15.2、strace 6.13、Python 3.12.16。APK 安装使用原可信密钥、离线仓库及签名验证，工具二进制未经修改。三端的工具与夹具 ELF hash 一致；完整版本、构建命令、镜像 hash、用例身份及结果见[机器记录](debugger-sessions-20261127.json)。

| 会话 | Linux | 解释器 2 CPU | HVF 2 CPU |
| --- | --- | --- | --- |
| 原 tracer 线程所有权，兄弟 GETREGSET／PEEKDATA／CONT 拒绝 | pass | pass | pass |
| GDB live attach | pass | pass | pass |
| 已有多线程 attach | pass | pass | pass |
| 追踪期间创建线程 | pass | pass | pass |
| 显式 detach，目标独立完成 | pass | pass | pass |
| gdbserver attach | pass | pass | pass |
| gdbserver launch | pass | pass | pass |
| gdbserver detach | pass | pass | pass |
| 无权限且 nondumpable 的 attach 拒绝 | pass | pass | pass |
| 停止时调试器被 SIGKILL，目标自动脱离并完成 | pass | pass | pass |
| 目标退出 23，调试器和自然父进程均取得状态 | pass | pass | pass |
| 多线程目标停止时被杀，调试器取得 SIGKILL | pass | pass | pass |
| `strace -f` 跨 fork／exec／wait／exit | pass | pass | pass |
| `strace -f` 跨非 leader exec 及 PID 替换 | pass | pass | pass |

GDB 会话实际写入目标全局变量、修改 x19、在存储指令处单步并检查 PC 增加 4；目标程序独立检查写入后的值和线程检查点数。gdbserver 使用已有隔离虚拟网络中的真实 TCP RSP。它实际监听通配地址，不能用拒绝该绑定的宿主直连 loopback 策略冒充远程调试验收。

两端 1 CPU 各复核八项：多线程 attach、追踪期间 clone、detach、gdbserver attach、调试器异常退出、停止目标被杀、strace fork/exec、strace 非 leader exec。阻塞任务释放执行槽，无新协调线程。

GDB 在已死亡的多线程目标上可能先报寄存器 ESRCH，再异步取得 SIGKILL；原生 Linux 的 GDB 自带事件日志也复现此顺序。夹具先等待终止事件再发 quit，保留 ESRCH 日志及自然父进程的原始退出状态。每项及外层均有截止时间和所属进程组清理，独立失败继续收集。

## 回归及平台检查

- Apple／Linux kernel 库各 **204 passed**，包括原 tracer、非 leader exec 通知解锁、SEIZE 新生事件三项资源回归。Linux session 库 **11 passed**。
- 最终产品内核组合 **547 passed、3 ignored**。Apple／Linux 对受影响 kernel 和 session 的严格 Clippy、Runtime 格式与执行边界检查通过。
- 最终解释器 release、签名 HVF release、iOS ARM64 Rust archive 构建通过。Mac 原参数接线沿用已发布 `f620fa2`；不覆盖其他领域代码。
- 六组原版 gVisor 共 **166 个身份**，两执行后端各 **165 passed、1 upstream skipped**，全部参考通过身份对齐。包括 ptrace 36、process-vm 51、wait 64、exec 7、fork 4、vfork 4。唯一跳过为原版 `PtraceTest.SetYAMAPtraceScope` 的 Native 平台保护。
- 最后 worker 修正后，解释器只重跑受影响的 **38 项**，其余 **128 项**复用同批已通过结果；HVF 166 项在最终候选全部运行。旧 Linux 台账两个计时异常以相同 ELF 单独复核为通过，原始结果保留。未增加全量 gVisor 台账身份，也未重跑无关 CPU／网络／图形／ART 全量验收。

本轮没有新的性能测量结论。未改变既有 allocator、FUSE、内存压力或网络实现；普通未追踪工作负载的既有证据不重复记为新结果。

## 支持边界及证据

支持本记录覆盖的 AArch64 general/FPSIMD/TLS、软件断点、实际单步、任务／syscall 事件和生命周期。硬件断点／观察点、SVE／SME 调试 regset，以及 seccomp tracing／checkpoint 扩展仍不在本轮支持范围；原版 GDB 的不可用硬件资源提示保留。物理 iPad 验收未运行。

共享 Runtime 基线为 `8bd058556ffb35be8e127afbaf7c1c26dae998d9`。原始会话、命令文件、GDB/strace 输出、GoogleTest XML、逐项账本、失败批次和 source manifest 位于 iPad checkout 的 `target/validation-debugger-20261127`；签名包输入及 Linux 对照在 `target/local-ci/io/debugger-20261127`。早期启动参数错误、旧 Mac 参数入口错误、停止状态错误与提前执行导致的失败均单独保留，未作为最终通过结果。
