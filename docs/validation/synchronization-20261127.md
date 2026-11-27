# futex2／rseq 集中验收（2026-11-27）

本批接续 Runtime `167b66acad47872db699f9009bc27fc9533ae765`。先完成同步领域实现、调用方和验收输入，再集中编译与运行。生产改动均位于平台无关的 session；不新增协调、资源服务或定时线程，不添加轮询总线、普通访存屏障或全局算法锁。原版 rseq 资源实现和 legacy futex 队列算法未修改。

## 实际修正

- 四个 futex2 入口共用原 futex 表。`futex_wake` 的严格零计数保持不唤醒；负 `int nr` 按 Linux 在选择首个匹配等待者后检查计数的行为唤醒一个。
- `futex_waitv`／`futex_wait` 带绝对超时的信号返回采用 Linux `ERESTARTSYS` 语义：安装 SA_RESTART 的 handler 返回后重新进入原 SVC；原绝对时间仍由调用参数表示。无 SA_RESTART 返回 EINTR。handler restart 是新入口，与下述后备缺页续接不同。
- 后备异步缺页不再被 futex2 导入／活值比较折叠成 EFAULT。保留已接受的标量、向量成员、跨页复制片段和原绝对 deadline，随原 Job → Done → Process／session continuation 续行。仅实际缺页时分配保留的调用；阻塞交还执行槽，通过原 PageWait 通知恢复。
- 活值比较仍在原 keyed bucket 的入队／requeue 边界内重读；元数据页等待前没有可消耗 wake 的票据。失败、超时、信号和退出清理原逻辑 waiter 的所有成员。未增加 guest 访存权限策略。
- 当前 Linux 要求 requeue 两个成员 flags 相同，继续拒绝混合 private/shared flags。v6.12 源码曾允许两者不同；本批 ARM64 Linux 7.0.0-44 参考与当前上游实现均要求相同。没有将旧版本的允许行为作为本批目标。

## 固定输入和支持边界

- gVisor 原始源 `89cacadae21eca4270a8f7c79281d0426d33ac5f`，与 `tests/gvisor/upstream.json` 的源码及依赖校验相同。原版 `rseq_test` 驱动和 ARM64 helper 均不修改。helper 使用原始 `critical_arm64.S`、`start_arm64.S` 和 `rseq.cc`，按上游 freestanding／static／nostdlib 配方链接，不混入 libc、allocator 或 GTest main，放在原始 `_main/test/syscalls/linux/rseq/rseq` runfile 位置。ARM64 上游共有 13 项；x86 专用 membarrier 项本就不属于 ARM64 清单。
- Linux v6.12 原始 futex 自测 `futex_waitv`、`futex_wait`、`futex_requeue`；rseq `basic_test`、`basic_percpu_ops_test`、`basic_percpu_ops_mm_cid_test`，以及 CPU／mm_cid 两种 `param_test`。全部保留原断言和源码；rseq 自测与其原始 rseq.c 静态链接，避免另引入 guest 动态库环境。参数化原版程序使用 4 线程、每线程 1000 次，覆盖 spinlock、list、buffer、memcpy、increment，再覆盖 yield／signal 注入。
- 上述 Linux 输入取自 [固定 v6.12 源码](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/tools/testing/selftests/)，源文件 URL 与 SHA256 保留在原始账本。当前 requeue 限制见 [Linux v7.0 futex syscall](https://github.com/torvalds/linux/blob/v7.0/kernel/futex/syscalls.c)。
- 新增 `tests/fixtures/synchronization.c` 使用原版 Ubuntu glibc 2.39 静态库，GCC 13.3 编译。同 ELF 在 Linux、解释器和 HVF 上运行；关闭 rseq 使用 glibc 自带 `GLIBC_TUNABLES=glibc.pthread.rseq=0`，不改 libc 的启动、TLS 注册或 sched_getcpu 实现。
- guest 支持 U32、private／shared 四个 futex2 接口。其他位宽和可选 NUMA／MPOL flags 未广告。rseq 维持已实现的 legacy ABI：auxv feature size 28、alignment 32；本轮 glibc 以 32 字节注册。没有宣称支持新 rseq V2、slice extension、硬件 PMU 或原版 ARM64 未实现的 rseq membarrier。

## 集中验证

| 项目 | ARM64 Linux 参考 | 解释器 | Mac HVF |
| --- | ---: | ---: | ---: |
| 原版 gVisor futex | 67/67 | 67/67 | 67/67 |
| 原版 gVisor rseq（实际 helper） | 13/13 | 13/13 | 13/13 |
| 原版 gVisor rseq，单执行槽 | — | 13/13 | 13/13 |
| 原版 Linux futex 自测程序 | 3/3 | 3/3 | 3/3 |
| 原版 Linux rseq 程序／参数组合 | 15/15 | 15/15 | 15/15 |
| 新 glibc 夹具，默认／fallback | 各 9 组通过 | 各 9 组通过 | 各 9 组通过 |
| 新 glibc 夹具，1／4 CPU | — | 各 9 组通过 | 各 9 组通过 |
| 原版 basic_test，单执行槽 | — | 通过 | 通过 |

新增夹具覆盖参数校验、32 位计数／flags 截断、位集、严格零／负数 wake、同 flags private/shared requeue 与混合拒绝、waitv 索引和其他成员清理、绝对超时、EINTR／SA_RESTART、memfd 共享别名跨 fork、阻塞任务退出，以及原版 glibc CPU 身份／affinity／信号／抢占与回退。

两个固定大压力程序各使用原版 200 线程，并在链表阶段执行两千万次 sched_yield。最初的 60 秒预算没有覆盖完成；随后只补跑这两项，240 秒硬上限下全部通过，单项约 149–151 秒。两端的 CPU／mm_cid 版本均实际打印并完成 spinlock 和 percpu_list 阶段，不计作 skip，也没有下调原版循环或线程数。补跑时两个后端、各两个程序同时运行；这些时长只用于诊断测试预算，不作为后端性能排名。

产品 interpreter conformance **553 通过、3 原有忽略，共 556**；其中新增 worker 回归验证唯一执行槽在真实后备缺页时让给 peer，经过 source 返回、向量替换和页就绪后仍按原始向量入队与唤醒。原有并发双地址唤醒、单逻辑完成、requeue／timeout 清理和 legacy futex 回归一并通过。Apple／Linux session 单元各 **16/16**；两端严格 Clippy、session completion／host execution 边界检查和 iOS ARM64 source-checked Rust archive 构建通过。未修改的 kernel、CPU、网络、图形和 ART 既有通过结果复用。

## 性能对照

同一静态 glibc ELF，对比 Runtime 167b66a 的已验证解释器／HVF 与本批候选；每种后端按 1／4 CPU、rseq 默认／fallback 各运行三次，baseline／candidate 交替顺序。每项为一万次 legacy FUTEX_WAKE_PRIVATE、一万次 glibc sched_getcpu、四个 pthread 的四万次 mutex 临界区。时间来自 guest CLOCK_MONOTONIC，排除启动／镜像导入；mutex 总数有精确断言。执行时不并发运行其他验证任务。

短样本出现约 10–18% 波动后，仅追加性能复核：先运行一万次预热，再测量二十万次 wake／getcpu 与四线程八十万次 mutex 操作，交替 baseline／candidate 各五次，并从同一已安装种子克隆存储，避免镜像导入和冷启动影响。结果如下（各五次中位数，默认启用 glibc rseq）：

| 后端／CPU | legacy wake：基线 → 候选，ns/次 | mutex：基线 → 候选，操作/秒 |
| --- | ---: | ---: |
| 解释器／1 | 174.72 → 175.78 | 1,317,528 → 1,320,077 |
| 解释器／4 | 188.94 → 188.62 | 505,546 → 507,735 |
| HVF／1 | 1,038.50 → 1,034.66 | 266,407,630 → 273,749,947 |
| HVF／4 | 1,047.90 → 1,045.88 | 69,995,844 → 72,636,200 |

旧 futex 耗时变化约 −0.4% 至 +0.6%，mutex 中位吞吐持平或略升，未复现短样本的回退。HVF／4 关闭 rseq 时 wake 为 1,049.53 → 1,046.21 ns，mutex 为 69,755,018 → 72,400,647 操作/秒，结论相同。

确认静态 ELF 的原版 sched_getcpu 直接读取 TLS 中 cpu_id，负值才执行 SYS_getcpu；功能夹具验证正常 rseq_size 为 32、opt-out 为 0。候选 HVF／4 预热后该调用约 0.85 ns/次，原版 glibc fallback 约 1,080.8 ns/次。此收益只描述该微型循环避免 syscall exit，不代表整个应用同倍加速；sub-ns 数字取批量时间平均，单次延迟精度低于这一数字。解释器／4 在相同预热和二十万次测量下，候选快速路径为 175.67 ns/次，fallback 为 365.95 ns/次，约 2.08 倍；单独复核的 fallback 旧 wake 为 187.18 → 188.60 ns（+0.8%），mutex 为 500,351 → 501,393 操作/秒。以上为所选微型工作负载的实测，不推广到其他 glibc 或应用。

## 原始账本与复现

配套 JSON 保存源哈希、相同 ELF 哈希、逐项结果、性能样本和构建状态。工作区原始输出为产品根目录下：

- `target/validation-synchronization-20261127`：候选／基线运行器哈希、产品 conformance、双后端／单槽 gVisor、fixture 原始日志、长压力补跑、性能与 iOS 构建。
- `target/local-ci/io/synchronization-20261127`：原版 Linux 编译产物、native 逐项对照、同 ELF SHA256、固定源码与编译环境记录。

gVisor 原版的标准准备／导出仍使用 `tests/gvisor/prepare.py --expanded`；在现有缓存中本批只构建 `rseq_test` 和 `gvisor_rseq_nolibc_build`，复用未变 futex ELF。原版 runfile 导出路径必须带 `_main`；初次临时导出漏掉此前缀导致 13 项 exec ENOENT，修正布局后只重跑这 13 项并全部通过。native 的已通过 67 项 futex 直接复用。

新夹具可用 ARM64 Linux `gcc -O2 -static -pthread -Wall -Wextra -Werror tests/fixtures/synchronization.c -o synchronization` 构建。正常执行验收九组；`GLIBC_TUNABLES=glibc.pthread.rseq=0 ./synchronization` 验收原版 glibc 回退；`./synchronization perf 10000` 输出上述三项指标。
