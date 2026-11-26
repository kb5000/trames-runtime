# 现代挂载性能收尾（2026-11-26）

本轮处理第二批遗留的读取／管道差距和 metadata 波动。先集中采样与实现，再统一验证；没有新增协调／资源服务线程、轮询总线、依赖或平台专用 API。按所有者要求使用解释器／Mac HVF，不等待物理设备。支持范围仍以[第一批](modern-mounts-20261126.md)和[第二批](modern-mount-overlay-20261126.md)为准，不宣称全部 Linux filesystem 参数均已实现。

状态：上述约定的领域 03 功能、工具验收及遗留性能收尾已完成，按 main 配对交付；下一领域为 04 cgroup。未支持的 filesystem、overlay index=on／metacopy=on 等选项继续明确拒绝。

## 定位与修改

1. 普通挂载遍历的 `has_children` 与 inode `mount_target` 单调标记原本只在 `hostfs` feature 下存在。解释器默认构建没有启用它们，普通路径需要扫描无关挂载，反复进入 `Attachment::key_view` 查询父文件系统。将已有标记、发布及快速判断统一到共享实现；宿主授权目录的特殊查找继续保留原编译隔离。false positive 仍走原扫描，标记不因卸载清零；移动、namespace clone 和新挂载使用原发布入口，没有增加第二份拓扑或缓存失效机制。标记仍用原来的 relaxed 原子访问，不增加普通访存屏障。
2. 管道专项样本的栈顶包含区域掩码 `mask` 630 次、`Guard::read` 232 次；读取和管道夹具包含逐字节内容校验，解释器访问这段共享内存路径。让小型掩码计算始终内联，并给覆盖检查／guard read 提供内联提示，使固定宽度及原范围关系可被编译器消去重复计算。原 bounds／region assert、访问权限、借用和锁全部保留；不修改 guest CPU 指令行为或 native／解释器的内存策略。这是本领域性能收尾所需的共用访问依赖。

只修改 `trames-vfs/src/lib.rs`、`trames-vfs/src/mounts.rs` 与 `trames-memory/src/parallel/page.rs` 的上述路径，不扩大到其他领域的实现。未改动正式计时客户端、内容校验、libfuse daemon 或原始 gVisor 测试。

## 输入与诊断证据

- 目录：`target/validation-modern-mount-closeout-20261126`；Linux 输出：`target/local-ci/io/modern-mount-closeout-20261126`。
- 冻结以 Runtime `7f80b14c0a134f1878e058c98ab43aa7749ac5df` 的已发布树为底，只覆盖本轮三个文件，未纳入其他会话正在修改的 Session／调试／内存探针／allocator／存储工作。`runtime-source-v1.json` 逐文件记录 SHA-256，构建前后核对冻结源码未变。
- 原生 ARM64 临时诊断 ELF 独立运行 metadata 与 pipe 循环，在 `PROFILE_BEGIN` 后每侧采样六秒，采样结束明确终止该负载，不把诊断计时混入验收。四份输入、栈顶与阶段状态保存在 `sampling-audit.json`。最初通用采样虽然取得调用栈，但完整负载随后被夹具看门狗终止，137 退出保留，不计作通过结果。
- 最终性能直接使用现代挂载之前的已交付 FUSE `7d4a9711` release CLI，SHA-256 `42b5986aaf18f750f0dd4cee3f3da288365f3a2b38e3b2c66bd9665b7a46a20d`，避免仅与上一候选持平就宣称消除原始差距。

## 集中验证

- Apple **1942 passed / 5 ignored**，Linux **1952 passed / 5 ignored**，含 VFS、syscall、memory；默认 VFS 两宿主各 1111 通过／1 忽略，按实际测试列表确认属于 hostfs 结果的子集后去重。memory 子进程的单项输出也不重复相加，来源为两宿主 `unit-audit.json`。两种配置的原挂载、rename、bind、namespace clone、FUSE 和访问边界回归均通过。
- 两宿主 memory／VFS／syscall 所有 target／feature 的严格 Clippy 通过，Linux 全工作区／全部 target／feature 编译通过；项目格式、diff 空白和原生产执行边界检查通过。
- 最终解释器与签名 Mac HVF 均通过同一 **342 项新 ELF＋234 项原 ELF**、四种实际 runc OCI，以及低层／写回／高层 FUSE 工具每侧 **39 项**。`functional-audit.json` 核对输入逐字节相同。原生未变 ELF 和固定工具输入的通过证据复用，不重新运行不相关的全量 CPU／网络／图形矩阵。
- 最终原版 gVisor **941 身份，931 passed / 10 skipped**，覆盖全部 **926 个原生通过项**；模式与上一批逐身份一致，预先分为 811 个 userspace/gVisor 模式和 130 个 Linux 模式运行。原始跳过不计作通过，也不叠加到历史全量台账，详见 `gvisor-audit.json`。
- CLI、签名 Mac HVF、iOS FFI release 构建分别耗时 360.488／385.429／351.859 秒，全部通过。iOS 定点清理 memory／VFS 后重建，所有构建前后检查同一冻结源码未变。最终 CLI 的符号检查确认 `page::mask` 不再作为独立函数存在，见 `inline-symbol-audit.json`。产品实际 Rust 源码与 manifest 核对通过。

冻结清单 `runtime-source-v1.json` SHA-256：`d321a1881b27eb235d1412cbed238db402382fad63a56151a8dbafa7b81cdbdc`。生产源码与该清单逐字节一致，报告后续记录独立于编译输入。

| 产物 | SHA-256 |
|---|---|
| CLI | `ce9397f7b49f9228ba9d8aab63824525d7d7cac4a5c9ba10ddb548519e431dec` |
| 签名 Mac HVF | `cf201ad7067206c76ffa7b87dbb394172fc7a882a26285b68cfee08a8115ba7c` |
| iOS FFI | `bed0462054abe3618849d5403f602f09abb74b3890b4d1a6546302d632cb757f` |

## 最终性能

同一原版 daemon、control client、内容校验及 workload，2 CPU、writeback、ordinary scale=20，AB／BA 交替四配对块，每块三次有效样本。含两次独立协商诊断共 **10 次进程／100 行记录**，每侧每项 12 个有效样本，阶段耗时 **219.867 秒**。测量前后没有编译或测试进程。原始结果在 `performance/`，配对块在 `performance-block-audit.json`，不覆盖上一批结果。

| 项目 | FUSE 基线中位 ms | 当前中位 ms | 变化 |
|---|---:|---:|---:|
| 写入＋同步 | 16.0242 | 15.8185 | −1.28% |
| 写入 | 15.3116 | 15.1861 | −0.82% |
| 同步 | 0.6166 | 0.6136 | −0.48% |
| 保持打开读取 | 277.8545 | 237.8235 | −14.41% |
| 重新打开读取 | 295.4701 | 251.2941 | −14.95% |
| 普通计算 | 50.5207 | 44.9067 | −11.11% |
| stat／只读 open／close | 208.0337 | 143.4720 | −31.03% |
| 普通文件 | 1511.9688 | 1311.0126 | −13.29% |
| 管道 | 1541.9309 | 1325.9597 | −14.01% |

遗留项目在四个配对块中均改善：metadata **−36.04%／−26.27%／−24.56%／−37.93%**，保持打开读取 **−9.47%／−24.09%／−18.67%／−6.73%**，重新打开读取 **−4.51%／−22.26%／−3.60%／−4.99%**，管道 **−4.82%／−23.08%／−6.13%／−3.12%**。因此不再把上一批相对该基线的 +3.25%／+3.70%／+2.74% 及 metadata +2.87% 留作未关闭问题；这里的结论来自本轮直接对照，没有拼接不同轮次的中位数。

配对波动仍公开保留。计算四块为 −0.59%／−16.33%／−4.35%／+0.30%，不能把全部 −11.11% 归因于这两个改动。以每块普通计算作为诊断性尺度校正后，metadata 为 −38.12% 至 −11.89%、保持打开读取为 −14.97% 至 −7.02%、管道为 −8.07% 至 −1.86%；重新打开读取为 −7.10% 至 +0.78%。这种校正只辅助辨别环境变化，不替代原始计时或建立因果保证。

写入＋同步四块为 −2.72%／−5.96%／−7.97%／+9.52%，同步为 +1.09%／−13.14%／−10.18%／+1.64%。总体中位未退化，但不声明每个块或每次运行都更快。原始样本全部保留，功能范围和已测性能据此收尾，不将结论扩展到未测设备／负载。

交付保留上述受测源码身份，通过 iPad／Mac `runtime-version.json` 配对固定；其他会话的 WIP 不纳入。文档状态更新不触发未变代码的重复矩阵。
