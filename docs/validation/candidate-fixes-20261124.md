# 2026-11-24 候选修复检查点

本批先合并实现当前已知问题和依赖，再集中验证，没有新增协调／服务线程、轮询总线或普通访存屏障。原完整功能清单仍未完成，本记录不代表完整 FUSE mmap、写回、Android 内存接口、perf 全作用域或真机交付。

## 实现

- 原 TaskLimit 进入 worker PathQueries，启动配置、proc 写入和实际任务准入共享同一资源。
- stat 输入解析移除输出页预检，由已接受结果的 FileCopyout 跨页等待；共享 PageSource 的 worker 首次驻留能正确 joined commit。
- 原 OFD 位置等待先订阅再检查；普通 read 的位置准入竞争进入等待，不向 guest 泄漏 EAGAIN。
- FUSE 本地零长度／缓存同步结果直接完成；取消后仍接收 GETATTR／SETATTR 的共享属性副作用。
- FileTarget.page_source 提供保留原 OFD 的异步页准备能力，复用原请求、独立错误、短读清零及当前 fault actor；没有据此开放 mmap／共享写回。
- 修正测试中错误的 ARM64 标志、fork 后 FD 成员关系、mount／superblock 范围、硬件 Registry 准备和 FUSE 协议／缓存／权限次序；严格保留错误断言。
- 清理弃用 API、未使用 import 和参数形式等 lint，保持原内存次序，没有新增 warning 屏蔽。

## 验证

原始证据在产品工作区 `target/validation-fixes-20261124-161212`；每阶段有命令、退出码、时限及日志。产品 `docs/validation/candidate-batch-20261124.md` 保存首轮失败及本轮修正详情。

- memory／VFS／Linux／kernel 四库：合并未受后续窄改影响的通过结果及失败项复查，1760 通过、0 失败、5 忽略；原 22 个失败全部关闭。
- 解释器 conformance／FFI：533 通过、0 失败、7 忽略。
- 原共享偏移间歇失败：20 次并发回归全部通过。
- 实际 guest：任务上限 1024 初始化、128／1024 动态读写通过；写入 1 后 fork 被拒绝，保留旧 runner 的错误放行作为前后反例。
- 原版 gVisor futex／rlimits／stat／statfs／fuse：166 个身份为 163 通过、3 参考一致跳过；全部 162 个 Linux 参考通过项通过，无超时。原 ELF 与 runner SHA256、XML 和正式 compare 输出保留。
- Runtime 及产品严格 all-targets／all-features Clippy、格式和执行边界通过；既有 vendor 警告保留。
- Mac/HVF 产品以相同 Runtime 候选完成 all-targets／all-features check；未将编译检查当作 HVF 实际行为验收。
- 固定 BusyBox 文件读写／元数据负载，6 次轮换对照全部正确；dev 中位数 2.614821s → 2.646939s（+1.23%），样本有重叠，不作发布性能结论。初次两版均触默认指令额度的样本无效，保留并统一提高额度后重测。

首次计数误把 4 个内存测试子进程小结重复相加，已按 Cargo target 最终小结修正；失败清单和对照结论不受影响。未因文档或计数修正重复执行已通过行为测试。

完整 254 组 gVisor、原版新增 futex2／rseq guest runfile、实际 HVF、原版调试工具、release／真实包安装与容器吞吐、物理 iPad 等验收仍按完整清单保留。


## 后续 CI 修正

推送后 Linux CI 暴露了网络命名空间初始化的栈溢出；本地 Linux ARM64 复现并取得回溯，指向含 smoltcp 大缓冲区的 Node 按值进入 B-tree 插入帧。将普通节点及 gateway 节点独立分配，B-tree 只保留 Box；原资源归属、同步与调用线程保持不变。新增 16 个命名空间跨树分裂、删除并继续隔离 UDP 收发的回归。

产品 Linux CI 的 sysinfo／结构性调用 3 项失败及本地复查的同类内存观察失败来自测试完成条件：累计指令上限没有随重试增加，或要求在 10ms bounded 夹具窗口内完成。观察测试等待真实结果并逐轮增加累计额度；结构性序列使用真实 guest 退出的 source completion，保留单 epoch、返回值、seccomp 计数及零宿主接管断言。没有放宽错误结果或添加跳过。

证据在产品 `target/local-ci/io/candidate-stack-20261124`。网络／VFS：Linux 1239 通过、0 失败、1 忽略，Mac 1242 通过、0 失败、1 忽略。网络／VFS 严格 Clippy、格式及执行边界通过。首次将测试栈变量误传给 rustc 的编译器栈溢出、沙箱拒绝本机套接字的 EPERM 均保留为无效尝试，未用于通过结论。未提高测试线程栈上限。

按测试身份合并未受修改影响的通过结果及 seccomp 58 项复查后，Linux／Mac 的进程 conformance 各为 509 通过、0 失败、3 忽略；没有把复查的同一身份重复计数。Linux 原溢出用例及新增树分裂回归另外直接用已编译可执行文件在显式 2 MiB 测试线程栈下运行通过。

最终受影响产品 core 的 all-targets／all-features 严格 Clippy、Runtime 执行边界和格式检查通过。隔离 Linux CI VM 已恢复停止状态，现有 Stable／Dev 应用及 guest 环境保持原状。
