# 现代挂载：挂载映射、重配置与 OCI（2026-11-26）

状态：领域 03 本批支持范围的实现、最终 v15 功能与性能验收已完成，按 main 配对交付。调试按所有者要求使用解释器／Mac HVF，不等待物理 iPad，也不把未运行的物理设备测试计作通过。没有新增协调／资源服务线程或轮询消息总线。

## 实现边界

- `mount_setattr(MOUNT_ATTR_IDMAP)` 在导入时取得原 user namespace 文件资源和映射快照；路径输入缺页时保存已接受快照。只接受非初始 user namespace、支持映射的文件系统和 detached mount，检查 filesystem owner 的能力、已有映射及活动 writer；递归全部预验证后发布。挂载仅保留不可变映射数据，不因映射延长原 user namespace 的配额／生命周期。bind、open_tree、namespace clone、查询投影及卸载后的 OFD 保留原映射。
- inode、命名 ACL 和文件 capability 的缓存仍保存文件系统身份；按原路径／OFD 转换 stat/statx、快速 fstat、DAC/ACL、sticky、chmod/chown、utimens、普通创建／SGID 继承及未映射 inode 的写回拒绝、硬链接、执行凭据／SUID／file capability 与 xattr。显示溢出 ID、拒绝权限和创建／修改的 EOVERFLOW 分开处理。
- `fspick`／`FSCONFIG_CMD_RECONFIGURE` 选择原 filesystem，支持已实现文件系统的通用只读更新；tmpfs 限额、debugfs 参数、devpts 参数和 cgroup 已支持选项使用对应解析。旧 remount 复用同一更新函数。bind 别名与旧 FD 观察 superblock 更新，挂载局部属性独立；失败不发布只读切换。tmpfs 创建用 mode/uid/gid 在重配置时解析但不修改已有根 inode。
- proc、sysfs 以原 PID／network namespace 的独立 superblock 资源保存只读／writer 状态，复用私有 inode 存储时不改变普通根存储。上下文跨 namespace 传递仍使用原资源。旧 sysfs 挂载继续保留其原 network namespace；复用已有 sysfs 的 get_tree 不因创建阶段 `ro` 参数重配置原 superblock。
- 普通可写文件的原 OFD 使用既有 writer 准入与计数；关闭数字 FD 后，映射／已接受调用仍持有 OFD 时继续阻止只读或 ID-map 切换。读写路径同时修正只读 FD 的 EBADF 顺序。原 proc FD 同线程组例外同时用于读取和目录搜索，支持降权后的 runc 执行收尾。
- Apple 专用接口沿用现有 cfg。本批新增挂载语义均在共享 Runtime；Host grant 的只读边界不能通过重配置提升。

当前明确限制：FUSE、ramfs、proc、sysfs、Host grant 等未声明支持的文件系统拒绝 ID-map。支持 Root、tmpfs 及 overlay 自身的映射；当前 overlay 直接共享 upper inode 的实现仍拒绝已映射的 backing layer（EOPNOTSUPP），没有把两套身份写入同一共享 inode。独立 O_TMPFILE 创建支持和尚未实现的 filesystem 参数／fsopen 类型不计作本批已交付。领域 03 的延伸范围保留在实施清单。

## 源码与输入

- 目录：`target/validation-modern-mount-20261126`；Linux 镜像内日志通过 `target/local-ci/io/modern-mount-20261126` 保存。
- 冻结源码：`runtime-source-v1`、`v2`、`v3`、`v4`、`v5`、`v6`、`v7`、`v8`、`v9` 至 `v15`；每份 JSON 逐文件 SHA-256。最终产物使用 v15；构建前后验证原冻结目录内容。
- v15 以 Runtime `243183d` 为基础，保留并发交付的依赖许可文档提交；未合并其他会话的调试／存储夹具、产品内存探针或 allocator 工作。
- 同一 ARM64 静态 ELF：`runtime/tests/fixtures/modern-mounts.c`，原生编译 `musl-gcc -static -O2 -Wall -Wextra`，内核 `7.0.0-43-generic`。最终原生计数 234，覆盖 namespace FD 类型／范围、活动 OFD／私有 VMA、所有权、DAC、ACL、capability root、SGID、创建、chown、卸载后 fstat、递归回滚、non-tmpfs 重配置／旧 FD／bind 别名／局部只读。
- OCI 输入与脚本：`runtime/tests/fixtures/modern-mount-oci.sh`，`modern-mount-oci.py` 生成验证目录 `oci-inputs/*.json`；生成结果逐字节匹配已运行输入。固定官方 runc **1.3.0**，commit `v1.3.0-0-g4ca628d1`、OCI spec 1.2.1、Go 1.23.8、libseccomp 2.5.6；ARM64 ELF SHA-256 `85c5e4e4f72e442c8c17bac07527cd4f961ee48e4f2b71797f7533c94f4a52b9`，对照官方 `runc.sha256sum`。
- 三种实际启动：`rbind+rro+rnoexec+rnosuid`、带 UID/GID 映射的 `bind+idmap`、`rbind+ridmap+rro+rnoexec+rnosuid`。容器内验证内容、投影 UID/GID、创建身份及两层拒绝写入；外部验证创建 inode 的原始 UID/GID。

## 统一验证

最终功能验证已完成；性能测量单独列出，不将中间候选替代最终产物。

- Apple v15 VFS：1170 passed / 1 ignored；Linux v15 VFS：1178 passed / 1 ignored。10 个新增语义回归全部通过，六个原 writer 断言按原生 OFD 规则调整，未删除或跳过。v13 合并 sticky 条件以通过严格 Clippy；v15 查询路径优化后两宿主重新整库通过。与未变系统调用层 523 passed / 1 ignored 按身份合并为 Apple 1693 passed / 2 ignored、Linux 1701 passed / 2 ignored。逐项来源保存在 `unit-audit.json`。
- v9 Linux Runtime 全工作区／全部 target／feature 编译通过，未变调用方复用此结果。v15 Apple／Linux 受影响两库全部 target／feature 的严格 Clippy 通过。最终 CLI／签名 Mac HVF release 与 iOS FFI 构建通过；iOS 以清理两个受影响包后的重建为准。格式、shell／Python 语法及 Runtime 执行边界检查通过。
- v15 解释器及签名 Mac HVF：同一份 234 项 ELF 全部通过，三份原始 runc OCI 配置均通过；原生 Linux 同 ELF 234 项及三种 OCI 输入通过结果复用，输入未改变。两执行器各复验低层、写回及高层 libfuse 三组工具，每组 13 项，共各 39 项通过。
- v4 原版 gVisor：450 身份首轮 447 passed / 1 failed / 2 skipped。唯一失败 `ExecTest.InterpreterScript` 使用 `/bin/bash`，Alpine 夹具无该解释器；补入原始 Bash、loader、libc、libtinfo 后原用例通过，不修改原脚本。另 3 个 FsConfig 身份沿用既有已核实 Linux ABI 模式单独运行，保留两种模式的来源。最终解释器统一重跑全部受影响用例时预先提供实际 Bash 及 loader；最终按身份汇总，不把重跑或旧全量台账相加。

- v15 原版 gVisor：453 个身份、449 passed / 4 skipped，覆盖全部 445 个原生通过项；其中 450 个身份按 userspace／gVisor 模式运行，三个 FsConfig 身份按既有 Linux ABI 模式运行。四个跳过为原始 BlocksFree、非 admin trusted xattr、FsConfigBadFilesystem、FsConfigUnsupportedCmds。`gvisor-audit-v15.json` 保留每个身份、模式、来源与原生状态。历史全量台账仍为 14,014 passed、13,965／13,965 原生通过项，不叠加这批重叠用例。

## 最终产物

最终构建的冻结输入为 `runtime-source-v15.json`，SHA-256 `2e860b2f5adf33f6ddf3d4d7b7873cf517e129e267708e8136927c4761ada688`；CLI、Mac 与清理缓存后的 iOS 构建前后均验证冻结文件未变。生产源码与冻结输入一致；本报告及 OCI 输入生成器不属于该生产源码清单，另行验证。产品及 CLI 的实际编译源码也与当前主线逐文件核对，无差异；并发主线变化仅为依赖许可／打包记录。

| 产物 | SHA-256 |
|---|---|
| 解释器 CLI | `bf0708ae53d60af752e4076f2433dbaffb74f7c7e38b667c24da2fae5d97c488` |
| 已签名 Mac HVF | `3e27c5222874cdff1b9e41a9d40ea5982f01ee9680045a7a36506b717e55a3ca` |
| iOS FFI 静态库（清理后） | `affbb1a8f443bbe10db5a6f31d49b57f48d068d040b1fe547877f8ee6aaf505d` |
| 同一 ARM64 检查 ELF | `1039e526d97c62040b5b0fac9cc6bacc30e688c2169322757339a90fdaa5d814` |

性能对照以已交付 FUSE Runtime `7d4a9711` 的解释器（SHA `42b5986aaf18f750f0dd4cee3f3da288365f3a2b38e3b2c66bd9665b7a46a20d`）为基线，使用同一 release 构建方式、原始 daemon、2 CPU、AB／BA 交替四块、每块三次有效样本及 ordinary scale=20。诊断预热与 WRITEBACK_CACHE 协商不计入样本；测量前没有本任务编译／测试进程。

## 最终性能结果

四个配对块共 10 次进程（含两次独立诊断）、100 条有效记录，阶段耗时 216.944 秒；每侧 12 个有效样本。普通负载每个样本使用两个 worker，比较其中较长耗时。测量前后没有本任务编译／测试进程。

| 项目 | 基线中位 ms | 最终中位 ms | 变化 |
|---|---:|---:|---:|
| 8 MiB 写入＋同步 | 15.5541 | 15.6494 | +0.61% |
| 8 MiB 写入 | 14.9664 | 15.0637 | +0.65% |
| 同步 | 0.5962 | 0.6007 | +0.74% |
| 保持打开读取 | 256.8136 | 265.1605 | +3.25% |
| 重新打开读取 | 263.5306 | 273.2717 | +3.70% |
| 普通计算 | 43.3837 | 43.3606 | -0.05% |
| stat／只读 open／close | 229.4249 | 228.3969 | -0.45% |
| 普通文件 | 1373.8086 | 1382.1955 | +0.61% |
| 管道 | 1381.0110 | 1418.9169 | +2.74% |

最终 metadata 总体中位为 −0.45%，四个配对块分别为 −10.84%、+10.21%、+11.26%、−1.45%；原始配对波动保留，不声称每块都改善。写入＋同步及同步分别为 +0.61%、+0.74%。读取仍有 +3.25%／+3.70%、管道 +2.74%，作为已量化的性能后续保留；计算及普通文件分别为 −0.05%、+0.61%。本次支持范围按此结果交付，不把数据有效标记自动等同于所有负载零回退。

原始 `performance/`（v9）、`performance-atomic/`（v13）与最终 `performance-fastpath/` 分别保存，不覆盖失败或中间结果。最终变更按 `main` 配对提交／推送，产品的 `runtime-version.json` 记录同一 Runtime 提交；其他会话的 WIP 不纳入。

## 原始失败与修正

- v1 首次 Apple 编译为查询临时借用生命周期错误；修正局部借用后通过。首次 CLI 冻结缺少独立 CLI 子模块，补入已验证、未变的子模块后构建。原始日志保留。
- Apple v1 系统调用层 29 项因执行环境不允许本机 socket 返回 EPERM；只在允许回环网络的执行环境重跑该组，29 项全部通过。其余通过结果保留。
- 两宿主 v1：并发 socket 生命周期断言及 sysfs 创建只读断言失败。原生确认既有 sysfs superblock 的创建 `ro` 不等同于重配置；sysfs 挂载也确实保留原 network namespace。回归调整为显式启用 pseudo 路径，卸载旧 sysfs 后检查 namespace 释放。
- v2 同 ELF 在两执行器暴露快速 fstat 没有使用原挂载映射；补齐快速路径。v2 runc 递归启动通过，降权 ID-map 启动在读取自身 proc FD 目录失败；统一同线程组读取／搜索例外后 v4 三种启动全部通过。
- 扩展同 ELF 在原生 Linux 通过，而 v4 两执行器在活动写 FD 的 ID-map 检查错误成功；补齐普通可写 OFD 的 mount/superblock writer 生命周期，并覆盖 FD 关闭后私有 VMA 仍持有 OFD。v6 两库既有六项断言仍假定可在活动可写 OFD 存在时改只读，按原生结果调整为等待真正最后引用释放；同时统一只读 FD 写入的 EBADF 优先级。v9 VFS 统一通过。
- 原生 OCI 夹具早期失败（非 mount root 的传播更新、缺 cgroup、外层 chroot 被 setns 越过、已有 cgroup 的重复 ro 挂载）均保留日志。改为原生私有 mount/PID namespace、同一路径和只读 cgroup bind 视图后，原版 runc 三组通过。没有据此修改 Runtime 来适配错误夹具。
- v4/v5 Clippy 仅报告 matches 写法及 bool 断言形式；v11 为 sticky 嵌套条件形式，统一修正后两宿主严格检查通过。
- v9 首次有效性能对照的 metadata 中位耗时增加 8.176%（219.845 → 237.819 ms），此结果没有按验收通过处理。同时核对新 writer 生命周期时发现普通写打开复用两把对象 mutex，v10 起改为每对象原子计数及转换位：正常写打开不取 mutex，实际转换由已有对象 mutex 串行并阻塞等待；没有自旋或新线程，计数不发布数据，acquire/release 仅对接真实属性转换。最终性能另列。v13 对照仍有 metadata +6.499%、sync +8.448%（绝对 +0.0495 ms），原始 6 次／52 行数据有效并保留在 `performance-atomic/`，没有当成性能通过。
- 原生未映射 inode 探针确认写打开 EACCES、chmod／删除／链接 EOVERFLOW、写 xattr EPERM、保留可写 FD 仍可写而 truncate EOVERFLOW；chown 可逐字段修复，未修改字段仍须可映射，ACL 无法反向映射返回 EINVAL。将这些入口一起补齐，扩展同 ELF 到 234 项。v11 两宿主仅剩空映射创建的错误优先级失败；按原生 may_create 顺序先校验创建身份，再检查父目录 DAC，v12 两宿主全部通过。
- iOS 中间构建虽然成功，VFS／Linux 的增量缓存没有重新编译后续源改动，静态库 SHA 重复，因此不将它们当成最终实现证据。最终只清理这两个包的 iOS release 缓存后重建，并核对编译日志、冻结输入和产物 SHA；不触发物理设备测试。

- 对照 metadata 夹具后确认计时只包含 stat／只读 open／close，写打开在计时外，故不能将该差距归因于 writer 锁。符号检查也发现无映射 ID 的 owner／visible 包装仍为独立调用。v15 统一改为借用原路径的 filesystem 做同步 provider 判断及 host lease 查询，避免跨 worker 反复增减整组 Arc；只在 O_NOATIME 生效时取其 owner，普通 stat 不重复改写未映射的 UID/GID，内联小型身份访问而保留实际映射转换函数。原资源、权限和缓存语义不变。最终对照扩为四配对块，以覆盖前一两块差距 1.66%／10.11% 的变化；不反复选择短样本。

- v15 首次解释器启动在 guest 导入之前被 SIGKILL，系统报告为 CODESIGNING／Taskgated Invalid Signature；磁盘签名检查有效，而同 SHA 的新文件可正常执行。将输出以新 inode 原子替换后恢复，保留 `*.launch-failure` 日志及诊断 JSON。未改生产代码或重新构建，随后只重跑尚未实际执行的解释器验证；已通过的 HVF 结果复用。构建夹具同步改为原子替换输出，避免覆盖已执行二进制的文件实例。

所有阶段有明确时限和磁盘下限，超时只终止该阶段拥有的进程组；不重复触发完整 CPU／网络／图形或物理设备验收。

依据：[Linux 挂载映射模型](https://docs.kernel.org/filesystems/idmappings.html)、[Linux v6.12 mount_setattr](https://github.com/torvalds/linux/blob/v6.12/fs/namespace.c)、[idmap 快照](https://github.com/torvalds/linux/blob/v6.12/fs/mnt_idmapping.c)、[tmpfs 重配置](https://github.com/torvalds/linux/blob/v6.12/mm/shmem.c)、[runc 1.3.0 原始挂载调用](https://github.com/opencontainers/runc/blob/v1.3.0/libcontainer/mount_linux.go)、[OCI 1.2.1](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config.md)。
