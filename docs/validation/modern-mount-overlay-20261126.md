# 现代挂载第二批：映射 overlay、构建上下文与匿名文件

本报告保留第二批的原始结果与当时遗留项；性能后续已由[现代挂载收尾](modern-mount-closeout-20261126.md)直接对照原 FUSE 基线完成，旧样本不覆盖或改写。

本批属于领域 03，按所有者要求整批实现后集中验证。使用解释器与 Mac HVF 调试；未运行的物理设备测试不计作通过。没有增加生产协调／资源服务线程或轮询消息总线。共享实现位于 Runtime，Apple 专用入口继续沿用现有 target cfg。

## 实现范围

- overlay backing layer 保留原目录 inode、挂载身份与文件系统资源。支持映射 lower、映射 upper 及两者组合；合并视图与底层 inode 的 UID/GID、命名 ACL、capability root 双向转换，底层缓存始终保存原文件系统身份。上层字节与 VM 页仍使用实际 provider。copy-up 验证上下层身份和原创建者权限；命名空间提交失败回滚投影元数据与 provider。
- 原只读 OFD 继续读取 copy-up 前的 lower，新的 OFD 使用 upper；写入 OFD、VMA 和执行映像保留实际层的 writer／执行引用。detach、unlink 与重新挂载不改变原引用的身份。投影索引使用弱引用，不额外固定已删除 inode。
- 对照 Linux 默认 index=off：lower 硬链接起初报告相同 inode，但一个 dentry copy-up 后不会自动复制其余 lower 别名；显式 upper 硬链接共享实际 inode。保留该行为的原生和单元回归。
- fsopen/fsconfig 增加 overlay、devpts、mqueue、cgroup2。overlay 在接受 lowerdir/lowerdir+/upperdir/workdir 时取得目录资源，后续改名不重新解析字符串；lowerdir+ 支持字面冒号与逗号。devpts 使用原实例，mqueue 与 cgroup2 保存创建上下文的原 namespace。支持相应已实现的 STRING／FLAG 参数，额外参数明确拒绝。
- 真正 O_TMPFILE 使用未发布到目录的 inode，覆盖 Root、tmpfs、ramfs、overlay upper；权限、SGID、默认 ACL、配额、OFD/VMA、idmap 与底层 writer 使用现有资源模型。一次性可链接状态由 inode 原子位记录；O_EXCL 不可链接，发布后删除不可再次复活。openat2 接受 O_TMPFILE 的 mode。
- 普通文件系统 handle 将原来多组不变资源引用合为一个 Arc；派生资源绑定采用 copy-on-write，实际 inode、配额、锁和 provider 仍共享。此项针对上一批读取及管道的额外引用计数成本。

边界：没有声明全部 Linux filesystem 参数已实现；不支持的 Host grant／FUSE 匿名文件入口及未声明支持 ID-map 的文件系统仍拒绝。overlay 的 index=on、metacopy=on 等功能不在本批范围。

## 输入与证据

- 工作目录 `target/validation-modern-mount-overlay-20261126`，Linux 日志与原生 ELF 在 `target/local-ci/io/modern-mount-overlay-20261126`。源码冻结逐文件记录 SHA-256；最终构建前后核对同一清单，原始失败不覆盖。
- 基于 Runtime `c8ac3f9`，保留同时交付的 Android init 测试修正；其他会话的产品内存探针、allocator、调试和存储夹具不纳入本批。
- 新 ARM64 静态 ELF `tests/fixtures/modern-mount-overlay.c` 复用原现代挂载公共夹具。Linux ARM64 `7.0.0-43-generic` 同 ELF **342 项全部通过**，覆盖三种映射层组合、chmod copy-up、ACL／capability、硬链接、原 FD、O_TMPFILE/openat2 和四种现代 context。
- 新实际容器夹具 `modern-mount-overlay-oci.sh` 与配置生成器 `modern-mount-overlay-oci.py` 使用上一批固定的原版 runc 1.3.0、同一 Alpine 输入；映射 lower 与 upper 组合，容器内读写身份与底层原始 inode 身份分别核对。原生 Linux 容器启动通过（`OCI_MAPPED_OVERLAY_RESULT:0`）。

## 集中验证

Apple **1700 passed / 2 ignored**，Linux **1708 passed / 2 ignored**。按身份合并 v3 VFS 整库、v4 context 失败项与 v5 socket 权限顺序复验及未变的 v2 syscall 结果，来源见 `unit-audit-v5.json`；未把重复执行相加。v5 两宿主受影响库所有 target／feature 严格 Clippy 通过；Linux v4 全工作区、所有 target／feature 编译通过，后续仅拒绝 socket 打开的局部条件变化，没有接口变化。

- v4 解释器与 Mac HVF：同一 342 项新 ELF、234 项原挂载 ELF 全部通过；原三种 runc OCI 加上映射 backing-layer OCI 共四种实际启动全部通过。原生 Linux 使用相同输入，原 234 项／三种 OCI 复用未变证据，新增 342 项／组合 OCI 本批运行通过。
- v5 原版 gVisor 按身份及明确模式合并为 **941 身份，931 passed / 10 skipped**，覆盖全部 **926 个原生通过项**。挂载、权限、ACL／xattr、overlay、O_TMPFILE／openat2、链接、锁、fallocate、mmap 等选集按 `gvisor-audit.json` 逐项记录。没有叠加到历史 14,014 通过／13,965 个原生通过项的全量台账。
- v5 socket 修正仅让无可打开数据对象的 Unix socket 直接完成原权限检查并返回 ENXIO，避免转交并不存在的文件工作。未改变普通文件／目录打开算法，因此复用 v4 的未变同 ELF／OCI 证据；重新运行完整原版 overlay/open 两组 **116 身份，110 通过／6 原始跳过**，两执行器重新运行低层、写回及高层 FUSE 三组工具，每侧 **39 项全部通过**。
- CLI、签名 Mac HVF 与 iOS FFI release 构建通过，构建前后核对冻结源码不变。iOS 定点清理实际变化的包后重建，编译日志包含 VFS／Linux。执行边界检查、受影响文件按项目 edition 2021 的格式检查、shell／Python 语法与 diff 空白检查通过。

产物由 `runtime-source-v5.json` 构建。交付冻结为 `runtime-source-v6.json`：清除了格式工具递归扩散到未改动文件的排版变化，保留原工程格式；所有不同的 Rust 文件经同一格式规范化后逐字节一致，其余文件逐字节一致，证据为 `format-equivalence-final.json`。按仓库规则复用通过结果，没有因纯格式清理再次触发产品构建或测试。

| 产物 | SHA-256 |
|---|---|
| 最终解释器 CLI | `e8cfd3f6c32f40ab86f1d435596cf072df91070cc9297007cde69002598a457c` |
| 最终签名 Mac HVF | `262369e89ada3d92b2c6bf1749ab9b385dc4c2b1ea82cf8d4ef0413e017e246e` |
| 最终 iOS FFI | `8ef3818986bf976ce4dc141936ccca5a0d0e4350f24256ed8f9744aa0199d0f4` |

构建输入清单 SHA-256：v5 `837b16b9ef85af5fa6b7db415830b31487822ffffc6fadad7f13639ca64f5bc2`；交付清单 v6 `3e88856699306e7324cb5b1ed3da62bdb05a0982cfad2a5afdb31ff12d8574d5`。交付通过产品 `runtime-version.json` 配对固定 Runtime 身份，保留已发布主线身份，不纳入其他会话 WIP。

## 性能与未收敛项

基线为上一批 Runtime `7617d2a` 的最终解释器，SHA-256 `bf0708ae53d60af752e4076f2433dbaffb74f7c7e38b667c24da2fae5d97c488`。两侧使用同一原 libfuse daemon、control client、Alpine、2 CPU、writeback、ordinary scale=20；AB／BA 交替四配对块，每块三次有效样本。包括两次独立协商诊断共 **10 次进程／100 行记录**，218.36 秒；每侧每项 12 个有效样本。测量前后没有编译／测试进程。原始数据位于 `performance/`。

| 项目 | 基线中位 ms | 当前中位 ms | 变化 |
|---|---:|---:|---:|
| 写入＋同步 | 15.8826 | 15.7738 | −0.68% |
| 写入 | 15.2899 | 15.1762 | −0.74% |
| 同步 | 0.6009 | 0.5954 | −0.91% |
| 保持打开读取 | 265.0832 | 265.6082 | +0.20% |
| 重新打开读取 | 273.3689 | 272.1503 | −0.45% |
| 普通计算 | 43.5528 | 43.6241 | +0.16% |
| stat／只读 open／close | 227.8680 | 234.4108 | +2.87% |
| 普通文件 | 1381.2271 | 1385.7434 | +0.33% |
| 管道 | 1409.3944 | 1412.2344 | +0.20% |

metadata 四个配对块分别为 −3.25%、+1.20%、−1.66%、+4.37%，总体中位仍增加 2.87%，不按零回退处理。读取／管道相对上一版基本持平，**没有证据证明本次引用计数整理消除了上一批相对 `7d4a9711` 的 +3.25%／+3.70%／+2.74% 差距**。数据有效不等于性能目标全部完成。功能实现和工具验收按本批范围交付；读取／管道差距及 metadata 波动继续作为明确性能后续，需以实际调用采样定位，不能将不同轮次的中位数拼接为直接对照。

## 原始失败与修正

- v1 编译暴露新 context 的临时 cgroup 借用与 anonymous 发布冲突，改为提前取得原资源。
- 新原生夹具最初假定所有 lower 硬链接一起 copy-up；原生默认 index=off 推翻此假定，实现及回归统一按实际 dentry 行为调整，未跳过原检查。
- v2 两宿主同四项失败：两个新夹具分别没有通过正确目录创建入口及启用 pseudo 路径；另两个暴露 lower 元数据视图误用实际层实时元数据，覆盖待提交 chmod，统一修正为只对 upper 转发。
- v3 剩余一项为内部 mq_open 测试误传带 slash 名称；系统调用层原本去除 slash，修正夹具后通过。Clippy 要求投影弱引用 map 提取类型别名，v4 两宿主通过。
- 原版 gVisor 首轮 938 项有 5 失败／1 无结果：fallocate KEEP_SIZE 要求 gVisor 不支持；overlay 的预 copy-up 只读映射切换、截断 SIGBUS、lower FIFO 不可写和 lower 目录递归 rename 四项明确只适用于 gVisor，其源注释说明与 Linux 的差异。保留原失败，按 Linux 模式运行对应整组，不将其改成 gVisor 行为；fallocate 的时间戳身份也在 Linux 模式补齐。真正的 socket ENXIO 错误已修正。所用原版源为固定 gVisor `89cacadae21eca4270a8f7c79281d0426d33ac5f`，`overlay.cc` 1223／1251／1278／1442 行及 `fallocate.cc` 106／130 行保留模式依据。
- iOS 首次定点清理 VFS／Linux 后，主线新合入的 worker assignment 接口仍命中旧 engine 缓存；清理原 engine 包后构建通过，最终 v5 再清理 VFS 并重建。未修改生产接口来适配旧缓存，也未触发设备部署。

依据：[Linux idmapping](https://docs.kernel.org/filesystems/idmappings.html)、[Linux v6.12 overlay copy-up](https://github.com/torvalds/linux/blob/v6.12/fs/overlayfs/copy_up.c)、[overlay inode](https://github.com/torvalds/linux/blob/v6.12/fs/overlayfs/inode.c)、[overlay 参数](https://github.com/torvalds/linux/blob/v6.12/fs/overlayfs/params.c)、[匿名文件](https://github.com/torvalds/linux/blob/v6.12/fs/namei.c)。
