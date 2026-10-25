# IC timer LPE — 源码包

PD2506 / V2506A（vivo，kernel 6.1.145）上的 POSIX CPU timer UAF 本地提权链源码。
目标：uid 2000 / `u:r:shell:s0` / SELinux Enforcing → root（fork + exec 终点）。
2026-10-25 已在真机 16.1.13.2 上验证（run18 一次命中，run21 用交付驱动复现）。

本包只含源码与脚本：**不含日志、QEMU 日志转储、initrd 镜像、内核镜像、编译产物**。

## 目录

```
timer_lpe.c            主利用程序（泄漏 → stage1 park → stage2 mcast 写 → 假 cred → fork → sid 扫描 → drop/exec）
reap_init.c            离线 harness 的 init（早期版本；带 ic-out 日志管道）
scratch/reap_init_sb.c 离线 harness 的 init（enforcing 全链用，推荐）
scratch/helper_probe.c 无 libc 探针（验证 drop payload 启动）
mcast61.c              设备侧 mcast/路由原语（6.1 内核对照代码）
mcast_pats.h           泄漏布局模式表
mcsem.c                mcast 语义/写原语试验程序
ic_*.h, mcast_pats.h   目标常量、结构偏移、工具宏
ipv6_*.c, sock_v61.c   内核（6.1.145）网络栈对照源码，用于定位 gadget/行为
user_ns_v61.c          内核 userns/ucounts 对照源码
diag/*.c               pcp/RCU 窗口诊断程序
probe_*.c, pcp*.c      各种分配/回收/权限探针
src/, src145/, ref61/, k61aux/, k61ucount/
                       内核 6.1.145 / 6.1.118 参考源码片段（page_alloc、posix timer、cred、ucounts 等），
                       仅作偏移与行号对照，不参与编译
mkcpiopy.py            initramfs 打包（cpio newc，只收指定文件）
mkctxs.py, drain_digest.py, p2c_digest.py, ptvec_digest.py, scan_refs.py, ...
                       分析/生成辅助脚本
run_*.sh               QEMU 离线复现脚本（按阶段）
kaslrg_loop.sh         多轮 KASLR 批次
gdb*.cmd               QEMU/gdb 调试脚本
scan_*.txt             SELinux 域/SID 扫描输入
device/                手机端交付物源码与驱动（run_lpe.ps1 / run_lpe.sh / run*.sh / README.md）
icapk/                 Shizuku App 源码（Java + AIDL + 无 Gradle 构建脚本 build.sh）
```

## 构建

主程序（NDK/bionic，设备交付版）：

```sh
CC=/d/Android/Sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android29-clang
$CC -O2 -g -D_GNU_SOURCE -static -pthread timer_lpe.c -o exploit.device
```

或 zig/musl：

```sh
zig cc -target aarch64-linux-musl -static -O2 -D_GNU_SOURCE -pthread timer_lpe.c -o exploit
```

离线 harness init：

```sh
zig cc -D_GNU_SOURCE -target aarch64-linux-musl -static -O2 -pthread scratch/reap_init_sb.c -o init
python -I mkcpiopy.py out.cpio.gz init:init exploit:exploit policy.bin:policy.bin ...
```

QEMU 复现（示例，需本机 QEMU 与内核镜像）：

```sh
./run_kaslr_fork.sh kaslr_fork1.log
./run_scan132.sh scan132a.log        # enforcing 终点演练
```

## 手机端

见 `device/README.md`：`run_lpe.ps1 -Check` / `-Run`，或手工
`adb push exploit.device /data/local/tmp/ic-timer` 后跑 `run_lpe.sh`。
每次完整运行前重启手机；`IC_ATTEMPT_WAIT=900` 不可调小（attempt 重叠会 panic）。

## 支持的内核

| 内核 | 状态 |
| --- | --- |
| `6.1.145-android14-11-g3de37d73fd1d`（16.1.13.2） | 真机 run18 / run21 跑通 |
| `6.1.145-android14-11-gf506252fa70d`（16.1.15.0） | QEMU 离线全链跑通（ct16_150） |
