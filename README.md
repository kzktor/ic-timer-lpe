# IC Timer LPE —— CVE-2026-98260

POSIX CPU timer UAF（CVE-2026-98260）的 vivo/iQOO 6.1 提权工具：从 shell 域
拿到 uid 0，并可把 root 交给 KernelSU 系列管理器（late-load 管理器自带的
`ksud` / 内核模块）。

> 仅供学习使用，请下载后24内删除。如设备出现任何问题，概不负责。
> 本软件免费开源，作者酷安 **@散花神木**

## 0.12 做了什么

旧版把每台机器/每个 build 的偏移、喷页几何、slide 方式都写死在主文件里，
一个内核改动就要重新编译。0.12 拆成：

| 模块 | 作用 |
| --- | --- |
| `core/profiles.h` | 每内核常量（静态地址、分配调用点 low21、cred 字段偏移、slab 几何），`-DIC_PROFILE_*` 选择 |
| `core/anchors.h` | 旧工具 9 个 build 的 anchor 表（生成：`core/tools/gen_anchors.py`） |
| `core/extra_syms.h` | fake-cred 需要的对象符号（镜像抽取 + 从 `init_user_ns` 推导） |
| `core/timer98260.c` | 主体：trace oracle → cred 泄漏 → 喷页 → 命中回读 → 写原语 → shell / KSU 终局 |
| `core/ic_syms.c` | 手机端「解析偏移」：boot.img / Image / vmlinux / System.map → 符号表 |
| `harness/qemu_core_init.c` | 本地 QEMU 最小 init（proc/sys/dev/tracefs，可 root 或 uid 2000） |
| `apk/` | Shizuku 用户服务 APK（`run_core.sh` 启动 core） |

关键设计：

- **slide 从 timer 调用点推导**：6.1 的 `do_timer_create` 在镜像里偏移
  < 2 MiB，KASLR slide 按 2 MiB 对齐，所以调用点低 21 位就是链接偏移，
  `slide = site0 - (0xffffffc008000000 + low21)`，不需要 kallsyms；
- **de-tag 地址** = 表里的 `__tracepoint_sys_exit` link + slide（优先
  kallsyms，可读时直接用绝对地址）；
- **fake-cred 对象符号**：`root_user / init_ucounts / init_groups` 在
  16.1/16.2 各 build 上相对 `init_user_ns` 的偏移固定
  （`+0x298 / +0x1b48 / +0x15b8`），由内置表的 `init_user_ns` 推导；
- **写后校验**：shell 路径回读 `/proc/<child>/status` 的 Uid，fake 路径用
  peek 协议让 child 自报 `getuid()/geteuid()`，未命中就重发（≤8 次）。

## 0.13 做了什么

界面从手写 framework View 换成 **移植 Shark 的 Jetpack Compose 界面**
（[Yunnijian/Shark](https://github.com/Yunnijian/Shark)，GPL-3.0）：

- 工程切到 Gradle + Kotlin + Compose（`apk-gradle/`，旧 `apk/` 保留作参照）；
- 底部三页：首页 / 日志 / 关于，沿用 Shark 的 `COUITheme`、`Scaffold`、
  `AnimatedContent`、模糊标题栏与卡片组件；
- 首页：状态卡、一键越狱、ROOT 管理器下拉、安全模式开关、使用手册入口、
  解析偏移 / 清理 KSU / 诊断、设备信息卡；使用手册是独立入口，点开是全屏页；
- 运行进度：点「一键越狱」后主按钮显示阶段（`7/12 零写 vr.ko` 之类），
  结束时短暂显示完成 / 失败；
- 偏移预检：运行前先跑 `ic-timer info`（只读），当前 build 没有可用偏移时
  弹「缺少偏移」对话框，引导到「解析偏移」；
- 解析偏移：识别 boot.img / 全量 OTA 包（zip64 + payload + zstd），自动提取
  boot 分区并与当前设备、版本比对，不一致/init_boot/非 6.1.145 一律拒绝并给出
  对话框说明；
- 日志页实时滚动（清空按钮在标题栏）；关于页为源码 / 社群 / 问题反馈、
  赞赏码与开放源代码许可；
- 后端替换为本站的 Shizuku 用户服务（`IcService` + `run_core.sh`），
  `IC_SYMS_FILE` / `IC_SAFE_MODE` / `IC_KSU` 行为与 0.12 一致。

移植自 Shark 的界面代码使本项目整体按 **GPL-3.0** 分发，见 `LICENSE` 与
`NOTICE`。

## 支持机型（内置偏移，机型 + 版本匹配）

| 机型 | 版本 |
| --- | --- |
| PD2506 / V2506（Y500） | 16.1.15.0、16.1.13.2、16.1.17.0 |
| PD2516 / V2516（Y500 Pro） | 16.1.11.0 |
| PD2307 / PD2329 / V2307（iQOO 12） | 16.2.11、16.2.20.3、16.2.20.7、16.2.21.1 |
| PD2417 / V2417（Z9 Turbo+） | 16.2.14.1 |
| PD2324 / V2324 | 16.2.12.0、16.2.13.1 |
| PD2352 / V2352 | 16.2.17.0 |
| PD2425 / V2425 | 16.1.17.10、16.1.16.2 |
| DPD2329 / PD2329 | 16.2.9.2 |
| PD2339 / V2339 | 16.2.13.1 |
| PD2309 / V2309 | 16.2.15.0 |
| PD2445 / V2445 | 16.1.16.0 |

列表内机型的提权与 KSU 交接都只需要内置数据；列表外的新 build 用 App 的
「解析偏移」从 `boot.img` 生成 `/data/local/tmp/ic-syms.txt`。

已内置表与旧工具解析结果（`dist/ic-syms-*.txt`）的交叉核对脚本：
`core/tools/verify_tables.py`。

## 用法

- 包：`ipe/ic-timer-<ver>/ic-timer-lpe-<ver>.apk`（Shizuku 用户服务，需用
  adb / 无线调试启动 Shizuku，不能用 root 启动）；
- 每次完整运行前重启手机；fake 链中途失败留下的 zombie 不能 kill -9；
- 不选 KSU：shell 域 uid 0 + 证明命令；
- 选 KSU 管理器：fake-cred 全 caps root → `ksu_handoff.sh`（`ksu` 模式）。

## 构建

```sh
core/build.sh /tmp/t98260 qemu_iqoo12     # NDK r27, API 29（API 24 的 TLS
                                          # 对齐会被 bionic 拒绝）
cp core/out/qemu_iqoo12/ic-timer apk-gradle/app/src/main/assets/ic-timer
cd apk-gradle && ./gradlew :app:assembleRelease   # AGP 9.4.1 / Kotlin 2.4.20
```

`apk/`（javac + framework View）是 0.12 及以前的手工构建，留作参照。

`core/tools/gen_anchors.py <Image>` 从内核镜像生成/更新 anchor 表；
`core/tools/verify_tables.py core/anchors.h dist/` 做交叉核对。

## 验证

- QEMU（iQOO 12 6.1.145 镜像）：shell 路径 `ROOT_SHELL_OK`；fake 路径
  `uid=0 euid=0` + payload 执行；
- 真机：PD2329 / PD2307 / PD2425 shell 域 uid 0；PD2425 `late-load rc=0`、
  kernelsu 模块 resident。

## 已知限制

- 真机文件系统布局、不同 build 的 `struct cred` 偏移按已知 build 推导，未
  实测的 build 失败时表现为 `fork/exec errno=12`（ENOMEM），不会 panic；
- 本分支仅适用于 6.1.145 内核的机型。

## 免责声明

本工具仅供**安全研究与自有设备测试**使用。使用前请确认你对目标设备拥有
合法授权；严禁用于未授权设备或任何非法用途。

- 本软件按“现状”提供，不提供任何明示或暗示的担保；
- 提权过程涉及内核写原语，可能导致设备重启、数据损坏甚至变砖；运行前请
  自行备份，并确认具备恢复手段（原厂 boot.img / 完整 OTA）；
- 使用本工具产生的一切后果由使用者自行承担，作者与贡献者不承担任何直接
  或间接责任；
- 请遵守当地法律法规以及设备厂商的用户协议。
