/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Finite ABI projection from the whole pinned Linux UAPI/driver texts.
 * No host headers or libc. Mapping mutation is guest-only and nonce-owned. */
typedef unsigned long U;
typedef unsigned int U32;
typedef signed int S32;
typedef unsigned long long U64;
struct dm_ioctl {
 U32 version[3],data_size,data_start,target_count;
 S32 open_count;
 U32 flags,event_nr,padding;
 U64 dev;
 char name[128],uuid[129],data[7];
};
struct dm_target_versions { U32 next,version[3];char name[]; };
struct kernel_utsname {char sysname[65],nodename[65],release[65],version[65],machine[65],domainname[65];};
#define NR_IOCTL 29
#define NR_OPENAT 56
#define NR_CLOSE 57
#define NR_READ 63
#define NR_WRITE 64
#define NR_SYNC 81
#define NR_EXIT_GROUP 94
#define NR_REBOOT 142
#define NR_UNAME 160
#define NR_GETPID 172
#define AT_PAGESZ 6
#define DM_MAJOR 4
#define DM_MINOR 50
#define DM_PATCH 0
#define DM_VERSION_CMD 0
#define DM_LIST_VERSIONS_CMD 13
#define DM_IOCTL_CODE(n) ((3U<<30)|(312U<<16)|(0xfdU<<8)|(n))
#define DM_BUFFER_FULL_FLAG (1U<<8)
#define DM_DATA_OUT_FLAG (1U<<16)
#define LINUX_REBOOT_MAGIC1 0xfee1deadU
#define LINUX_REBOOT_MAGIC2 0x28121969U
#define LINUX_REBOOT_CMD_POWER_OFF 0x4321fedcU
_Static_assert(sizeof(U)==8,"LP64 required");
_Static_assert(sizeof(struct dm_ioctl)==312,"whole pinned dm_ioctl ABI");
_Static_assert(__builtin_offsetof(struct dm_ioctl,data_start)==16,"data_start ABI");
_Static_assert(__builtin_offsetof(struct dm_ioctl,dev)==40,"device ABI");
_Static_assert(sizeof(struct dm_target_versions)==16,"target versions ABI");

struct dm_target_spec {U64 sector_start,length;S32 status;U32 next;char target_type[16];};
#define NR_UMOUNT2 39
#define NR_MOUNT 40
#define NR_PREAD64 67
#define NR_FSTAT 80
#define BLKROGET 0x125eU
#define BLKGETSIZE64 0x80081272U
#define DM_DEV_CREATE_CMD 3
#define DM_DEV_REMOVE_CMD 4
#define DM_DEV_SUSPEND_CMD 6
#define DM_DEV_STATUS_CMD 7
#define DM_TABLE_LOAD_CMD 9
#define DM_TABLE_STATUS_CMD 12
_Static_assert(sizeof(struct dm_target_spec)==40,"whole pinned target spec ABI");
