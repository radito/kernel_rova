#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/susfs.h>
#include <linux/uaccess.h>

#include "compat/kernel_compat.h"
#include "feature/susfs.h"
#include "selinux/selinux.h"

#define KERNEL_SU_OPTION 0xDEADBEEFU

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_run_try_umount_for_current_mnt_ns(void);
#endif

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
extern bool susfs_is_auto_add_sus_bind_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
extern bool susfs_is_auto_add_sus_ksu_default_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
extern bool susfs_is_auto_add_try_umount_for_bind_mount_enabled;
#endif

static bool susfs_umount_for_zygote_system_process;

static int susfs_reply(unsigned long arg5, int error)
{
	if (!arg5 || !ksu_access_ok((void __user *)arg5, sizeof(error)))
		return -EFAULT;

	return copy_to_user((void __user *)arg5, &error, sizeof(error)) ?
		-EFAULT : 0;
}

static int susfs_copy_string(unsigned long arg3, unsigned long arg5,
			     const char *value)
{
	int error;
	size_t len = strlen(value) + 1;

	if (!arg3 || !ksu_access_ok((void __user *)arg3, len))
		error = -EFAULT;
	else
		error = copy_to_user((void __user *)arg3, value, len) ?
			-EFAULT : 0;

	susfs_reply(arg5, error);
	return 0;
}

static u64 susfs_enabled_features(void)
{
	u64 features = 0;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	features |= 1ULL << 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	features |= 1ULL << 1;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	features |= 1ULL << 2;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	features |= 1ULL << 3;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	features |= 1ULL << 4;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
	features |= 1ULL << 5;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	features |= 1ULL << 6;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	features |= 1ULL << 7;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	features |= 1ULL << 8;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	features |= 1ULL << 9;
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	features |= 1ULL << 10;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	features |= 1ULL << 11;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	features |= 1ULL << 12;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	features |= 1ULL << 13;
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
	features |= 1ULL << 14;
#endif

	return features;
}

/*
 * SUSFS v1.5.x uses a root-only prctl ABI.  Keep it isolated from the normal
 * KernelSU control plane so an unprivileged app receives the same -EINVAL it
 * would get from an unknown prctl option.
 */
int ksu_susfs_handle_prctl(int option, unsigned long arg2,
			   unsigned long arg3, unsigned long arg4,
			   unsigned long arg5)
{
	int error;

	(void)arg4;

	if ((unsigned int)option != KERNEL_SU_OPTION || current_uid().val != 0)
		return -ENOSYS;

	switch (arg2) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	case CMD_SUSFS_ADD_SUS_PATH:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(struct st_susfs_sus_path)))
			error = -EFAULT;
		else
			error = susfs_add_sus_path(
			(struct st_susfs_sus_path __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	case CMD_SUSFS_ADD_SUS_MOUNT:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(struct st_susfs_sus_mount)))
			error = -EFAULT;
		else
			error = susfs_add_sus_mount(
			(struct st_susfs_sus_mount __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(struct st_susfs_sus_kstat)))
			error = -EFAULT;
		else
			error = susfs_add_sus_kstat(
			(struct st_susfs_sus_kstat __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(struct st_susfs_sus_kstat)))
			error = -EFAULT;
		else
			error = susfs_update_sus_kstat(
			(struct st_susfs_sus_kstat __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	case CMD_SUSFS_ADD_TRY_UMOUNT:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(struct st_susfs_try_umount)))
			error = -EFAULT;
		else
			error = susfs_add_try_umount(
			(struct st_susfs_try_umount __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
	case CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS:
		susfs_run_try_umount_for_current_mnt_ns();
		susfs_reply(arg5, 0);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	case CMD_SUSFS_SET_UNAME:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(struct st_susfs_uname)))
			error = -EFAULT;
		else
			error = susfs_set_uname(
			(struct st_susfs_uname __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	case CMD_SUSFS_ENABLE_LOG:
		if (arg3 > 1)
			error = -EINVAL;
		else {
			susfs_set_log(arg3 != 0);
			error = 0;
		}
		susfs_reply(arg5, error);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE))
			error = -EFAULT;
		else
			error = susfs_set_cmdline_or_bootconfig(
			(char __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(struct st_susfs_open_redirect)))
			error = -EFAULT;
		else
			error = susfs_add_open_redirect(
			(struct st_susfs_open_redirect __user *)arg3);
		susfs_reply(arg5, error);
		return 0;
#endif
	case CMD_SUSFS_SHOW_VERSION:
		return susfs_copy_string(arg3, arg5, SUSFS_VERSION);
	case CMD_SUSFS_SHOW_ENABLED_FEATURES: {
		u64 features = susfs_enabled_features();

		if (!arg3 || !ksu_access_ok((void __user *)arg3,
					      sizeof(features)))
			error = -EFAULT;
		else
			error = copy_to_user((void __user *)arg3, &features,
					     sizeof(features)) ? -EFAULT : 0;
		susfs_reply(arg5, error);
		return 0;
	}
	case CMD_SUSFS_SHOW_VARIANT:
		return susfs_copy_string(arg3, arg5, SUSFS_VARIANT);
	default:
		return -ENOSYS;
	}
}

bool susfs_is_current_ksu_domain(void)
{
	return unlikely(is_ksu_domain());
}

bool susfs_is_current_zygote_domain(void)
{
	return unlikely(is_zygote(current_cred()));
}

static bool __maybe_unused susfs_marker_exists(const char *pathname)
{
	struct path path;

	if (kern_path(pathname, 0, &path))
		return false;

	path_put(&path);
	return true;
}

void ksu_susfs_on_post_fs_data(void)
{
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	susfs_umount_for_zygote_system_process =
		susfs_marker_exists(
			DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS);
	pr_info("susfs: umount zygote system processes: %d\n",
		susfs_umount_for_zygote_system_process);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	if (susfs_marker_exists(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT))
		susfs_is_auto_add_sus_bind_mount_enabled = false;
	pr_info("susfs: auto-add bind mounts: %d\n",
		susfs_is_auto_add_sus_bind_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	if (susfs_marker_exists(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT))
		susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
	pr_info("susfs: auto-add KernelSU mounts: %d\n",
		susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	if (susfs_marker_exists(
		    DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT))
		susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
	pr_info("susfs: auto-add bind mounts to try-umount: %d\n",
		susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif
}

bool ksu_susfs_should_umount_system_process(uid_t uid)
{
	return susfs_umount_for_zygote_system_process && uid >= 1000 &&
		uid < 10000;
}

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void susfs_try_umount_all(uid_t uid)
{
	susfs_try_umount(uid);
}
#endif

void __init ksu_susfs_init(void)
{
	susfs_init();
}
