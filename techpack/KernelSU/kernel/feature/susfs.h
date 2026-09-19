#ifndef __KSU_FEATURE_SUSFS_H
#define __KSU_FEATURE_SUSFS_H

#include <linux/init.h>
#include <linux/types.h>

#ifdef CONFIG_KSU_SUSFS
void __init ksu_susfs_init(void);
void ksu_susfs_on_post_fs_data(void);
bool ksu_susfs_should_umount_system_process(uid_t uid);
int ksu_susfs_handle_prctl(int option, unsigned long arg2,
			   unsigned long arg3, unsigned long arg4,
			   unsigned long arg5);
#endif

#endif /* __KSU_FEATURE_SUSFS_H */
