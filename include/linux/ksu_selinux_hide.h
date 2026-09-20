#ifndef _LINUX_KSU_SELINUX_HIDE_H
#define _LINUX_KSU_SELINUX_HIDE_H

#include <linux/kconfig.h>
#include <linux/types.h>

#if IS_BUILTIN(CONFIG_KSU)
int ksu_selinux_hide_validate_context(const char *context, size_t size);
int ksu_selinux_hide_validate_access(const char *request, size_t size);
u32 ksu_selinux_hide_access_seqno(u32 seqno);
#else
static inline int ksu_selinux_hide_validate_context(const char *context,
						    size_t size)
{
	return 0;
}

static inline int ksu_selinux_hide_validate_access(const char *request,
						   size_t size)
{
	return 0;
}

static inline u32 ksu_selinux_hide_access_seqno(u32 seqno)
{
	return seqno;
}
#endif

#endif /* _LINUX_KSU_SELINUX_HIDE_H */
