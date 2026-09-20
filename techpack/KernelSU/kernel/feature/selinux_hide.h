#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

#include <linux/types.h>

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();
int ksu_selinux_hide_validate_context(const char *context, size_t size);
int ksu_selinux_hide_validate_access(const char *request, size_t size);
u32 ksu_selinux_hide_access_seqno(u32 seqno);

#endif
