#include <linux/types.h>

#include "supercall/internal.h"
#include "manager/manager_identity.h"
#include "policy/allowlist.h"

// Permission check functions
bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool trusted_caller(void)
{
	uid_t uid = current_uid().val;

	return uid == 0 || is_manager() || ksu_is_allow_uid_for_current(uid);
}

bool allowed_for_su(void)
{
	bool is_allowed = is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
	return is_allowed;
}
