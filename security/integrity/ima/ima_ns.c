#include <linux/export.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/ima_namespace.h>

struct ima_namespace init_ima_ns = {
	.kref = KREF_INIT(2),
	.user_ns = &init_user_ns,
	.ns.inum = PROC_IMA_INIT_INO,
#ifdef CONFIG_IMA_NS
	.ns.ops = &imans_operations,
#endif
	.parent = NULL,
	.ima_measurements = LIST_HEAD_INIT(init_ima_ns.ima_measurements),
};
EXPORT_SYMBOL(init_ima_ns);
