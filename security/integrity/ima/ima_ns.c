/*
 * Copyright (C) 2008 IBM Corporation
 * Author: Yuqiong Sun <suny@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/export.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>

#include "ima.h"

static struct kmem_cache *ns_status_cachep;

struct ima_namespace init_ima_ns = {
	.kref = KREF_INIT(2),
	.user_ns = &init_user_ns,
	.ns.inum = PROC_IMA_INIT_INO,
#ifdef CONFIG_IMA_NS
	.ns.ops = &imans_operations,
#endif
	.parent = NULL,
	.ima_measurements = LIST_HEAD_INIT(init_ima_ns.ima_measurements),
	.ima_rules = &ima_default_rules,
	.ima_policy_rules = LIST_HEAD_INIT(init_ima_ns.ima_policy_rules),
	.ima_temp_rules = LIST_HEAD_INIT(init_ima_ns.ima_temp_rules),
	.nr_extents = 0,
	.ima_fs_flags = 0,
	.ima_policy_flag = 0,
	.iint_list = LIST_HEAD_INIT(init_ima_ns.iint_list),
	.ima_htable = {
		.len = ATOMIC_LONG_INIT(0),
		.violations = ATOMIC_LONG_INIT(0),
		.queue[0 ... IMA_MEASURE_HTABLE_SIZE - 1] = HLIST_HEAD_INIT,
	},
};
EXPORT_SYMBOL(init_ima_ns);

struct ns_status *ima_get_ns_status(struct ima_namespace *ns,
				    struct integrity_iint_cache *iint)
{
	struct ns_status *status;

	rcu_read_lock();

	list_for_each_entry_rcu(status, &iint->ns_list, ns_next) {
		if (status->ns == ns) {
			rcu_read_unlock();
			return status;
		}
	}

	rcu_read_unlock();

	/* First time a namespace opened a inode */

	status = kmem_cache_alloc(ns_status_cachep, GFP_NOFS);
	if (!status)
		return NULL;
	status->ns = ns;
	status->flags = 0UL;
	status->measured_pcrs = 0;
	INIT_LIST_HEAD(&status->ns_next);
	list_add_tail_rcu(&status->ns_next, &iint->ns_list);
	INIT_LIST_HEAD(&status->iint_next);
	list_add_tail_rcu(&status->iint_next, &ns->iint_list);

	return status;
}

void ima_free_ns_status(struct ima_namespace *ns)
{
	struct ns_status *current_status;
	struct ns_status *next_status;

	list_for_each_entry_safe(current_status, next_status,
				 &ns->iint_list, iint_next) {
		if (!list_empty(&current_status->ns_next))
			list_del_rcu(&current_status->ns_next);
		synchronize_rcu();
		list_del_rcu(&current_status->iint_next);
		synchronize_rcu();
		current_status->ns = NULL;
		current_status->flags = 0UL;
		current_status->measured_pcrs = 0;
		kmem_cache_free(ns_status_cachep, current_status);
	}
}

void ima_iint_clear_ns_list(struct integrity_iint_cache *iint)
{
	struct ns_status *current_status, *next_status;

	list_for_each_entry_safe(current_status, next_status,
				 &iint->ns_list, ns_next) {
		list_del_rcu(&current_status->ns_next);
		INIT_LIST_HEAD_RCU(&current_status->ns_next);
		synchronize_rcu();
	}
}

int ima_ns_status_init(void)
{
	ns_status_cachep = KMEM_CACHE(ns_status, SLAB_PANIC);
	return 0;
}
