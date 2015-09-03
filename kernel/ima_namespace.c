/*
 * Copyright (C) 2008 IBM Corporation
 * Author: Yuqiong Sun <suny@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/export.h>
#include <linux/ima_namespace.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>
#include <linux/capability.h>
#include <linux/cred.h>

static struct ima_namespace *create_ima_ns(void)
{
	struct ima_namespace *ima_ns;

	ima_ns = kmalloc(sizeof(*ima_ns), GFP_KERNEL);
	if (ima_ns)
		kref_init(&ima_ns->kref);

	return ima_ns;
}

/**
 * Clone a new ns copying an original ima namespace, setting refcount to 1
 * @old_ns: old ima namespace to clone
 * @user_ns: user namespace that current task runs in
 * Return ERR_PTR(-ENOMEM) on error (failure to kmalloc), new ns otherwise
 */
static struct ima_namespace *clone_ima_ns(struct user_namespace *user_ns,
					  struct ima_namespace *old_ns)
{
	struct ima_namespace *ns;
	int err;

	ns = create_ima_ns();
	if (!ns)
		return ERR_PTR(-ENOMEM);

	err = ns_alloc_inum(&ns->ns);
	if (err) {
		kfree(ns);
		return ERR_PTR(err);
	}

	ns->ns.ops = &imans_operations;
	get_ima_ns(old_ns);
	ns->parent = old_ns;
	ns->user_ns = get_user_ns(user_ns);
	INIT_LIST_HEAD(&ns->ima_measurements);

	return ns;
}

/**
 * Copy task's ima namespace, or clone it if flags
 * specifies CLONE_NEWIMA.  In latter case, events
 * in new ima namespace will be measured against a
 * separate measurement policy and results will be
 * extended into a sparate measurement list
 *
 * @flags: flags used in the clone syscall
 * @user_ns: user namespace that current task runs in
 * @old_ns: old ima namespace to clone
 */
struct ima_namespace *copy_ima(unsigned long flags,
			       struct user_namespace *user_ns,
			       struct ima_namespace *old_ns)
{
	struct ima_namespace *new_ns;

	BUG_ON(!old_ns);
	get_ima_ns(old_ns);

	if (!(flags & CLONE_NEWIMA))
		return old_ns;

	new_ns = clone_ima_ns(user_ns, old_ns);
	put_ima_ns(old_ns);

	return new_ns;
}

static void destroy_ima_ns(struct ima_namespace *ns)
{
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	ima_free_queue_entries(ns);
	kfree(ns);
}

void free_ima_ns(struct kref *kref)
{
	struct ima_namespace *ns;
	struct ima_namespace *parent;

	ns = container_of(kref, struct ima_namespace, kref);

	while (ns != &init_ima_ns) {
		parent = ns->parent;
		destroy_ima_ns(ns);
		put_ima_ns(parent);
		ns = parent;
	}
}

static inline struct ima_namespace *to_ima_ns(struct ns_common *ns)
{
	return container_of(ns, struct ima_namespace, ns);
}

static struct ns_common *imans_get(struct task_struct *task)
{
	struct ima_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->ima_ns;
		get_ima_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void imans_put(struct ns_common *ns)
{
	put_ima_ns(to_ima_ns(ns));
}

static int imans_install(struct nsproxy *nsproxy, struct ns_common *new)
{
	struct ima_namespace *ns = to_ima_ns(new);

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	get_ima_ns(ns);
	put_ima_ns(nsproxy->ima_ns);
	nsproxy->ima_ns = ns;
	return 0;
}

const struct proc_ns_operations imans_operations = {
	.name    = "ima",
	.type    = CLONE_NEWIMA,
	.get     = imans_get,
	.put     = imans_put,
	.install = imans_install,
};
