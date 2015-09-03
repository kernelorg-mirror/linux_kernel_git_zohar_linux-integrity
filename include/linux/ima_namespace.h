/*
 * Copyright (C) 2008 IBM Corporation
 * Author: Yuqiong Sun <suny@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef __LINUX_IMA_NAMESPACE_H__
#define __LINUX_IMA_NAMESPACE_H__

#include <linux/kref.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/rculist.h>
#include <linux/sched.h>

struct ima_namespace {
	struct kref kref;
	struct user_namespace *user_ns;
	struct ns_common ns;
	struct ima_namespace *parent;
	struct list_head ima_measurements;
};

extern struct ima_namespace init_ima_ns;
static inline struct list_head *get_measurements(void)
{
	return &current->nsproxy->ima_ns->ima_measurements;
}

static inline struct ima_namespace *get_current_ns(void)
{
	return current->nsproxy->ima_ns;
}

#ifdef CONFIG_IMA_NS
void free_ima_ns(struct kref *kref);
void ima_free_queue_entries(struct ima_namespace *ns);

static inline void get_ima_ns(struct ima_namespace *ns)
{
	kref_get(&ns->kref);
}

static inline void put_ima_ns(struct ima_namespace *ns)
{
	kref_put(&ns->kref, free_ima_ns);
}

struct ima_namespace *copy_ima(unsigned long flags,
			       struct user_namespace *user_ns,
			       struct ima_namespace *old_ns);

#else
static inline void get_ima_ns(struct ima_namespace *ns)
{
}

static inline void put_ima_ns(struct ima_namespace *ns)
{
}

static inline struct ima_namespace *copy_ima(unsigned long flags,
					     struct user_namespace *user_ns,
					     struct ima_namespace *old_ns)
{
	if (flags & CLONE_NEWIMA)
		return ERR_PTR(-EINVAL);
	return old_ns;
}
#endif

#endif /* __LINUX_IMA_NAMESPACE_H__ */
