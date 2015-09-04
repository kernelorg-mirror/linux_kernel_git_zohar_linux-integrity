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
#include <linux/fs.h>

/* Moved from ima.h to ima_namespace.h */
#ifndef IMA_HASH_BITS
#define IMA_HASH_BITS 9
#endif
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)

enum ima_fs_flags {
	IMA_FS_BUSY,
};

struct ima_h_table {
	/* Number of stored measurements in the list */
	atomic_long_t len;
	atomic_long_t violations;
	struct hlist_head queue[IMA_MEASURE_HTABLE_SIZE];
};

struct ima_namespace {
	struct kref kref;
	struct user_namespace *user_ns;
	struct ns_common ns;
	struct ima_namespace *parent;
	struct list_head ima_measurements;
	/* Pointer to ns's current policy */
	struct list_head *ima_rules;
	struct list_head ima_temp_rules;
	/* ns's policy rules */
	struct list_head ima_policy_rules;
	/* How many times a policy has been written */
	int nr_extents;
	/* ima_policy file avaiability */
	unsigned long ima_fs_flags;
	/* for policy quick check */
	int ima_policy_flag;
	struct list_head iint_list;
	struct ima_h_table ima_htable;
};

extern struct ima_namespace init_ima_ns;
extern struct list_head ima_default_rules;
static inline struct list_head *get_measurements(struct ima_namespace *ns)
{
	return &ns->ima_measurements;
}

static inline struct list_head *get_current_measurements(void)
{
	return &current->nsproxy->ima_ns->ima_measurements;
}

static inline struct ima_namespace *get_current_ns(void)
{
	return current->nsproxy->ima_ns;
}

static inline struct list_head **get_current_ima_rules(void)
{
	return &current->nsproxy->ima_ns->ima_rules;
}

static inline struct list_head **get_ima_rules(struct ima_namespace *ns)
{
	return &ns->ima_rules;
}

static inline struct list_head *get_ima_policy_rules(struct ima_namespace *ns)
{
	return &ns->ima_policy_rules;
}

static inline struct list_head *get_current_ima_policy_rules(void)
{
	return &current->nsproxy->ima_ns->ima_policy_rules;
}

void ima_update_policy_flag(struct ima_namespace *ns);
int ima_open_policy_ns(struct inode *inode, struct file *filp,
		       struct ima_namespace *ns);
ssize_t ima_write_policy_ns(struct file *file,
			    const char __user *buf,
			    size_t size, loff_t *ppos,
			    struct ima_namespace *ns);
int ima_release_policy_ns(struct inode *inode, struct file *file,
			  struct ima_namespace *ns);

#ifdef CONFIG_IMA_NS
void free_ima_ns(struct kref *kref);
void ima_delete_rules(struct list_head *ima_policy_rules);
void ima_free_queue_entries(struct ima_namespace *ns);
void ima_free_ns_status(struct ima_namespace *ns);

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
