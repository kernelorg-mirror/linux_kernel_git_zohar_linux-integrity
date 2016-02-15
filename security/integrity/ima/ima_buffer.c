/*
 * Copyright (C) 2016 IBM Corporation
 *
 * Author:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/ima.h>

#include "ima.h"

struct buffer_idmap {
	enum ima_hooks func;
	char *buf;
};

static struct buffer_idmap _idmap[MEASURING_MAX_BUFFER_ID] = {
	[MEASURING_KEXEC_CMDLINE].func = KEXEC_CMDLINE_CHECK,
	[MEASURING_KEXEC_CMDLINE].buf = "boot-cmdline",
};

static void process_buffer_measurement(void *buf, loff_t size,
				       enum ima_buffer_id buffer_id, int pcr)
{
	struct {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
	} hash;
	struct ima_template_entry *entry;
	struct integrity_iint_cache tmp_iint, *iint = &tmp_iint;
	struct ima_event_data event_data = {iint, NULL, NULL, NULL, 0, NULL};
	int violation = 0;
	int result;

	memset(&hash, 0, sizeof(hash));
	hash.hdr.algo = ima_hash_algo;
	result = ima_calc_buffer_hash(buf, size, &hash.hdr);
	if (result < 0) {
		pr_debug("failed calculating buffer hash\n");
		return;
	}

	iint->ima_hash = &hash.hdr;
	event_data.filename = _idmap[buffer_id].buf;
	result = ima_alloc_init_template(&event_data, &entry);
	if (result < 0) {
		pr_debug("failed allocating template\n");
		return;
	}

	result = ima_store_template(entry, violation, NULL,
				    event_data.filename, pcr);
	if (result < 0) {
		pr_debug("failed storing buffer measurement\n");
		ima_free_template_entry(entry);
	}
}

/**
 * ima_buffer_check - based on policy, collect & store buffer measurement
 * @buf: pointer to buffer
 * @size: size of buffer
 * @buffer_id: caller identifier
 *
 * Buffers can only be measured, not appraised.
 */
void ima_buffer_check(void *buf, loff_t size, enum ima_buffer_id buffer_id)
{
	int pcr = CONFIG_IMA_MEASURE_PCR_IDX;

	if (buffer_id > MEASURING_MAX_BUFFER_ID)
		return;

	if (!ima_match_buffer_id(_idmap[buffer_id].func, &pcr))
		return;

	process_buffer_measurement(buf, size, buffer_id, pcr);
}
EXPORT_SYMBOL_GPL(ima_buffer_check);
