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
#include <crypto/hash_info.h>
#include <linux/string_helpers.h>

#include "ima.h"

struct buffer_idmap {
	enum ima_hooks func;
	char *buf;
};

static struct buffer_idmap _idmap[MEASURING_MAX_BUFFER_ID] = {
	[MEASURING_KEXEC_CMDLINE].func = KEXEC_CMDLINE_CHECK,
	[MEASURING_KEXEC_CMDLINE].buf = "kexec-boot-cmdline",
	[MEASURING_PRECALC_DATA].func = PRECALC_CHECK,
	[MEASURING_PRECALC_DATA].buf = "precalc",
};

#define IMA_MAX_BUFFER_HINT_SIZE 255

static int store_buffer_measurement(struct ima_digest_data *hash, int pcr,
				    char *buffer_hint)
{
	struct ima_template_entry *entry;
	struct integrity_iint_cache tmp_iint, *iint = &tmp_iint;
	struct ima_event_data event_data = {iint, NULL, NULL, NULL, 0, NULL};
	int violation = 0;
	int result;

	iint->ima_hash = hash;
	event_data.filename = buffer_hint;

	result = ima_alloc_init_template(&event_data, &entry);
	if (result < 0)
		return result;

	result = ima_store_template(entry, violation, NULL,
				    event_data.filename, pcr);
	if (result < 0)
		ima_free_template_entry(entry);

	return result;
}

static void process_buffer_measurement(void *buf, loff_t size,
				       enum ima_buffer_id buffer_id, int pcr)
{
	struct {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
	} hash;
	int result;

	memset(&hash, 0, sizeof(hash));
	hash.hdr.algo = ima_hash_algo;
	result = ima_calc_buffer_hash(buf, size, &hash.hdr);
	if (result < 0) {
		pr_debug("failed calculating buffer hash\n");
		return;
	}

	result = store_buffer_measurement(&hash.hdr, pcr,
					  _idmap[buffer_id].buf);
	if (result < 0)
		pr_debug("failed storing buffer measurement\n");
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

/**
 * ima_add_measurement_check - add pre-calculated hash measurement
 * @hashname: pointer to hash algorithm name
 * @digest: pointer to hash digest
 * @size: hash digest size
 * @buffer_id: caller identifier
 * @hint: measurement identifier
 *
 * Include pre-calculated hash measurements in the IMA measurement list.
 * Returns 0 on success, error code otherwise.
 */
int ima_add_measurement_check(const char *hashname, u8 *digest, loff_t size,
			      enum ima_buffer_id buffer_id, char *hint)
{
	struct {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
	} hash;
	int pcr = CONFIG_IMA_MEASURE_PCR_IDX;
	char buffer_hint[IMA_MAX_BUFFER_HINT_SIZE];
	char *buf;
	int result, i;

	if (buffer_id > MEASURING_MAX_BUFFER_ID)
		return -EINVAL;

	if (!ima_match_buffer_id(_idmap[buffer_id].func, &pcr))
		return -EPERM;

	if (!hint) {
		pr_debug("missing buffer hint\n");
		return -EINVAL;
	}

	buf = kstrdup_quotable(hint, GFP_KERNEL);
	if (!buf) {
		pr_debug("failed quoting buffer hint\n");
		return -ENOMEM;
	}

	/* Limit the total measurement hint to IMA_MAX_BUFFER_HINT_SIZE. */
	snprintf(buffer_hint, sizeof(buffer_hint), "(%s) %s",
		 _idmap[buffer_id].buf, buf);
	kfree(buf);

	memset(&hash, 0, sizeof(hash));
	for (i = 1; i < HASH_ALGO__LAST; i++) {
		if (strcmp(hashname, hash_algo_name[i]) != 0)
			continue;
		hash.hdr.algo = i;
		break;
	}
	if (hash.hdr.algo == 0) {
		pr_debug("invalid hash algorithm (%d)\n", hash.hdr.algo);
		return -EINVAL;
	}

	hash.hdr.length = size;
	memcpy(&hash.hdr.digest, digest, size);
	result = store_buffer_measurement(&hash.hdr, pcr, buffer_hint);
	if (result < 0) {
		pr_debug("failed to store buffer measurement\n");
		return result;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ima_add_measurement_check);
