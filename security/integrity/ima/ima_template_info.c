/*
 * Copyright (C) 2013 IBM Corporation
 *
 * Author:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <crypto/hash_info.h>
#include "ima.h"

const char *IMA_TEMPLATE_NAME = "ima";
const char *IMA_NG_TEMPLATE_NAME = "ima-ng";

const char *const template_hash_name[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]		= "ima-md4",
	[HASH_ALGO_MD5]		= "ima-md5",
	[HASH_ALGO_SHA1]	= "ima-sha1",
	[HASH_ALGO_RIPE_MD_160]	= "ima-rmd160",
	[HASH_ALGO_SHA256]	= "ima-sha256",
	[HASH_ALGO_SHA384]	= "ima-sha384",
	[HASH_ALGO_SHA512]	= "ima-sha512",
	[HASH_ALGO_SHA224]	= "ima-sha224",
	[HASH_ALGO_RIPE_MD_128]	= "ima-rmd128",
	[HASH_ALGO_RIPE_MD_256]	= "ima-rmd256",
	[HASH_ALGO_RIPE_MD_320]	= "ima-rmd320",
	[HASH_ALGO_WP_256]	= "ima-wp256",
	[HASH_ALGO_WP_384]	= "ima-wp384",
	[HASH_ALGO_WP_512]	= "ima-wp512",
	[HASH_ALGO_TGR_128]	= "ima-tgr128",
	[HASH_ALGO_TGR_160]	= "ima-tgr160",
	[HASH_ALGO_TGR_192]	= "ima-tgr192",
};
