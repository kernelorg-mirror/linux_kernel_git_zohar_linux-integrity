#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <attr/xattr.h>

#include "gencpio.h"

static char *xattr_names;
static char xattr_header[8];	/* number xattrs */
static ssize_t xattr_nameslen;

#define DEFAULT_XATTR_BUFSIZE 1024
static char *xattr_buf;
static unsigned int xattr_bufsize;

unsigned int get_xattrs(const char *name)
{
	char xattr_num[9];
	char *xname, *buf, *bufend;
	int num_xattrs = 0;
	ssize_t xattrsize = 0;
	ssize_t new_xattr_nameslen;

	new_xattr_nameslen = listxattr(name, NULL, 0);
	if (new_xattr_nameslen <= 0)
		return 0;

	if (new_xattr_nameslen > xattr_nameslen) {
		if (xattr_names)
			free(xattr_names);
		xattr_nameslen = new_xattr_nameslen;
		xattr_names = malloc(xattr_nameslen + 1);
		if (!xattr_names) {
			fprintf(stderr, "xattr_names out of memory\n");
			return 0;
		}
	}
	xattr_names[xattr_nameslen] = 0;
	xattr_nameslen = listxattr(name, xattr_names, xattr_nameslen);
	if (xattr_nameslen <= 0)
		return 0;

	/* xattr format: <number of xattrs> {<name> <value-len> <value>} */
	if (!xattr_buf) {
		xattr_buf = malloc(DEFAULT_XATTR_BUFSIZE);
		if (!xattr_buf) {
			fprintf(stderr, "xattr_buf out of memory\n");
			return 0;
		}
		xattr_bufsize = DEFAULT_XATTR_BUFSIZE;

	}
	buf = xattr_buf + sizeof xattr_header;	/* reserve number of xattrs */
	bufend = xattr_buf + xattr_bufsize;

	for (xname = xattr_names; xname < (xattr_names + xattr_nameslen);
	     xname += strlen(xname) + 1) {
		char sizebuf[9];
		int offset;

		/* skip security.evm as it is file system specific */
		if (strcmp(xname, "security.evm") == 0)
			continue;

		xattrsize = getxattr(name, xname, NULL, 0);
		if (xattrsize <= 0)
			continue;

		offset = strlen(xname) + 1 + 8;
		if ((offset + xattrsize + 1) > bufend - buf) {
			char *new_xattr_buf;
			size_t alloc_size;

			alloc_size = offset + xattrsize + 1 - (bufend - buf);
			if (alloc_size < DEFAULT_XATTR_BUFSIZE)
				alloc_size = DEFAULT_XATTR_BUFSIZE;

			new_xattr_buf = realloc(xattr_buf,
						xattr_bufsize + alloc_size);
			if (!new_xattr_buf) {
				fprintf(stderr, "xattr_buf out of memory\n");
				return 0;
			}
			xattr_buf = new_xattr_buf;
			xattr_bufsize += alloc_size;
			buf = xattr_buf + sizeof xattr_header;
			bufend = xattr_buf + xattr_bufsize;
		}

		xattrsize = getxattr(name, xname, buf + offset,
				     bufend - (buf + offset));
		if (xattrsize <= 0)
			continue;

		num_xattrs++;
		fprintf(stderr, "%s: %s %lu (%d)\n", name, xname, xattrsize,
			num_xattrs);

		/* fill in xattr name and value size */
		strcpy(buf, xname);
		buf += strlen(xname) + 1;
		sprintf(sizebuf, "%08X", (int)xattrsize);
		memcpy(buf, sizebuf, 8);
		buf += (8 + xattrsize);
	}

	*buf = 0;
	buf++;
	sprintf(xattr_num, "%08X", num_xattrs);
	memcpy(xattr_buf, xattr_num, 8);	/* fill in number of xattrs */

	return buf - xattr_buf;
}

void include_xattrs(int xattrs_buflen)
{
	if (!xattrs_buflen)
		return;

	if (fwrite(xattr_buf, xattrs_buflen, 1, stdout) != 1)
		fprintf(stderr, "writing xattrs failed\n");
}
