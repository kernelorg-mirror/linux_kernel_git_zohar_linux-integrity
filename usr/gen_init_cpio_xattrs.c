#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <attr/xattr.h>

#include "gencpio.h"

#define MAX_XATTRNAMES_SIZE 500

static char xattr_names[MAX_XATTRNAMES_SIZE];
static char xattr_header[8];	/* number xattrs */
static ssize_t xattr_nameslen;
static char xattr_buf[1000];

unsigned int get_xattrs(const char *name)
{
	char xattr_num[9];
	char *xname, *buf, *bufend;
	int num_xattrs = 0;
	ssize_t xattrsize = 0;

	xattr_nameslen = listxattr(name, NULL, 0);
	if (xattr_nameslen <= 0 || xattr_nameslen > MAX_XATTRNAMES_SIZE)
		return 0;

	xattr_names[xattr_nameslen] = 0;
	xattr_nameslen = listxattr(name, xattr_names, xattr_nameslen);
	if (xattr_nameslen <= 0)
		return 0;

	/* xattr format: <number of xattrs> {<name> <value-len> <value>} */
	buf = xattr_buf + sizeof xattr_header;	/* reserve number of xattrs */
	bufend = xattr_buf + sizeof xattr_buf;

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
		if (buf + offset + xattrsize > bufend) {
			fprintf(stderr, "%s: xattrs too large \n", name);
			return 0;
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
