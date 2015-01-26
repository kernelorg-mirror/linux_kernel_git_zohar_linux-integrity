#ifdef CONFIG_INITRAMFS_XATTRS
extern void include_xattrs(int xattrs_buflen);
extern unsigned int get_xattrs(const char *name);
#else
static inline void include_xattrs(int xattrs_buflen)
{
	return;
}

static inline unsigned int get_xattrs(const char *name)
{
	return 0;
}
#endif
