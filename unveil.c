#ifndef __OpenBSD__
int
unveil(const char *path, const char *permissions)
{

	return 0;
}
#endif
