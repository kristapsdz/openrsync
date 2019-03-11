#ifndef __OpenBSD__
int
pledge(const char *promises, const char *execpromises)
{

	return 0;
}
#endif
