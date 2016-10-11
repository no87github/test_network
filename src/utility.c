#include <stdio.h>
#include <printf.h>

#include "utility.h"
#include <time.h>

static int print_buffer(FILE *stream, const struct printf_info *info, const void *const *args) {
	unsigned char *p = *(unsigned char**)args[0];
	int width = info->width;
	int len = 0;
	int rc;

	rc = fprintf(stream, "(%d)[", width);
	if(rc == -1) {
		return len;
	}
	len+=rc;

	for(; width>0; width--) {
		rc = fprintf(stream, " %02X", *p++);
		if(rc == -1) {
			return len;
		}
		len+=rc;
	}

	rc = fprintf(stream, " ]");
	if(rc == -1) {
		return len;
	}
	len+=rc;

	return len;
}

static int print_buffer_arginfo(const struct printf_info *info, size_t n, int *argtypes) {
	if(n > 0) {
		argtypes[0] = PA_POINTER;
	}
	return 1;
}

static int print_urlenc(FILE *stream, const struct printf_info *info, const void *const *args) {
	unsigned char *p = *(unsigned char**)args[0];
	unsigned char ch;
	//int width = info->width;
	unsigned int is_long_double = info->is_long_double;
	int len = 0;
	int rc;

	for(; (ch=*p)!=0; p++) {
		if(	(ch>47&&ch<58) || (ch>64&&ch<91) || (ch>96&&ch<123)) {
			rc = fprintf(stream, "%c", ch);
		} else {
			if(is_long_double==0) {
				rc = fprintf(stream, "%%%02X", ch);
			} else {
				rc = fprintf(stream, "%%25%02X", ch);
			}
		}

		if(rc == -1) {
			return len;
		}
		len+=rc;
	}
	return len;
}
	
static int print_urlenc_arginfo(const struct printf_info *info, size_t n, int *argtypes) {
	if(n > 0) {
		argtypes[0] = PA_POINTER;
	}
	return 1;
}

static int print_time(FILE *stream, const struct printf_info *info, const void *const *args) {
	time_t *pt = *(time_t**)args[0];
	//unsigned char ch;
	//int width = info->width;
	int len = 0;
	int rc;

	{
		char buf[128];
		struct tm tm;

		localtime_r(pt, &tm);
		strftime(buf, sizeof(buf), "%m/%d/%Y %H:%M:%S", &tm);
		rc = fprintf(stream, "%s", buf);
		len+=rc;
	}

	return len;
}

static int print_time_arginfo(const struct printf_info *info, size_t n, int *argtypes) {
	if(n > 0) {
		argtypes[0] = PA_POINTER;
	}
	return 1;
}

int register_printf_buffer() {
	register_printf_function('b', print_buffer, print_buffer_arginfo);
	register_printf_function('T', print_time, print_time_arginfo);
	return register_printf_function('U', print_urlenc, print_urlenc_arginfo);
}

int unregister_printf_buffer() {
	register_printf_function('b', 0, 0);
	register_printf_function('T', 0, 0);
	return register_printf_function('U', 0, 0);
}
