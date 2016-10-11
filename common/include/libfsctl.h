/**
 * Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This
 * program is an unpublished copyrighted work which is proprietary to Trend
 * Micro Incorporated and contains confidential information that is not to be
 * reproduced or disclosed to any other person or entity without prior written
 * consent from Trend Micro, Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as unauthorized
 * preparation of derivative works based upon the program or distribution of
 * copies by sale, rental, lease or lending are violations of federal copyright
 * laws and state trade secret laws, punishable by civil and criminal
 * penalties.
 */

#ifndef __LIBFSCTL_H__
#define __LIBFSCTL_H__

//#include <unistd.h>
//#include <stdint.h>
#include "fsctl.h"

__BEGIN_DECLS

ssize_t fsctl_read_raw(const char *name, void *buf, size_t count);
ssize_t fsctl_read_string(const char *name, char *str, size_t count);
int fsctl_read_int32(const char *name, int32_t *val);
int fsctl_read_uint32(const char *name, uint32_t *val);

ssize_t fsctl_write_raw(const char *name, const void *buf, size_t count);
ssize_t fsctl_write_string(const char *name, const char *str, size_t count);
int fsctl_write_int32(const char *name, int32_t val);
int fsctl_write_uint32(const char *name, uint32_t val);

int fsctl_exec_raw(const char *name, const void *buf, size_t count);
int fsctl_exec_string(const char *name, const char *str, size_t count);
int fsctl_exec_int32(const char *name, int32_t val);
int fsctl_exec_uint32(const char *name, uint32_t val);

__END_DECLS

#endif /* __LIBFSCTL_H__ */
