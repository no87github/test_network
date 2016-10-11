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

#ifndef __FSCTL_VSCAN_H__
#define __FSCTL_VSCAN_H__

#include "vscan.h"

__BEGIN_DECLS

int reload_pattern(const void *buf, size_t count);
int reload_engine(const void *buf, size_t count);
int report_version(char *str, size_t count);
int reload_config(const void *buf, size_t count);
int fsctl_vscan_init(vscan_config_t * vscan_config);
void fsctl_vscan_exit(void);

__END_DECLS

#endif /* __FSCTL_VSCAN_H__ */
