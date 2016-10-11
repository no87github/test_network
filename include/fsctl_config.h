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

#ifndef __FSCTL_CONFIG_H__
#define __FSCTL_CONFIG_H__

#include "fs_config.h"

__BEGIN_DECLS

int enable_scan_read(int32_t *val);
int enable_scan_write(int32_t val);
int use_fse_sha1_read(char* str, size_t count);
int use_fse_sha1_write(int32_t val);
int hit_rate_limit_read(char* str, size_t count);
int hit_rate_limit_write(char* str, size_t count);
int save_scanning_file_read(int32_t *val);
int save_scanning_file_write(int32_t val);
int log_level_read(int32_t *val);
int log_level_write(int32_t val);
int log_level_reload(int32_t val);
int fsctl_config_init(char * config);
void fsctl_config_exit(void);
int fsctl_config_reload();

extern filescan_conf       gfilescan_config;
extern threadpool_conf     gthreadpool_config;

__END_DECLS

#endif /* __FSCTL_CONFIG_H__ */
