/*
 * Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This program is an unpublished
 * copyrighted work which is proprietary to Trend Micro Incorporated and contains confidential
 * information that is not to be reproduced or disclosed to any other person or entity without prior
 * written consent from Trend Micro, Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as unauthorized preparation of
 * derivative works based upon the program or distribution of copies by sale, rental, lease or
 * lending are violations of federal copyright laws and state trade secret laws, punishable by civil
 * and criminal penalties.
 */

/*
 * msg_utils.h
 *
 * Description: header file of common functions for message related module
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */

#ifndef MSG_UTILS_H
#define MSG_UTILS_H

#include <unistd.h>
#include <stdlib.h>
#include "tmdebug.h"
//#include <tmmsg_def.h>
#include "msg_utils_def.h"
#include "glcfg.h"

#ifdef __cplusplus
extern "C" {
#endif

int   mu_read_vscan_common_setting(glcfg_t glcfg, common_config_t *common);
int   mu_read_vscan_protocol_setting(glcfg_t glcfg, char *module, protocol_config_t *protocol);
ssize_t mu_read_line_from_file(const char *file, char *entry_list[], size_t entry_max);

/* engine reload API*/
void *mu_library_loader_open(const char *path);
int   mu_library_loader_resolve(void *handle,const char *symbol,void **ppv);
int   mu_library_loader_close(void *handle);
const char *mu_library_loader_error(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
