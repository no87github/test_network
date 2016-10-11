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

#include "fs_cav.h"

#ifndef __FSCTL_CAV_H__
#define __FSCTL_CAV_H__

int fid_list_size_read(int32_t *val);
int fid_list_size_write(int32_t val);
int fid_list_dump(char *str, size_t count);

#endif /* __FSCTL_CAV_H__ */
