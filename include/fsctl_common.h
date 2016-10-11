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

#ifndef FSCTL_COMMON_H
#define FSCTL_COMMON_H

#include "glcfg.h"
#include "msg_utils.h"
#include "tmdebug.h"
#include "fsctl_vscan.h"
#include "fsctl_cav.h"
#include "fsctl_config.h"
#include "mp_entry.h"
#include "fs_cache.h"

__BEGIN_DECLS

#define LOGFATAL(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_FATAL, format, ##args)
#define LOGERROR(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_ERROR, format, ##args)
#define LOGWARN(format, args...)   tmDebugWrite(0, TMDEBUG_LEVEL_WARN, format, ##args)
#define LOGINFO(format, args...)   tmDebugWrite(0, TMDEBUG_LEVEL_INFO, format, ##args)
#define LOGDEBUG(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_DEBUG, format, ##args)

extern char var_config_file[];
extern char var_text_file[];

__END_DECLS

#endif /* FSCTL_COMMON_H */
