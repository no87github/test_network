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

#ifndef MSG_UTILS_COMMON_H
#define MSG_UTILS_COMMON_H

#include <tmdebug.h>

__BEGIN_DECLS

#define xfree(p) do { if (p) { free(p); (p) = NULL; } } while (0)

#define LOGFATAL(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_FATAL, format, ##args)
#define LOGERROR(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_ERROR, format, ##args)
#define LOGWARN(format, args...)   tmDebugWrite(0, TMDEBUG_LEVEL_WARN, format, ##args)
#define LOGINFO(format, args...)   tmDebugWrite(0, TMDEBUG_LEVEL_INFO, format, ##args)
#define LOGDEBUG(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_DEBUG, format, ##args)

__END_DECLS

#endif /* MSG_UTILS_COMMON */
