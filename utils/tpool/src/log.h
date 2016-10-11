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

#ifndef LOG_H
#define LOG_H

#include <unistd.h>

__BEGIN_DECLS

#ifdef USE_TMDEBUG
#include <tmdebug.h>
#define LOGFATAL(format, args...)  tmDebugWrite(NULL, TMDEBUG_LEVEL_FATAL, format, ##args)
#define LOGERROR(format, args...)  tmDebugWrite(NULL, TMDEBUG_LEVEL_ERROR, format, ##args)
#define LOGWARN(format, args...)   tmDebugWrite(NULL, TMDEBUG_LEVEL_WARN, format, ##args)
#define LOGINFO(format, args...)   tmDebugWrite(NULL, TMDEBUG_LEVEL_INFO, format, ##args)
#define LOGDEBUG(format, args...)  tmDebugWrite(NULL, TMDEBUG_LEVEL_DEBUG, format, ##args)
#else
#define LOGFATAL(format, args...)  printf("F: " format "\n", ##args)
#define LOGERROR(format, args...)  printf("E: " format "\n", ##args)
#define LOGWARN(format, args...)   printf("W: " format "\n", ##args)
#define LOGINFO(format, args...)   printf("I: " format "\n", ##args)
#define LOGDEBUG(format, args...)  printf("D: " format "\n", ##args)
#endif

__END_DECLS

#endif /* LOG_H */
