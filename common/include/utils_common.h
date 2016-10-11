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

#ifndef UTILS_COMMON_H
#define UTILS_COMMON_H

#define LOGFATAL(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_FATAL, format, ##args)
#define LOGERROR(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_ERROR, format, ##args)
#define LOGWARN(format, args...)   tmDebugWrite(0, TMDEBUG_LEVEL_WARN, format, ##args)
#define LOGINFO(format, args...)   tmDebugWrite(0, TMDEBUG_LEVEL_INFO, format, ##args)
#define LOGDEBUG(format, args...)  tmDebugWrite(0, TMDEBUG_LEVEL_DEBUG, format, ##args)




int utils_vscan_init(void);
void utils_vscan_exit(void);
int reload_pattern();
int reload_engine(char * buf);
int report_version(char *str, size_t count);



#endif /* UTILS_COMMON_H */
