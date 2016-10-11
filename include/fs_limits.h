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

#ifndef __FS_LIMITS_H__
#define __FS_LIMITS_H__

#include <stdint.h>
#include <limits.h>

__BEGIN_DECLS

/**
 * The maximum number of characters in a filename.
 * (Not including the terminating \0 if the filename is stored as a string).
 */
#ifndef FS_NAME_MAX
#define FS_NAME_MAX (NAME_MAX)
#endif /* FS_NAME_MAX */

/**
 * The maximum number of characters in a complete path name.
 * (Not including the terminating \0 if the path name is stored as a string).
 */
#ifndef FS_PATH_MAX
#define FS_PATH_MAX (PATH_MAX)
#endif /* FS_PATH_MAX */

/**
 * The maximum number of bytes in atomic write to a pipe.
 */
#ifndef FS_PIPE_BUF
#define FS_PIPE_BUF (PIPE_BUF)
#endif /* FS_PIPE_BUF */

/**
 * The maximum length of a host name 
 * (Not including the terminating \0 if the host name is stored as a string).
 */
#ifndef FS_HOST_NAME_MAX
#define FS_HOST_NAME_MAX (HOST_NAME_MAX)
#endif /* FS_HOST_NAME_MAX */

#ifndef FS_PORT_MIN
#define FS_PORT_MIN (0)
#endif /* FS_PORT_MIN */

#ifndef FS_PORT_MAX
#define FS_PORT_MAX (UINT16_MAX)
#endif /* FS_PORT_MAX */

#ifndef FS_BACKTRACE_BUFFER_MAX
#define FS_BACKTRACE_BUFFER_MAX	(8192)
#endif /* FS_BACKTRACE_BUFFER_MAX */

__END_DECLS

#endif /* __FS_LIMITS_H__ */
