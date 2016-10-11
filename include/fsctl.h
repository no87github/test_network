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

#ifndef __FSCTL_H__
#define __FSCTL_H__

#include "fs_limits.h"

__BEGIN_DECLS

/****************************************************************************/
/* TEXT MACRO DECLARATIONS                                                  */
/****************************************************************************/

#define T_NONE   "NONE"

#define T_READ	 "READ"
#define T_WRITE  "WRITE"
#define T_EXEC   "EXEC"

#define T_RAW    "RAW"
#define T_STRING "STRING"
#define T_INT8   "INT8"
#define T_UINT8  "UINT8"
#define T_INT16  "INT16"
#define T_UINT16 "UINT16"
#define T_INT32  "INT32"
#define T_UINT32 "UINT32"
#define T_INT64  "INT64"
#define T_UINT64 "UINT64"

#define T_CONTENT_TYPE   "Content-Type"
#define T_CONTENT_LENGTH "Content-Length"
#define T_RETURN        "Return"
#define T_CONNECTION    "Connection"
#define T_CLOSE         "Close"

#define FSCTL_SVR_ADDR "127.0.0.1"
#define FSCTL_SVR_PORT 9999

/****************************************************************************/
/* MACRO DECLARATIONS                                                       */
/****************************************************************************/

#define FSCTL_MAX_MIB (256)
#define FSCTL_MAX_BUF (4096)
#define FSCTL_LISTEN_BACKLOG (SOMAXCONN)
#define FSCTL_RESPONSE_SIMPLE \
    "MP/1.0 200 OK\r\n" \
    "Return: %ld\r\n" \
    "\r\n"
#define FSCTL_RESPONSE_CONTENT \
    "MP/1.0 200 OK\r\n" \
    "Content-Type: %s\r\n" \
    "Content-Length: %zu\r\n" \
    "Return: %ld\r\n" \
    "\r\n"
#define FSCTL_RESPONSE_CLOSE \
    "MP/1.0 200 OK\r\n" \
    "Connection: Close\r\n" \
    "Return: 0\r\n" \
    "\r\n"
#define FSCTL_RESPONSE_NOT_FOUND \
    "MP/1.0 404 Not Found\r\n" \
    "Return: -1\r\n" \
    "\r\n"
#define FSCTL_RESPONSE_DATA_TOO_LONG \
    "MP/1.0 414 Data Too Long\r\n" \
    "Return: -1\r\n" \
    "\r\n"
#define FSCTL_RESPONSE_INTERNAL_ERROR \
    "MP/1.0 500 Internal Error\r\n" \
    "Return: -1\r\n" \
    "\r\n"

typedef enum {
    FSCTL_CMD_READ,
    FSCTL_CMD_WRITE,
    FSCTL_CMD_EXEC,
    FSCTL_CMD_NONE,
} enum_fsctl_cmd;

typedef enum {
    FSCTL_CONTENT_TYPE_NONE,
    FSCTL_CONTENT_TYPE_RAW,
    FSCTL_CONTENT_TYPE_STRING,
    FSCTL_CONTENT_TYPE_INT8,
    FSCTL_CONTENT_TYPE_UINT8,
    FSCTL_CONTENT_TYPE_INT16,
    FSCTL_CONTENT_TYPE_UINT16,
    FSCTL_CONTENT_TYPE_INT32,
    FSCTL_CONTENT_TYPE_UINT32,
    FSCTL_CONTENT_TYPE_INT64,
    FSCTL_CONTENT_TYPE_UINT64,
} enum_fsctl_content_type;


__END_DECLS

#endif /* __FSCTL_H__ */
