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

#ifndef __FS_SYSLOG_H__
#define __FS_SYSLOG_H__

#include "tmsyslog.h"
#include "fs.h"
#include "SLF2.h"

__BEGIN_DECLS

enum filescan_log_severity_e {
    FILESCAN_LOGSVT_UNKNOWN   = SLF_SEVCODE_UNKNOWN,
    FILESCAN_LOGSVT_INFO      = SLF_SEVCODE_INFORMATION,
    FILESCAN_LOGSVT_WARN      = SLF_SEVCODE_WARNING,
    FILESCAN_LOGSVT_ERR       = SLF_SEVCODE_ERROR,
    FILESCAN_LOGSVT_CRIT      = SLF_SEVCODE_CRITICAL,
    FILESCAN_LOGSVT_UNDEFINED = SLF_SEVCODE_UNDEFINED,
};

#define FILESCAN_LOGTYPE_SYSTEM     (0)

#define FILESCAN_LOGEVT_WARN_INFO   SLF_ACTIVITY_EVT_ERROR_WARNING_INFO

enum filescan_log_msgcode_e {
    FILESCAN_LOGMSG_DISK_ERROR,
    FILESCAN_LOGMSG_CONFIG_CORRUPT,
    FILESCAN_LOGMSG_INTERNAL_ERROR,
    FILESCAN_LOGMSG_VSCAN_ERROR,
    FILESCAN_LOGMSG_CTRL_SVR_START_ERR,
    FILESCAN_LOGMSG_SCAN_SVR_START_ERR,
    FILESCAN_LOGMSG_SCAN_SERVICE_ERR, 
    FILESCAN_LOGMSG_COUNT,
};

int fs_syslog(const int evt_type, const int severity, const int msgcode);

__END_DECLS

#endif /* __FS_SYSLOG_H__ */
