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

#ifndef __FS_H__
#define __FS_H__

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef PROJECT_RUNTIME_PATH
#warning "PROJECT_RUNTIME_PATH not defined"
#endif

#include <stdint.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "vsapi2_btscan.h"
#include "vscan.h"

typedef struct thread_data_st
{
    const char* qid;
    int sd;
    int cav_sd;
    struct sockaddr_un cav_sockname;
    socklen_t cav_socklen;
    int fd;
    struct btheader_npu2fpga sinfo;
    uint32_t file_id;
    uint16_t pattern_id;
    uint32_t pattern_ver;
    uint32_t session_id;
    unsigned char file_sha1[20];
    unsigned char * filename;
    long long file_size;
    int over_sized;
    VSCTYPE thread_vsc;
    unsigned int *patse_reload_indicator;
    VscanHandle *vsh;
    uint32_t scanbuf_size;
    char scanbuf[0];    // !!! DO NOT APPEND !!!!
}thread_data_t;

#ifdef  __cplusplus
} /* extern "C" */
#endif

#include "fs_limits.h"
#include "fs_log.h"
#include "fsctl_svr.h"
#include "fs_syslog.h"
#include "fs_config.h"
#include "fs_cav.h"
#include "fs_cache.h"


#endif /* __FS_H__ */
