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

#ifndef __FS_CAV_H__
#define __FS_CAV_H__

#include <stdint.h>
#include <sys/socket.h>
#include "fs.h"
#include "list.h"
#include "vscan.h"

__BEGIN_DECLS

/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/
typedef struct trigger_buf_st {
    list_head list;
    struct iovec piov[1];
}trigger_buf_t;

typedef struct cav_msg_st {
    uint32_t id;
    list_head trigger_buf_list;
    int fd;
} cav_msg_t;

/****************************************************************************/
/* GLOBAL VARIABLES                                                         */
/****************************************************************************/
extern uint32_t gfile_id;
extern int gfid_list_length;
extern pthread_mutex_t gmutex_file_id;
extern pthread_cond_t gcond_fid_list;
extern list_head gfid_list;
extern int gfd_count;
extern pthread_mutex_t gmutex_fd_count;
extern filescan_conf gfilescan_config;

static inline void __set_B8(unsigned char * dst, uint8_t src)
{
    *dst = src & 0xff;
}

static inline void __set_B16(unsigned char * dst, uint16_t src)
{
    *dst = (src >> 8 ) & 0xff;
    *(dst+1) = src & 0xff;
}

static inline void __set_B32(unsigned char * dst, uint32_t src)
{
    *dst = (src >> 24 ) & 0xff;
    *(dst+1) = (src >> 16 ) & 0xff;
    *(dst+2) = (src >> 8  ) & 0xff;
    *(dst+3) = src & 0xff;
}

static inline void __set_L8(unsigned char * dst, uint8_t src)
{
    *dst = src;
}

static inline void __set_L16(unsigned char * dst, uint16_t src)
{
    *dst = src & 0xff;
    *(dst+1) = (src >> 8 ) & 0xff;
}

static inline void __set_L32(unsigned char * dst, uint32_t src)
{
    *dst = src & 0xff;
    *(dst+1) = (src >> 8  ) & 0xff;
    *(dst+2) = (src >> 16 ) & 0xff;
    *(dst+3) = (src >> 24 ) & 0xff;
}

int
fs_cav(
        VirusResult *vr,
#ifdef USE_ATSE
        scan_evae_result_t *er,
#endif
        thread_data_t *data,
        unsigned char *sha1);

__END_DECLS

#endif /* __FS_CAV_H__ */
