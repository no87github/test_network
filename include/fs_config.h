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

#ifndef __FS_CONFIG_H__
#define __FS_CONFIG_H__

#include <stdint.h>

__BEGIN_DECLS

#define DEFAULT_FS_LOGLEVEL     (0)
#define DEFAULT_FS_ENABLE_SCAN  (1)
#define DEFAULT_FS_USE_FSE_SHA1  (1)
#define DEFAULT_FS_FID_LIST_SIZE	(500)
#define DEFAULT_FS_SAVE_SCANNING_FILE  (0)
#define DEFAULT_FS_HASH_SIZE  (4)
#define DEFAULT_FS_CACHE_SIZE  (16)
#define DEFAULT_FS_SCANBUF_SIZE (1024*1024)
#define DEFAULT_FS_FORCE_SAVE_SCANNING_FILE  (0)
#define DEFAULT_POOL_SIZE		(20)
#define DEFAULT_INIT_THREAD		(10)
#define DEFAULT_MAX_TASKS		(32768)
#define DEFAULT_DETECT_PERIOD	(500)
#define DEFAULT_STACK_SIZE      (4096000)
#define DEFAULT_HIGH_TASK_WATERMARK	(100)
#define DEFAULT_LOW_TASK_WATERMARK	(10)

#define DEFAULT_DEBUGLOG_FILE   "/var/log/filescan.log"
#define TEMP_SCANNING_FILENAME  "/var/fs2_tmp/file_id_%ld%s%s.tmp"

#define FILESCAN_CONF_MODULE            "filescan"
#define FILESCAN_CONF_PARAM_LOGLEVEL    "loglevel"
#define FILESCAN_CONF_PARAM_ENABLE_SCAN    "enable_scan"
#define FILESCAN_CONF_PARAM_FID_LIST_SIZE    "fid_list_size"
#define FILESCAN_CONF_PARAM_SAVE_SCANNING_FILE "save_scanning_file"
#define FILESCAN_CONF_PARAM_HASH_SIZE "hash_size"
#define FILESCAN_CONF_PARAM_CACHE_SIZE "cache_size"
#define FILESCAN_CONF_PARAM_USE_FSE_SHA1    "use_fse_sha1"
#define FILESCAN_CONF_PARAM_HIT_RATE_LIMIT "hit_rate_limit"
#define FILESCAN_CONF_PARAM_SCANBUF_SIZE "scanbuf_size"
#define FILESCAN_CONF_PARAM_FORCE_SAVE_SCANNING_FILE "force_save_scanning_file"
#define THREAD_POOL_CONF_MODULE          "thread_pool"
#define THREAD_POOL_CONF_PARAM_POOL_SIZE         "pool_size"
#define THREAD_POOL_CONF_PARAM_INIT_THREADS         "init_threads"
#define THREAD_POOL_CONF_PARAM_MAX_TASKS         "max_tasks"
#define THREAD_POOL_CONF_PARAM_DETECT_LOAD_PERIOD         "detect_load_period"
#define THREAD_POOL_CONF_PARAM_STACK_SIZE         "stack_size"
#define THREAD_POOL_CONF_PARAM_HIGH_TASK_WATERMARK         "high_task_watermark"
#define THREAD_POOL_CONF_PARAM_LOW_TASK_WATERMARK         "low_task_watermark"

/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/
typedef struct filescan_conf_t {
//    int loglevel;
    int enable_scan;
    int fid_list_size;
    int save_scanning_file;
    unsigned int hash_size;
    unsigned int cache_size;
    int use_fse_sha1;
    double hit_rate_limit;
    uint32_t scanbuf_size;
    int force_save_scanning_file;
} filescan_conf;

typedef struct threadpool_conf_t {
    int pool_size;
    int init_threads;
    int max_tasks;
    int detect_load_period;
    int stack_size;
    int high_task_watermark;
    int low_task_watermark;
} threadpool_conf;

__END_DECLS

#endif /* __FS_CONFIG_H__ */
