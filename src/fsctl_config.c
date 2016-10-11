#include <assert.h>
#include <errno.h>
#include "list.h"
#include "fs_config.h"
#include "fsctl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************/
/*                 GLOBAL  VARIABLE                  */
/*****************************************************/
filescan_conf       gfilescan_config = {0};
threadpool_conf     gthreadpool_config = {0};

/*****************************************************/
/*                  STATIC FNUCTION                  */
/*****************************************************/


#ifdef __cplusplus
} /* extern "C" */
#endif

int enable_scan_read(int32_t *val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++ENABLE_SCAN_READ++");
#endif
    if (val == NULL)
    {
        LOGERROR("filescan.enable_scan_read:val == NULL");
        ret = EPERM;
    }
    else /* val != NULL */
    {
        *val = gfilescan_config.enable_scan;
        LOGINFO("filescan.enable_scan_read:%d", gfilescan_config.enable_scan);
    }
#ifdef DEBUG
    LOGDEBUG("--ENABLE_SCAN_READ--");
#endif
    return ret;
}


int enable_scan_write(int32_t val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++ENABLE_SCAN_WRITE++");
#endif
    if ( 0 > val || 1 < val ) {
        LOGERROR("filescan.enable_scan_write: failed, val:%d", val);
        ret = EPERM;
    }
    else {
        gfilescan_config.enable_scan = val;
        LOGINFO("filescan.enable_scan_write:%d", gfilescan_config.enable_scan);
    }
#ifdef DEBUG
    LOGDEBUG("--ENABLE_SCAN_WRITE--");
#endif
    return ret;
}

int use_fse_sha1_read(char* str, size_t count)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++USE_FSE_SHA1_READ++");
#endif

    ret = snprintf(str, count, "%d", gfilescan_config.use_fse_sha1);

#ifdef DEBUG
    LOGDEBUG("--USE_FSE_SHA1_READ--");
#endif
    return ret;
}


int use_fse_sha1_write(int32_t val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++USE_FSE_SHA1_WRITE++");
#endif
    if ( 0 > val || 1 < val ) {
        LOGERROR("filescan.use_fse_sha1_write: failed, val:%d", val);
        ret = EPERM;
    }
    else {
        gfilescan_config.use_fse_sha1 = val;
        LOGINFO("filescan.use_fse_sha1_write:%d", gfilescan_config.use_fse_sha1);
    }
#ifdef DEBUG
    LOGDEBUG("--USE_FSE_SHA1_WRITE--");
#endif
    return ret;
}

int hit_rate_limit_read(char* str, size_t count)
{
    int ret = 0;

#ifdef DEBUG
    LOGDEBUG("++HIT_RATE_LIMIT_READ++");
#endif

    ret = snprintf(str, count, "%.2f%s",
        gfilescan_config.hit_rate_limit,
        (gfilescan_config.hit_rate_limit <  0.0 || gfilescan_config.hit_rate_limit >= 1.0)? " (simulation disabled)":
        (gfilescan_config.hit_rate_limit == 0.0)? " (assuming all cache missed)": "");

    LOGINFO("filescan.hit_rate_limit:%.2f", gfilescan_config.hit_rate_limit);

#ifdef DEBUG
    LOGDEBUG("--HIT_RATE_LIMIT_READ--");
#endif
    return ret;
}


int hit_rate_limit_write(char* str, size_t count)
{
    int ret = -1;

#ifdef DEBUG
    LOGDEBUG("++HIT_RATE_LIMIT_WRITE++");
#endif
    char number[32];
    int  len = count >= sizeof(number)? sizeof(number) - 1: count;

    strncpy(number, str, len);
    number[len] = '\0';

    double val = atof(number);

    if(val < 0) {
        val = -1;
    } else if(val > 1) {
        val = 1;
    }

    gfilescan_config.hit_rate_limit = val;
    LOGINFO("filescan.hit_rate_limit:%.2f", gfilescan_config.hit_rate_limit);

#ifdef DEBUG
    LOGDEBUG("--HIT_RATE_LIMIT_WRITE--");
#endif
    return ret;
}

int save_scanning_file_read(int32_t *val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++SAVE_SCANNING_FILE_READ++");
#endif
    if (val == NULL)
    {
        LOGERROR("filescan.save_scanning_file_read:val == NULL");
        ret = EPERM;
    }
    else /* val != NULL */
    {
        *val = gfilescan_config.save_scanning_file;
        LOGINFO("filescan.save_scanning_file_read:%d", gfilescan_config.save_scanning_file);
    }
#ifdef DEBUG
    LOGDEBUG("--SAVE_SCANNING_FILE_READ--");
#endif
    return ret;
}

int save_scanning_file_write(int32_t val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++SAVE_SCANNING_FILE_WRITE++");
#endif
    if ( 0 > val || 1 < val ) {
        LOGERROR("filescan.save_scanning_file_write: failed, val:%d", val);
        ret = EPERM;
    }
    else {
        gfilescan_config.save_scanning_file = val;
        LOGINFO("filescan.save_scanning_file_write:%d", gfilescan_config.save_scanning_file);
    }
#ifdef DEBUG
    LOGDEBUG("--SAVE_SCANNING_FILE_WRITE--");
#endif
    return ret;
}

int log_level_read(int32_t *val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++LOG_LEVEL_READ++");
#endif
    if (val == NULL)
    {
        LOGERROR("filescan.log_level_read:val == NULL");
        ret = EPERM;
    }
    else /* val != NULL */
    {
        *val = tmDebugGetLevel(NULL);
        LOGINFO("filescan.log_levle_read:%d", *val);
    }
#ifdef DEBUG
    LOGDEBUG("--LOG_LEVEL_READ--");
#endif
    return ret;
}

int log_level_write(int32_t val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++LOG_LEVEL_WRITE++");
#endif
    if ( TMDEBUG_LEVEL_DISABLE > val || TMDEBUG_LEVEL_DEBUG < val ) {
        LOGERROR("filescan.log_level: failed, val:%d", val);
        ret = EPERM;
    }
    else {
        ret = tmDebugSetLevel(NULL, val);
        LOGINFO("filescan.log_level_write:%d", tmDebugGetLevel(NULL));
    }
#ifdef DEBUG
    LOGDEBUG("--LOG_LEVEL_WRITE--");
#endif
    return ret;
}

int log_level_reload(int32_t val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++LOG_LEVEL_RELOAD++");
#endif
    tmDebugCloseDefault();
    ret = tmDebugOpenDefault(TmDebugFile, DEFAULT_DEBUGLOG_FILE);
    if (ret) {
        fprintf(stderr, "tmDebugOpenDefault: failed, ret=%d, %m\n", ret);
        return -1;
    }
    ret = tmDebugGetLevel(NULL);
    LOGINFO("filescan.log_levle_reload:%d", ret);
    ret = 0;
#ifdef DEBUG
    LOGDEBUG("--LOG_LEVEL_RELOAD--");
#endif
    return ret;
}

int 
fsctl_config_init(char * conf)
{
    glcfg_t config;
    int ret = 0;
    const char *pv=NULL, *po=NULL;
#ifdef DEBUG
    LOGDEBUG("+FSCTL_CONFIG!");
#endif

    if(NULL==(config=glcfg_open(conf, GLCFG_MODE_READ))) {
        LOGERROR("Failed to open configuration file: %s", conf);
        ret = -1;
        goto leave_load_config;
    }
    /* Common config */
#if 0
    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_LOGLEVEL, &po);
    if(pv!=NULL) {
        gfilescan_config.loglevel = atoi(pv);
    } else {
        gfilescan_config.loglevel = DEFAULT_FS_LOGLEVEL;
    }
#endif

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_ENABLE_SCAN, &po);
    if(pv!=NULL) {
        gfilescan_config.enable_scan = atoi(pv);
    } else {
        gfilescan_config.enable_scan = DEFAULT_FS_ENABLE_SCAN;
    }    
    
    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_USE_FSE_SHA1, &po);
    if(pv!=NULL) {
        gfilescan_config.use_fse_sha1 = atoi(pv);
    } else {
        gfilescan_config.use_fse_sha1 = DEFAULT_FS_USE_FSE_SHA1;
    }    
    
    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_FID_LIST_SIZE, &po);
    if(pv!=NULL) {
        gfilescan_config.fid_list_size = atoi(pv);
    } else {
        gfilescan_config.fid_list_size = DEFAULT_FS_FID_LIST_SIZE;
    }

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_SAVE_SCANNING_FILE, &po);
    if(pv!=NULL) {
        gfilescan_config.save_scanning_file = atoi(pv);
    } else {
        gfilescan_config.save_scanning_file = DEFAULT_FS_SAVE_SCANNING_FILE;
    }

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_HASH_SIZE, &po);
    if(pv!=NULL) {
        gfilescan_config.hash_size = (unsigned int)atoi(pv);
    } else {
        gfilescan_config.hash_size = DEFAULT_FS_HASH_SIZE;
    }
    
    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_CACHE_SIZE, &po);
    if(pv!=NULL) {
        gfilescan_config.cache_size = (unsigned int)atoi(pv);
    } else {
        gfilescan_config.cache_size = DEFAULT_FS_CACHE_SIZE;
    }

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_HIT_RATE_LIMIT, &po);
    if(pv!=NULL) {
        gfilescan_config.hit_rate_limit = atof(pv);

        if(gfilescan_config.hit_rate_limit < 0) {
            gfilescan_config.hit_rate_limit = -1;
        } else if(gfilescan_config.hit_rate_limit > 1) {
            gfilescan_config.hit_rate_limit = 1;
        }
        if(gfilescan_config.hit_rate_limit >= 0 && gfilescan_config.hit_rate_limit < 1) {
            LOGDEBUG("++enabled hit_rate_limit = %2.2f%%", gfilescan_config.hit_rate_limit * 100);
        }
    } else {
        gfilescan_config.hit_rate_limit = -1;
    }

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_SCANBUF_SIZE, &po);
    if(pv!=NULL) {
        gfilescan_config.scanbuf_size = (unsigned int)atoi(pv);
    } else {
        gfilescan_config.scanbuf_size = DEFAULT_FS_SCANBUF_SIZE;
    }

    /* Thread pool config */
    pv=glcfg_get_param_value(config, THREAD_POOL_CONF_MODULE, THREAD_POOL_CONF_PARAM_POOL_SIZE, &po);
    if(pv!=NULL) {
        gthreadpool_config.pool_size = atoi(pv);
    } else {
        gthreadpool_config.pool_size = DEFAULT_POOL_SIZE;
    }
    pv=glcfg_get_param_value(config, THREAD_POOL_CONF_MODULE, THREAD_POOL_CONF_PARAM_INIT_THREADS, &po);
    if(pv!=NULL) {
        gthreadpool_config.init_threads = atoi(pv);
    } else {
        gthreadpool_config.init_threads = DEFAULT_INIT_THREAD;
    }
    pv=glcfg_get_param_value(config, THREAD_POOL_CONF_MODULE, THREAD_POOL_CONF_PARAM_MAX_TASKS, &po);
    if(pv!=NULL) {
        gthreadpool_config.max_tasks = atoi(pv);
    } else {
        gthreadpool_config.max_tasks = DEFAULT_MAX_TASKS;
    }
    pv=glcfg_get_param_value(config, THREAD_POOL_CONF_MODULE, THREAD_POOL_CONF_PARAM_DETECT_LOAD_PERIOD, &po);
    if(pv!=NULL) {
        gthreadpool_config.detect_load_period = atoi(pv);
    } else {
        gthreadpool_config.detect_load_period = DEFAULT_DETECT_PERIOD;
    }
    pv=glcfg_get_param_value(config, THREAD_POOL_CONF_MODULE, THREAD_POOL_CONF_PARAM_STACK_SIZE, &po);
    if(pv!=NULL) {
        gthreadpool_config.stack_size = atoi(pv);
    } else {
        gthreadpool_config.stack_size = DEFAULT_STACK_SIZE;
    }
    pv=glcfg_get_param_value(config, THREAD_POOL_CONF_MODULE, THREAD_POOL_CONF_PARAM_HIGH_TASK_WATERMARK, &po);
    if(pv!=NULL) {
        gthreadpool_config.high_task_watermark = atoi(pv);
    } else {
        gthreadpool_config.high_task_watermark = DEFAULT_HIGH_TASK_WATERMARK;
    }
    pv=glcfg_get_param_value(config, THREAD_POOL_CONF_MODULE, THREAD_POOL_CONF_PARAM_LOW_TASK_WATERMARK, &po);
    if(pv!=NULL) {
        gthreadpool_config.low_task_watermark = atoi(pv);
    } else {
        gthreadpool_config.low_task_watermark = DEFAULT_LOW_TASK_WATERMARK;
    }
    
leave_load_config:
    glcfg_close(config);
#ifdef DEBUG
    LOGDEBUG("-FSCTL_CONFIG!");
#endif
    return ret;
}

void
fsctl_config_exit(void)
{
    return ;
}

int
fsctl_config_reload()
{
    glcfg_t config = NULL;

    int ret = 0;
    const char *pv=NULL, *po=NULL;

#ifdef DEBUG
    LOGDEBUG("+FSCTL_CONFIG_RELOAD!");
#endif
    if(!var_config_file[0]) {
        LOGERROR("configuration file not set: %s", var_config_file);
        ret = -1;
        goto leave_load_config;
    }

    if(NULL==(config=glcfg_open(var_config_file, GLCFG_MODE_READ))) {
        LOGERROR("Failed to open configuration file: %s", var_config_file);
        ret = -1;
        goto leave_load_config;
    }

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_ENABLE_SCAN, &po);
    if(pv!=NULL) {
        gfilescan_config.enable_scan = atoi(pv);
    } else {
        gfilescan_config.enable_scan = DEFAULT_FS_ENABLE_SCAN;
    }
    LOGDEBUG("++enable_scan = %d", gfilescan_config.enable_scan);
    
    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_USE_FSE_SHA1, &po);
    if(pv!=NULL) {
        gfilescan_config.use_fse_sha1 = atoi(pv);
    } else {
        gfilescan_config.use_fse_sha1 = DEFAULT_FS_USE_FSE_SHA1;
    }
    LOGDEBUG("++use_fse_sha1 = %d", gfilescan_config.use_fse_sha1);
    
    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_FID_LIST_SIZE, &po);
    if(pv!=NULL) {
        gfilescan_config.fid_list_size = atoi(pv);
    } else {
        gfilescan_config.fid_list_size = DEFAULT_FS_FID_LIST_SIZE;
    }
    LOGDEBUG("++fid_list_size = %d", gfilescan_config.fid_list_size);

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_SAVE_SCANNING_FILE, &po);
    if(pv!=NULL) {
        gfilescan_config.save_scanning_file = atoi(pv);
    } else {
        gfilescan_config.save_scanning_file = DEFAULT_FS_SAVE_SCANNING_FILE;
    }
    LOGDEBUG("++save_scanning_file = %d", gfilescan_config.save_scanning_file);

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_CACHE_SIZE, &po);
    if(pv!=NULL) {
        gfilescan_config.cache_size = (unsigned int)atoi(pv);
    } else {
        gfilescan_config.cache_size = DEFAULT_FS_CACHE_SIZE;
    }
    fs_cache_size_write(gfilescan_config.cache_size);
    LOGDEBUG("++cache_size = %d", gfilescan_config.cache_size);

    pv=glcfg_get_param_value(config, FILESCAN_CONF_MODULE, FILESCAN_CONF_PARAM_HIT_RATE_LIMIT, &po);
    if(pv!=NULL) {
        gfilescan_config.hit_rate_limit = atof(pv);

        if(gfilescan_config.hit_rate_limit < 0) {
            gfilescan_config.hit_rate_limit = -1;
        } else if(gfilescan_config.hit_rate_limit > 1) {
            gfilescan_config.hit_rate_limit = 1;
        }
        if(gfilescan_config.hit_rate_limit >= 0 && gfilescan_config.hit_rate_limit < 1) {
            LOGDEBUG("++enabled hit_rate_limit = %2.2f%%", gfilescan_config.hit_rate_limit * 100);
        } else {
            LOGDEBUG("++disabled hit_rate_limit");
        }
    } else {
        gfilescan_config.hit_rate_limit = -1;
        LOGDEBUG("++disabled hit_rate_limit");
    }
    
leave_load_config:
    glcfg_close(config);

    if(ret == 0) {
	    fs_cache_purge(0);
    }
#ifdef DEBUG
    LOGDEBUG("-FSCTL_CONFIG_RELOAD!");
#endif
    return ret;
}
