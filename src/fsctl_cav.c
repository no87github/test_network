#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include "list.h"
#include "fs.h"
#include "fsctl_common.h"

int fid_list_size_read(int32_t *val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++FID_LIST_SIZE_READ++");
#endif
    if (val == NULL)
    {
        LOGERROR("filescan.fid_list_size_read:val == NULL");
        ret = EPERM;
    }
    else /* val != NULL */
    {
        *val = gfilescan_config.fid_list_size;
        LOGINFO("filescan.fid_list_size_read:%d", *val);
    }
#ifdef DEBUG
    LOGDEBUG("--FID_LIST_SIZE_READ--");
#endif
    return ret;
}

int fid_list_size_write(int32_t val)
{
    int ret = 0;
#ifdef DEBUG
    LOGDEBUG("++FID_LIST_SIZE_WRITE++");
#endif
    if ( 0 > val || 65536 < val ) {
        LOGERROR("filescan.fid_list_size: failed, val:%d", val);
        ret = EPERM;
    }
    else {
        gfilescan_config.fid_list_size = val;
        LOGINFO("filescan.fid_list_size_write:%d", gfilescan_config.fid_list_size);
    }
#ifdef DEBUG
    LOGDEBUG("--FID_LIST_SIZE_WRITE--");
#endif
    return ret;
}

