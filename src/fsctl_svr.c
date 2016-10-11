#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>

#include "list.h"
#include "fs.h"
#include "fsctl.h"
#include "tmdebug.h"
#include "sk_io.h"
#include "fsctl_common.h"

#define OUTBUF_MAX  (4096)

/****************************************************************************/
/* STATIC GLOBAL VARIABLES                                                  */
/****************************************************************************/

static struct mp_entry_ops g_entry_ops[] = {
    { /* filescan.log_level*/
      .name = "filescan.log_level",
      .read_type = MP_ENTRY_TYPE_INT32, .read_func = log_level_read,
      .write_type = MP_ENTRY_TYPE_INT32, .write_func = log_level_write,
      .exec_type = MP_ENTRY_TYPE_INT32, .exec_func = log_level_reload,
    },
    { /* filescan.enable_scan */
      .name = "filescan.enable_scan",
      .read_type = MP_ENTRY_TYPE_INT32, .read_func = enable_scan_read,
      .write_type = MP_ENTRY_TYPE_INT32, .write_func = enable_scan_write,
    },
    { /* filescan.use_fse_sha1 */
      .name = "filescan.use_fse_sha1",
      .read_type = MP_ENTRY_TYPE_STRING, .read_func = use_fse_sha1_read,
      .write_type = MP_ENTRY_TYPE_INT32, .write_func = use_fse_sha1_write,
    },
    { /* filescan.hit_rate_limit */
      .name = "filescan.hit_rate_limit",
      .read_type = MP_ENTRY_TYPE_STRING, .read_func = hit_rate_limit_read,
      .write_type = MP_ENTRY_TYPE_STRING, .write_func = hit_rate_limit_write,
    },
    { /* filescan.fid_list_size*/
      .name = "filescan.fid_list_size",
      .read_type = MP_ENTRY_TYPE_INT32, .read_func = fid_list_size_read,
      .write_type = MP_ENTRY_TYPE_INT32, .write_func = fid_list_size_write,
    },
    { /* filescan.save_scanning_file */
      .name = "filescan.save_scanning_file",
      .read_type = MP_ENTRY_TYPE_INT32, .read_func = save_scanning_file_read,
      .write_type = MP_ENTRY_TYPE_INT32, .write_func = save_scanning_file_write,
    },
    { /* filescan.reload_config*/
      .name = "filescan.reload_config",
      .exec_type = MP_ENTRY_TYPE_RAW, .exec_func = fsctl_config_reload,
    },
    { /* vscan.reload_pattern */
      .name = "vscan.reload_pattern",
      .exec_type = MP_ENTRY_TYPE_RAW, .exec_func = reload_pattern,
    },
    { /* reload_engine */
      .name = "vscan.reload_engine",
      .exec_type = MP_ENTRY_TYPE_STRING, .exec_func = reload_engine,
    },
    { /* vscan.version */
      .name = "vscan.version",
      .read_type = MP_ENTRY_TYPE_STRING, .read_func = report_version,
    },
    { /* vscan.reload_config */
        .name = "vscan.reload_config",
        .exec_type = MP_ENTRY_TYPE_RAW, .exec_func = reload_config,
    },
    { /* fs_cache.stats */
      .name = "fs_cache.stats",
      .read_type = MP_ENTRY_TYPE_STRING, .read_func = fs_cache_dump,
    },
    { /* fs_cache.purge */
      .name = "fs_cache.purge",
      .exec_type = MP_ENTRY_TYPE_INT32, .exec_func = fs_cache_purge,
    },
    { /* fs_cache.size */
      .name = "fs_cache.size",
      .write_type = MP_ENTRY_TYPE_UINT32, .write_func = fs_cache_size_write,
    },
    { .name = NULL },
};

/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/

struct fsctl_server
{
    int fd;

    enum_fsctl_cmd method;

    enum_fsctl_content_type content_type;

    long int content_length;

    enum
    {
        fs_server_state_request_line,
        fs_server_state_request_header,
        fs_server_state_request_body,
    } state;

    char mib[FSCTL_MAX_MIB];
    size_t miblen;

    char req_buf[FSCTL_MAX_BUF];
    size_t req_buflen;

    char rsp_buf[FSCTL_MAX_BUF];
    size_t rsp_buflen;
};

/****************************************************************************/
/* FUNCTION DECLARATIONS                                                    */
/****************************************************************************/

static const char *fs_server_get_content_type(unsigned int content_type);
static int fs_server_dispatch(struct fsctl_server *fs_server);
static int fs_server_read(struct fsctl_server *fs_server, struct mp_entry_ops *entry);
static int fs_server_write(struct fsctl_server *fs_server, struct mp_entry_ops *entry);
static int fs_server_exec(struct fsctl_server *fs_server, struct mp_entry_ops *entry);

/****************************************************************************/
/* FUNCTION DEFINITIONS                                                     */
/****************************************************************************/

static const char *
fs_server_get_content_type(
    unsigned int content_type)
{
    if (content_type == FSCTL_CONTENT_TYPE_RAW)
        return T_RAW;
    else if (content_type == FSCTL_CONTENT_TYPE_STRING)
        return T_STRING;
    else if (content_type == FSCTL_CONTENT_TYPE_INT8)
        return T_INT8;
    else if (content_type == FSCTL_CONTENT_TYPE_UINT8)
        return T_UINT8;
    else if (content_type == FSCTL_CONTENT_TYPE_INT16)
        return T_INT16;
    else if (content_type == FSCTL_CONTENT_TYPE_UINT16)
        return T_UINT16;
    else if (content_type == FSCTL_CONTENT_TYPE_INT32)
        return T_INT32;
    else if (content_type == FSCTL_CONTENT_TYPE_UINT32)
        return T_UINT32;
    else if (content_type == FSCTL_CONTENT_TYPE_INT64)
        return T_INT64;
    else if (content_type == FSCTL_CONTENT_TYPE_UINT64)
        return T_UINT64;

    return T_NONE;
}

static int
fs_server_dispatch(
    struct fsctl_server *fs_server)
{
    int ret = -1;
    char outbuf[4096];
    struct mp_entry_ops *entry = NULL;
LOGDEBUG("++ fs_server_dispatch ++"); //XXX
    if (fs_server == NULL)
    {
        errno = EINVAL;
        LOGERROR("fs_server=%p: %m", fs_server);
        goto leave;
    }

    if ((strcasecmp("all", fs_server->mib) == 0) && (fs_server->method == FSCTL_CMD_READ))
    {
//        snprintf(outbuf, sizeof(outbuf), FSCTL_RESPONSE_CLOSE);
        (void)sk_io_write(fs_server->fd, FSCTL_RESPONSE_CLOSE, strlen(FSCTL_RESPONSE_CLOSE));
        entry = g_entry_ops;
        while(entry->name)
        {
            snprintf(outbuf, sizeof(outbuf), "%c%c%c  %s: (r=%s, w=%s, x=%s)\n",
                     entry->read_type ? 'r' : '-',
                     entry->write_type ? 'w' : '-',
                     entry->exec_type ? 'x' : '-',
                     entry->name,
                     fs_server_get_content_type(entry->read_type),
                     fs_server_get_content_type(entry->write_type),
                     fs_server_get_content_type(entry->exec_type));
            (void)sk_io_write(fs_server->fd, outbuf, strlen(outbuf));
//            LOGDEBUG("%s", outbuf);
            ++entry;
        }

        ret = 0;
        goto leave;
    }

    if ((entry = mp_find_entry(g_entry_ops, fs_server->mib)) == NULL)
    {
        LOGERROR("mp_find_entry(): mib=\"%s\"", fs_server->mib);
        (void)sk_io_write(fs_server->fd, FSCTL_RESPONSE_NOT_FOUND, strlen(FSCTL_RESPONSE_NOT_FOUND));
        ret = 0;
        goto leave;
    }

    if (fs_server->method == FSCTL_CMD_READ)
    {
        if (fs_server_read(fs_server, entry) != 0)
        {
            LOGERROR("fs_server_read(): entry=%p", entry);
            goto leave;
        }
    }
    else if (fs_server->method == FSCTL_CMD_WRITE)
    {
        if (fs_server_write(fs_server, entry) != 0)
        {
            LOGERROR("fs_server_write(): entry=%p", entry);
            goto leave;
        }
    }
    else if (fs_server->method == FSCTL_CMD_EXEC)
    {
        if (fs_server_exec(fs_server, entry) != 0)
        {
            LOGERROR("fs_server_exec(): entry=%p", entry);
            goto leave;
        }
    }
    else
    {
        LOGERROR("Invalid method (%d)", fs_server->method);
        goto leave;
    }

    ret = 0;

leave:

    if (ret != 0 
    		&& fs_server)/* fix klokwork issue 1161 */
    {
        (void)sk_io_write(fs_server->fd, FSCTL_RESPONSE_INTERNAL_ERROR, strlen(FSCTL_RESPONSE_INTERNAL_ERROR));
    }
    return ret;
LOGDEBUG("-- fs_server_dispatch --");
}


static int
fs_server_read(
    struct fsctl_server *fs_server,
    struct mp_entry_ops *entry)
{
    int ret = -1;
    char outbuf[OUTBUF_MAX];
    long int ret_val = -1;
    char *buf = (fs_server != NULL) ? fs_server->rsp_buf : NULL;
    size_t count = FSCTL_MAX_BUF;

    LOGDEBUG("Enter %s(): fs_server=%p, entry=%p, buf=%p",
                 __FUNCTION__, fs_server, entry, buf);

    if ((fs_server == NULL) || (entry == NULL) || (buf == NULL) || (entry->read_type == MP_ENTRY_TYPE_NONE) || (entry->read_func == NULL))
    {
        errno = EINVAL;
        LOGERROR("fs_server=%p, entry=%p, buf=%p, entry->read_type=%d, entry->read_func=%p: %m",
                     fs_server, entry, buf, entry->read_type, entry->read_func);
        goto leave;
    }

    if (entry->read_type == MP_ENTRY_TYPE_RAW)
    {
        mp_entry_read_raw_t read_raw = entry->read_func;

        if ((ret_val = read_raw(buf, count)) > 0)
            count = MIN((size_t)ret_val, count);
        else
            count = 0;

        count = MIN(count, fs_server->content_length);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_STRING)
    {
        mp_entry_read_string_t read_string = entry->read_func;

        if ((ret_val = read_string(buf, count)) > 0)
            count = MIN((size_t)ret_val, count);
        else
            count = 0;

        count = MIN(count, fs_server->content_length);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_INT8)
    {
        int8_t val;
        mp_entry_read_int8_t read_int8 = entry->read_func;

        ret_val = read_int8(&val);
        snprintf(buf, count, "%d", val);
        count = strlen(buf);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_UINT8)
    {
        uint8_t val;
        mp_entry_read_uint8_t read_uint8 = entry->read_func;

        ret_val = read_uint8(&val);
        snprintf(buf, count, "%u", val);
        count = strlen(buf);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_INT16)
    {
        int16_t val;
        mp_entry_read_int16_t read_int16 = entry->read_func;

        ret_val = read_int16(&val);
        snprintf(buf, count, "%d", val);
        count = strlen(buf);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_UINT16)
    {
        uint16_t val;
        mp_entry_read_uint16_t read_uint16 = entry->read_func;

        ret_val = read_uint16(&val);
        snprintf(buf, count, "%u", val);
        count = strlen(buf);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_INT32)
    {
        int32_t val;
        mp_entry_read_int32_t read_int32 = entry->read_func;

        ret_val = read_int32(&val);
        snprintf(buf, count, "%d", val);
        count = strlen(buf);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_UINT32)
    {
        uint32_t val;
        mp_entry_read_uint32_t read_uint32 = entry->read_func;

        ret_val = read_uint32(&val);
        snprintf(buf, count, "%u", val);
        count = strlen(buf);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_INT64)
    {
        int64_t val;
        mp_entry_read_int64_t read_int64 = entry->read_func;

        ret_val = read_int64(&val);
        snprintf(buf, count, "%lld", val);
        count = strlen(buf);
    }
    else if (entry->read_type == MP_ENTRY_TYPE_UINT64)
    {
        uint64_t val;
        mp_entry_read_uint64_t read_uint64 = entry->read_func;

        ret_val = read_uint64(&val);
        snprintf(buf, count, "%llu", val);
        count = strlen(buf);
    }
    else
    {
        LOGERROR("Invalid type: entry=%p, type=%d", entry, entry->read_type);
        goto leave;
    }

    snprintf(outbuf, sizeof(outbuf), FSCTL_RESPONSE_CONTENT,
             fs_server_get_content_type(entry->read_type),
             count,
             ret_val);

    (void)sk_io_write(fs_server->fd, outbuf, strlen(outbuf));
    (void)sk_io_write(fs_server->fd, buf, count);

    ret = 0;

leave:
    LOGDEBUG("Leave %s(): ret=%d", __FUNCTION__, ret);
    return ret;
}

static int
fs_server_write(
    struct fsctl_server *fs_server,
    struct mp_entry_ops *entry)
{
    int ret = -1;
    char outbuf[OUTBUF_MAX];
    long int ret_val = -1;
    char * endptr = NULL;
    const char *buf = (fs_server != NULL) ? fs_server->req_buf : NULL;
    size_t count = (fs_server != NULL) ? fs_server->req_buflen : 0;

    LOGDEBUG("Enter %s(): fs_server=%p, entry=%p, buf=%p",
                 __FUNCTION__, fs_server, entry, buf);

    if ((fs_server == NULL) || (entry == NULL) || (buf == NULL) || (entry->write_type == MP_ENTRY_TYPE_NONE) || (entry->write_func == NULL))
    {
        errno = EINVAL;
        LOGERROR("fs_server=%p, entry=%p, buf=%p, entry->write_type=%d, entry->write_func=%p: %m",
                     fs_server, entry, buf, entry->write_type, entry->write_func);
        goto leave;
    }

    if (entry->write_type == MP_ENTRY_TYPE_RAW)
    {
        mp_entry_write_raw_t write_raw = entry->write_func;

        ret_val = write_raw(buf, count);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_STRING)
    {
        mp_entry_write_string_t write_string = entry->write_func;

        ret_val = write_string(buf, count);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_INT8)
    {
        long int val = 0;
        mp_entry_write_int8_t write_int8 = entry->write_func;
        val = strtol(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_int8((int8_t)val);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_UINT8)
    {
        unsigned long int val = 0;
        mp_entry_write_uint8_t write_uint8 = entry->write_func;
        val = strtoul(buf, &endptr, 10);
        if ((((val == ULONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_uint8((uint8_t)val);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_INT16)
    {
        long int val = 0;
        mp_entry_write_int16_t write_int16 = entry->write_func;
        val = strtol(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_int16((int16_t)val);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_UINT16)
    {
        unsigned long int val = 0;
        mp_entry_write_uint16_t write_uint16 = entry->write_func;
        val = strtoul(buf, &endptr, 10);
        if ((((val == ULONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_uint16((uint16_t)val);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_INT32)
    {
        long int val = 0;
        mp_entry_write_int32_t write_int32 = entry->write_func;
        val = strtol(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_int32((int32_t)val);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_UINT32)
    {
        unsigned long int val = 0;
        mp_entry_write_uint32_t write_uint32 = entry->write_func;
        val = strtoul(buf, &endptr, 10);
        if (((val == ULONG_MAX) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_uint32((uint32_t)val);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_INT64)
    {
        long long int val = 0;
        mp_entry_write_int64_t write_int64 = entry->write_func;
        val = strtoll(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_int64((int64_t)val);
    }
    else if (entry->write_type == MP_ENTRY_TYPE_UINT64)
    {
        unsigned long long int val = 0;
        mp_entry_write_uint64_t write_uint64 = entry->write_func;
        val = strtoull(buf, &endptr, 10);
        if ((((val == ULONG_MAX)) && (errno == ERANGE)) || (endptr == buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = write_uint64((uint64_t)val);
    }
    else
    {
        LOGERROR("Invalid type: entry=%p, type=%d", entry, entry->write_type);
        goto leave;
    }

    snprintf(outbuf, sizeof(outbuf), FSCTL_RESPONSE_SIMPLE, ret_val);
    (void)sk_io_write(fs_server->fd, outbuf, strlen(outbuf));

    ret = 0;

leave:
    LOGDEBUG("Leave %s(): ret=%d", __FUNCTION__, ret);
    return ret;
}

static int
fs_server_exec(
    struct fsctl_server *fs_server,
    struct mp_entry_ops *entry)
{
    int ret = -1;
    char outbuf[OUTBUF_MAX];
    long int ret_val = -1;
    char * endptr = NULL;
    const char *buf = (fs_server != NULL) ? fs_server->req_buf : NULL;
    size_t count = (fs_server != NULL) ? fs_server->req_buflen : 0;

    LOGDEBUG("Enter %s(): fs_server=%p, entry=%p, buf=%p",
                 __FUNCTION__, fs_server, entry, buf);

    if ((fs_server == NULL) || (entry == NULL) || (buf == NULL) || (entry->exec_type == MP_ENTRY_TYPE_NONE) || (entry->exec_func == NULL))
    {
        errno = EINVAL;
        LOGERROR("fs_server=%p, entry=%p, buf=%p, entry->exec_type=%d, entry->exec_func=%p: %m",
                     fs_server, entry, buf, entry->exec_type, entry->exec_func);
        goto leave;
    }

    if (entry->exec_type == MP_ENTRY_TYPE_RAW)
    {
        mp_entry_exec_raw_t exec_raw = entry->exec_func;

        ret_val = exec_raw(buf, count);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_STRING)
    {
        mp_entry_exec_string_t exec_string = entry->exec_func;

        ret_val = exec_string(buf, count);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_INT8)
    {
        long int val = 0;
        mp_entry_exec_int8_t exec_int8 = entry->exec_func;
        val = strtol(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_int8((int8_t)val);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_UINT8)
    {
        unsigned long int val = 0;
        mp_entry_exec_uint8_t exec_uint8 = entry->exec_func;
        val = strtoul(buf, &endptr, 10);
        if ((((val == ULONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_uint8((uint8_t)val);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_INT16)
    {
        long int val = 0;
        mp_entry_exec_int16_t exec_int16 = entry->exec_func;
        val = strtol(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_int16((int16_t)val);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_UINT16)
    {
        unsigned long int val = 0;
        mp_entry_exec_uint16_t exec_uint16 = entry->exec_func;
        val = strtoul(buf, &endptr, 10);
        if ((((val == ULONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_uint16((uint16_t)val);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_INT32)
    {
        long int val = 0;
        mp_entry_exec_int32_t exec_int32 = entry->exec_func;
        val = strtol(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_int32((int32_t)val);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_UINT32)
    {
        unsigned long int val = 0;
        mp_entry_exec_uint32_t exec_uint32 = entry->exec_func;
        val = strtoul(buf, &endptr, 10);
        if ((((val == ULONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_uint32((uint32_t)val);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_INT64)
    {
        long long int val = 0;
        mp_entry_exec_int64_t exec_int64 = entry->exec_func;
        val = strtoll(buf, &endptr, 10);
        if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (endptr == buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_int64((int64_t)val);
    }
    else if (entry->exec_type == MP_ENTRY_TYPE_UINT64)
    {
        unsigned long long int val = 0;
        mp_entry_exec_uint64_t exec_uint64 = entry->exec_func;
        val = strtoull(buf, &endptr, 10);
        if ((((val == ULONG_MAX)) && (errno == ERANGE)) || (endptr == buf))
        {
            errno = EINVAL;
            goto leave;
        }

        ret_val = exec_uint64((uint64_t)val);
    }
    else
    {
        LOGERROR("Invalid type: entry=%p, type=%d", entry, entry->exec_type);
        goto leave;
    }

    snprintf(outbuf, sizeof(outbuf), FSCTL_RESPONSE_SIMPLE, ret_val);
    (void)sk_io_write(fs_server->fd, outbuf, strlen(outbuf));

    ret = 0;

leave:
    LOGDEBUG("Leave %s(): ret=%d", __FUNCTION__, ret);
    return ret;
}

int
fsctl_svr(
    int fd)
{
    ssize_t ret = 0;
    int req_for_len = 0;
    int less = 0;
    static char buf[OUTBUF_MAX] = {0};
    struct fsctl_server fctlserver = {0};
    struct fsctl_server * fs_server = &fctlserver;
    char * pbuf = buf;
    char * ebuf = buf;
    int done = 0;
    fs_server->state = fs_server_state_request_line;
    fs_server->fd = fd;
 
    while (!done)
    {
        char *p, *e, *q;
        int need_more_data = 0;
        /* update conn->pbuf and conn->ebuf */
        if (pbuf == ebuf)
        {
            /* reset pointer "conn->pbuf" and "conn->ebuf" to front of buffer */
            pbuf = ebuf = buf;
        }
        else if (pbuf > buf)
        {
            size_t n = ebuf - pbuf;

            assert(OUTBUF_MAX >= n);

            (void)memmove(buf, pbuf, n);

            pbuf = buf;
            ebuf = buf + n;
        }
read_more:
        ret = read(fd, ebuf, OUTBUF_MAX - (ebuf - pbuf));
        if (0 > ret)
        {
            if (EINTR != errno && EAGAIN != errno)
                break;
            else {
                LOGDEBUG("EINTR or EAGAIN, read more");
                goto read_more;
            }
        }
        else if (0 == ret)
        {
            if ((pbuf != NULL) && (ebuf != NULL) && (ebuf - pbuf > 0)) {
                LOGDEBUG("sock closed, try to flush buffer");
                done = 1;
                p = pbuf;
                q = ebuf;
            }
            else {
                LOGDEBUG("socke closed, and buffer is empty, p:%p, e:%p", pbuf, ebuf);
                break;
            }
            
        }
        else
        {
            ebuf += ret;
        }
        while (pbuf < ebuf && !need_more_data) {
            LOGDEBUG("while!!");
            if (0 < less)
                pbuf += less;
            less = 0;
            p = pbuf;
            e = ebuf;
            q = NULL;
            if (0 == req_for_len) {
                if (NULL == (q = memchr(pbuf, '\n', ebuf - pbuf)))
                {
                    if (OUTBUF_MAX == ebuf - pbuf) {
                        LOGINFO("Buffer fulled, close fsctl socket");
                        return ret;
                    }
                    else { 
                        LOGDEBUG("LF Not found, read more!!!");
                        need_more_data = 1;
                        break;
                    }
                }
                else {
                    p = pbuf;
                    less = q - p + 1;
                    e = p + less;
                    LOGDEBUG("Found LF, p:%p, e:%p, q:%p, less:%d", p, e, q, less);
                }
            }

            if (p == NULL || e == NULL || e - p == 0)
                break;

            switch (fs_server->state)
            {
                case fs_server_state_request_line:
                    {
                        char *lp, *le; /* request line */
                        char *mp, *me; /* method */
                        char *sp, *se; /* MIB string */
                        char *vp, *ve; /* MP version */
                        /* Initialization */
                        fs_server->method = FSCTL_CMD_NONE;
                        fs_server->content_type = FSCTL_CONTENT_TYPE_NONE;
                        fs_server->content_length = 0;
                        fs_server->mib[0] = '\0';
                        fs_server->miblen = 0;
                        fs_server->req_buf[0] = '\0';
                        fs_server->req_buflen = 0;
                        fs_server->rsp_buf[0] = '\0';
                        fs_server->rsp_buflen = 0;

                        /* strip CRLF */
                        lp = p;
                        le = e;
                        if (le > lp && *(le - 1) == '\n' && --le > lp && *(le - 1) == '\r')
                            --le;

                        if (le - lp == 0)
                            break;

                        /* parse http request line */
                        mp = lp;
                        while (lp < le && *lp != ' ')
                            lp++;
                        me = lp;

                        while (lp < le && *lp == ' ')
                            lp++;
                        sp = lp;
                        while (lp < le && *lp != ' ')
                            lp++;
                        se = lp;

                        while (lp < le && *lp == ' ')
                            lp++;
                        vp = lp;
                        while (lp < le && *lp != ' ')
                            lp++;
                        ve = lp;

                        LOGDEBUG("REQ:[%.*s]:[%.*s]:[%.*s]\n",
                                (int)(me - mp), mp,
                                (int)(se - sp), sp,
                                (int)(ve - vp), vp);

                        if ((me - mp == 4) && (strncasecmp(mp, T_READ, strlen(T_READ)) == 0))
                        {
                            fs_server->method = FSCTL_CMD_READ;
                        }
                        else if ((me - mp == 5) && (strncasecmp(mp, T_WRITE, strlen(T_WRITE)) == 0))
                        {
                            fs_server->method = FSCTL_CMD_WRITE;
                        }
                        else if ((me - mp == 4) && (strncasecmp(mp, T_EXEC, strlen(T_EXEC)) == 0))
                        {
                            fs_server->method = FSCTL_CMD_EXEC;
                        }
                        else
                        {
                            fs_server->method = FSCTL_CMD_NONE;
                            ret = -1;
                            goto leave;
                        }

                        /* MIB */
                        fs_server->miblen = (se - sp) < (int)(sizeof(fs_server->mib) - 1) ? (se - sp) : (int)(sizeof(fs_server->mib) - 1);
                        (void)memcpy(fs_server->mib, sp, fs_server->miblen);
                        fs_server->mib[fs_server->miblen] = '\0';

                        LOGDEBUG("MIB=%.*s\n", (int)(fs_server->miblen), fs_server->mib);

                        fs_server->state = fs_server_state_request_header;
                    }
                    break;

                case fs_server_state_request_header:
                    {
                        char *lp, *le; /* request header line */
                        char *fp, *fe; /* field */
                        char *vp, *ve; /* value */

                        /* strip CRLF */
                        lp = p;
                        le = e;
                        if (le > lp && *(le - 1) == '\n' && --le > lp && *(le - 1) == '\r')
                            --le;

                        if (le > lp)
                        {
                            /* field */
                            while (lp < le && *lp == ' ')
                                lp++;
                            fp = lp;
                            while (lp < le && *lp != ' ' && *lp != ':')
                                lp++;
                            fe = lp;

                            /* value */
                            while (lp < le && *lp == ' ')
                                lp++;
                            if (lp < le && *lp == ':')
                                lp++;
                            while (lp < le && *lp == ' ')
                                lp++;
                            vp = lp;
                            ve = le;

                            if (strncasecmp(T_CONTENT_TYPE, fp, fe - fp) == 0)
                            {
                                if (strncasecmp(T_RAW, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_RAW;
                                    LOGDEBUG("Content-Type: %s", T_RAW);
                                }
                                else if (strncasecmp(T_STRING, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_STRING;
                                    LOGDEBUG("Content-Type: %s", T_STRING);
                                }
                                else if (strncasecmp(T_INT8, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_INT8;
                                    LOGDEBUG("Content-Type: %s", T_INT8);
                                }
                                else if (strncasecmp(T_UINT8, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_UINT8;
                                    LOGDEBUG("Content-Type: %s", T_UINT8);
                                }
                                else if (strncasecmp(T_INT16, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_INT16;
                                    LOGDEBUG("Content-Type: %s", T_INT16);
                                }
                                else if (strncasecmp(T_UINT16, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_UINT16;
                                    LOGDEBUG("Content-Type: %s", T_UINT16);
                                }
                                else if (strncasecmp(T_INT32, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_INT32;
                                    LOGDEBUG("Content-Type: %s", T_INT32);
                                }
                                else if (strncasecmp(T_UINT32, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_UINT32;
                                    LOGDEBUG("Content-Type: %s", T_UINT32);
                                }
                                else if (strncasecmp(T_INT64, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_INT64;
                                    LOGDEBUG("Content-Type: %s", T_INT64);
                                }
                                else if (strncasecmp(T_UINT64, vp, ve - vp) == 0)
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_UINT64;
                                    LOGDEBUG("Content-Type: %s", T_UINT64);
                                }
                                else
                                {
                                    fs_server->content_type = FSCTL_CONTENT_TYPE_NONE;
                                    LOGDEBUG("Content-Type: %s", T_NONE);
                                }
                            }
                            else if (strncasecmp(T_CONTENT_LENGTH, fp, fe - fp) == 0)
                            {
                                char * endptr = NULL;
                                fs_server->content_length = 0;
                                fs_server->content_length = strtoul(vp, &endptr, 10);
                                if ((((fs_server->content_length == ULONG_MAX)) && (errno == ERANGE)) || (endptr == (char *)vp))
                                {
                                    ret = EINVAL;
                                    LOGERROR("Content-Length invalid: %m");
                                }
                                LOGDEBUG("Content-Length: %ld", fs_server->content_length);
                            }

                            LOGDEBUG("HDR:[%.*s]:[%.*s]",
                                    (int)(fe - fp), fp,
                                    (int)(ve - vp), vp);
                            break;
                        }
                        else
                        { /* end of header line */
                            LOGDEBUG("HDR:END\n");

                            if (fs_server->content_length > FSCTL_MAX_BUF)
                            {
                                /* TODO */
                                sk_io_timedwrite(fd, 
                                        FSCTL_RESPONSE_DATA_TOO_LONG, 
                                        strlen(FSCTL_RESPONSE_DATA_TOO_LONG), 
                                        2, 
                                        NULL, 
                                        NULL);
                                ret = -1; goto leave;
                            }

                            if (((fs_server->method == FSCTL_CMD_WRITE) || (fs_server->method == FSCTL_CMD_EXEC)) && 
                                    (fs_server->content_length > 0))
                            {
                                fs_server->state = fs_server_state_request_body;
                                req_for_len = 1;
                                break; // break out of select, to read content lengh of data from fd 
                            }
                            else
                            {
                                fs_server->state = fs_server_state_request_line;
                                (void)fs_server_dispatch(fs_server); // XXX XXX XXX XXX
                                ret = 0; goto leave;
                            }
                        }
                    }
                    break;

                case fs_server_state_request_body:
                    {
                        LOGDEBUG("select case: fs_server_state_request_body, break to read content length");
                        break;

                    }
                    break;

                default:
                    {
                        LOGERROR("_request_handler: unknown state: %d", fs_server->state);
                        goto leave;
                    }
            } /* select(fs_server->state) */

            if (fs_server_state_request_body == fs_server->state) 
            {
                size_t read_len = 0;
                if (fs_server->content_length < 0)
                {
                    LOGERROR("Invalid content_length");
                    ret = -1; goto leave; /* break out of while */
                }

                p += less;
                if (p < ebuf) {
                    fs_server->req_buflen = ebuf - p;
                    (void)memcpy(fs_server->req_buf, p, fs_server->req_buflen);
                    p = fs_server->req_buf + fs_server->req_buflen;
                }
                else {
                    p = fs_server->req_buf;
                    fs_server->req_buflen = 0;
                }
                    
                fs_server->content_length -= fs_server->req_buflen;
                LOGDEBUG("contentLen:%ld, req_buflen:%zd, p:%p", fs_server->content_length, fs_server->req_buflen, p); // XXX XXX 
                if ((fs_server->req_buflen + fs_server->content_length) > sizeof(fs_server->req_buf))
                {
                    LOGERROR("Exceeds the buffer size limit: %zu, content len: %ld", sizeof(fs_server->req_buf), fs_server->content_length);
                    ret = -1; goto leave; /* break out of while */
                }
                read_len = fs_server->content_length;
                if ( 0 < read_len && 
                     (0 > (ret = sk_io_readn(fd, p, (size_t *)&(read_len))) ||
                      0 != read_len ))
                {
                    LOGERROR("Error read from fctl: %zd, left length: %ld, %m", ret, fs_server->content_length);
                    goto leave; /* break out of while */
                }
                fs_server->req_buflen += fs_server->content_length;
                fs_server->req_buf[fs_server->req_buflen] = 0;
                LOGDEBUG("DONE, buf:%p, buflen:%zd", fs_server->req_buf, fs_server->req_buflen);
                (void)fs_server_dispatch(fs_server); // XXX XXX XXX XXX
                goto leave; /* break out of while */
            }
        }
    }

leave:

    return ret;
}
