#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "fsctl.h"
#include "fs_limits.h"

static const char * var_server_host = FSCTL_SVR_ADDR;
static const unsigned short var_server_port = FSCTL_SVR_PORT;

/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/

struct fsctl_message {
    enum_fsctl_cmd cmd;

    char name[FS_NAME_MAX];

    enum_fsctl_content_type content_type;

    union {
        void *raw;
        char *string;
        int32_t int32;
        uint32_t uint32;
    } content_data;

    unsigned long int content_length;

    int connection_close;

    long int ret;
};

/****************************************************************************/
/* FUNCTION DECLARATIONS                                                    */
/****************************************************************************/

static FILE *fsctl_connect(const char *host, unsigned short port);
static int fsctl_sendmsg(FILE *fp, struct fsctl_message *msg);
static int fsctl_recvmsg(FILE *fp, struct fsctl_message *msg);
static void fsctl_close(FILE *fp);

/****************************************************************************/
/* FUNCTION DEFINITIONS                                                     */
/****************************************************************************/

ssize_t
fsctl_read_raw(
    const char *name,
    void *buf,
    size_t count)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_READ;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_RAW;
        msg.content_data.raw = NULL;
        msg.content_length = count;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_READ;
        msg.content_data.raw = buf;
        msg.content_length = count;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

ssize_t
fsctl_read_string(
    const char *name,
    char *str,
    size_t count)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_READ;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_STRING;
        msg.content_data.string = NULL;
        msg.content_length = count;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }
    
    { /* recvmsg */
        msg.cmd = FSCTL_CMD_READ;
        msg.content_data.string = str;
        msg.content_length = count;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_read_int32(
    const char *name,
    int32_t *val)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_READ;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_INT32;
        msg.content_data.int32 = 0;
        msg.content_length = 0;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_READ;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }

        if (val != NULL)
            *val = msg.content_data.int32;
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_read_uint32(
    const char *name,
    uint32_t *val)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_READ;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_UINT32;
        msg.content_data.uint32 = 0;
        msg.content_length = 0;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_READ;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }

        if (val != NULL)
            *val = msg.content_data.uint32;
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

ssize_t
fsctl_write_raw(
    const char *name,
    const void *buf,
    size_t count)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_WRITE;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_RAW;
        msg.content_data.raw = (void *)buf;
        msg.content_length = count;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_WRITE;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

ssize_t
fsctl_write_string(
    const char *name,
    const char *str,
    size_t count)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_WRITE;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_STRING;
        msg.content_data.string = (char *)str;
        msg.content_length = count;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_WRITE;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_write_int32(
    const char *name,
    int32_t val)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_WRITE;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_INT32;
        msg.content_data.int32 = val;
        msg.content_length = 0;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_WRITE;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_write_uint32(
    const char *name,
    uint32_t val)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_WRITE;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_UINT32;
        msg.content_data.uint32 = val;
        msg.content_length = 0;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_WRITE;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_exec_raw(
    const char *name,
    const void *buf,
    size_t count)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_EXEC;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_RAW;
        msg.content_data.raw = (void *)buf;
        msg.content_length = count;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_EXEC;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_exec_string(
    const char *name,
    const char *str,
    size_t count)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_EXEC;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_STRING;
        msg.content_data.string = (char *)str;
        msg.content_length = count;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_EXEC;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_exec_int32(
    const char *name,
    int32_t val)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_EXEC;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_INT32;
        msg.content_data.int32 = val;
        msg.content_length = 0;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_EXEC;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

int
fsctl_exec_uint32(
    const char *name,
    uint32_t val)
{
    int ret = -1;
    FILE *fp = NULL;
    struct fsctl_message msg = {0};

    if ((name == NULL) || (*name == '\0'))
        goto leave;

    if ((fp = fsctl_connect(var_server_host, var_server_port)) == NULL)
        goto leave;

    (void)memset(&msg, 0, sizeof(msg));

    { /* sendmsg */
        msg.cmd = FSCTL_CMD_EXEC;
        (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
        msg.content_type = FSCTL_CONTENT_TYPE_UINT32;
        msg.content_data.uint32 = val;
        msg.content_length = 0;
        msg.connection_close = 0;
        msg.ret = 0;

        if (fsctl_sendmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_sendmsg() failed\n");
            goto leave;
        }
    }

    { /* recvmsg */
        msg.cmd = FSCTL_CMD_EXEC;

        if (fsctl_recvmsg(fp, &msg) < 0)
        {
            fprintf(stderr, "fsctl_recvmsg() failed\n");
            goto leave;
        }
    }

    ret = msg.ret;

leave:
    if (fp != NULL)
    {
        fsctl_close(fp);
        fp = NULL;
    }

    return ret;
}

static FILE *
fsctl_connect(
    const char *host,
    unsigned short port)
{
    int sock = -1;
    FILE *fp = NULL;
    struct sockaddr_in addr;
    socklen_t addrlen;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        fprintf(stderr, "socket(): %m\n");
        return NULL;
    }

    (void)memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);
    addrlen = sizeof(addr);

    if (connect(sock, (struct sockaddr *)&addr, addrlen) < 0)
    {
        fprintf(stderr, "connect(): %m\n");
        return NULL;
    }

    if ((fp = fdopen(sock, "w+")) == NULL)
    {
        close(sock);
        sock = -1;
        return NULL;
    }

    return fp;
}

static int
fsctl_sendmsg(
    FILE *fp,
    struct fsctl_message *msg)
{
    int ret = 0;

    if ((fp == NULL) || (msg == NULL))
        return -1;

    if (msg->cmd == FSCTL_CMD_READ)
    {
        fprintf(fp, "READ %s MP/1.0\r\n", msg->name);
        fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
        fprintf(fp, "\r\n");
    }
    else if (msg->cmd == FSCTL_CMD_WRITE)
    {
        fprintf(fp, "WRITE %s MP/1.0\r\n", msg->name);

        switch (msg->content_type)
        {
            case FSCTL_CONTENT_TYPE_RAW:
            {
                fprintf(fp, "Content-Type: RAW\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(msg->content_data.raw, msg->content_length, 1, fp);
            }
            break;

            case FSCTL_CONTENT_TYPE_STRING:
            {
                msg->content_length = strlen(msg->content_data.string);

                fprintf(fp, "Content-Type: STRING\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(msg->content_data.string, msg->content_length, 1, fp);
            }
            break;

            case FSCTL_CONTENT_TYPE_INT32:
            {
                char buf[FS_NAME_MAX];

                (void)snprintf(buf, sizeof(buf), "%d", msg->content_data.int32);
                msg->content_length = strlen(buf);

                fprintf(fp, "Content-Type: INT32\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(buf, msg->content_length, 1, fp);
            }
            break;

            case FSCTL_CONTENT_TYPE_UINT32:
            {
                char buf[FS_NAME_MAX];

                (void)snprintf(buf, sizeof(buf), "%u", msg->content_data.uint32);
                msg->content_length = strlen(buf);

                fprintf(fp, "Content-Type: UINT32\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(buf, msg->content_length, 1, fp);
            }
            break;

            default:
            {
                fprintf(fp, "Content-Type: NONE\r\n");
                fprintf(fp, "Content-Length: 0\r\n");
                fprintf(fp, "\r\n");
                ret = -1;
                goto leave;
            }
        }
    }
    else if (msg->cmd == FSCTL_CMD_EXEC)
    {
        fprintf(fp, "EXEC %s MP/1.0\r\n", msg->name);

        switch (msg->content_type)
        {
            case FSCTL_CONTENT_TYPE_RAW:
            {
                fprintf(fp, "Content-Type: RAW\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(msg->content_data.raw, msg->content_length, 1, fp);
            }
            break;

            case FSCTL_CONTENT_TYPE_STRING:
            {
                msg->content_length = strlen(msg->content_data.string);

                fprintf(fp, "Content-Type: STRING\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(msg->content_data.string, msg->content_length, 1, fp);
            }
            break;

            case FSCTL_CONTENT_TYPE_INT32:
            {
                char buf[FS_NAME_MAX];

                (void)snprintf(buf, sizeof(buf), "%d", msg->content_data.int32);
                msg->content_length = strlen(buf);

                fprintf(fp, "Content-Type: INT32\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(buf, msg->content_length, 1, fp);
            }
            break;

            case FSCTL_CONTENT_TYPE_UINT32:
            {
                char buf[FS_NAME_MAX];

                (void)snprintf(buf, sizeof(buf), "%u", msg->content_data.uint32);
                msg->content_length = strlen(buf);

                fprintf(fp, "Content-Type: UINT32\r\n");
                fprintf(fp, "Content-Length: %lu\r\n", msg->content_length);
                fprintf(fp, "\r\n");

                fwrite(buf, msg->content_length, 1, fp);
            }
            break;

            default:
            {
                fprintf(fp, "Content-Type: NONE\r\n");
                fprintf(fp, "Content-Length: 0\r\n");
                fprintf(fp, "\r\n");
                ret = -1;
                goto leave;
            }
        }
    }

leave:
    (void)fflush(fp);
    
    return ret;
}

static int
fsctl_recvmsg(
    FILE *pfile,
    struct fsctl_message *msg)
{
    ssize_t ret = 0;
    size_t len = 0;
    char *line = NULL;
    unsigned long int buffer_length = msg->content_length;

    if ((ret = getline(&line, &len, pfile)) == -1)
        goto leave;

    while ((ret = getline(&line, &len, pfile)) != -1)
    {
        char *p, *e;
        char *lp, *le; /* response header line */
        char *fp, *fe; /* field */
        char *vp, *ve; /* value */

        p = line;
        e = line + ret;

        if (p == NULL || e == NULL || e - p == 0)
            break;

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
                    msg->content_type = FSCTL_CONTENT_TYPE_RAW;
                }
                else if (strncasecmp(T_STRING, vp, ve - vp) == 0)
                {
                    msg->content_type = FSCTL_CONTENT_TYPE_STRING;
                }
                else if (strncasecmp(T_INT32, vp, ve - vp) == 0)
                {
                    msg->content_type = FSCTL_CONTENT_TYPE_INT32;
                }
                else if (strncasecmp(T_UINT32, vp, ve - vp) == 0)
                {
                    msg->content_type = FSCTL_CONTENT_TYPE_UINT32;
                }
                else
                {
                    msg->content_type = FSCTL_CONTENT_TYPE_NONE;
                }
            }
            else if (strncasecmp(T_CONTENT_LENGTH, fp, fe - fp) == 0)
            {
                char buf[FS_NAME_MAX];
                snprintf(buf, sizeof(buf), "%.*s", (int)(ve - vp), vp);
                if (ve - vp == 0)
                    msg->content_length = 0;
                else {
                    int l = atol(buf);
                    if(l < msg->content_length) {
                        msg->content_length = l;
                    }
                }
            }
            else if (strncasecmp(T_RETURN, fp, fe - fp) == 0)
            {
                char buf[FS_NAME_MAX];
                snprintf(buf, sizeof(buf), "%.*s", (int)(ve - vp), vp);
                if (ve - vp == 0)
                    msg->ret = 0;
                else
                    msg->ret = atol(buf);
            }
            else if (strncasecmp(T_CONNECTION, fp, fe - fp) == 0)
            {
                if (strncasecmp(T_CLOSE, vp, ve - vp) == 0)
                    msg->connection_close = 1;
                else
                    msg->connection_close = 0;
            }
        }
        else
        {
            break;
        }
    }

    if (msg->cmd == FSCTL_CMD_READ)
    {
        switch (msg->content_type)
        {
            case FSCTL_CONTENT_TYPE_RAW:
                {
                    if (msg->connection_close)
                        msg->ret = fread(msg->content_data.raw, 1, buffer_length, pfile);
                    else
                        fread(msg->content_data.raw, msg->content_length, 1, pfile);

                    break;
                }

            case FSCTL_CONTENT_TYPE_STRING:
                {
                    if (msg->connection_close)
                        msg->ret = fread(msg->content_data.string, 1, buffer_length, pfile);
                    else
                        fread(msg->content_data.string, msg->content_length, 1, pfile);
                }
                break;

            case FSCTL_CONTENT_TYPE_INT32:
                {
                    char buf[FS_NAME_MAX];

                    (void)memset(buf, 0, sizeof(buf));
                    fread(buf, msg->content_length, 1, pfile);
                    buf[sizeof(buf) - 1] = '\0';

                    msg->content_data.int32 = atol(buf);
                }
                break;

            case FSCTL_CONTENT_TYPE_UINT32:
                {
                    char buf[FS_NAME_MAX];

                    (void)memset(buf, 0, sizeof(buf));
                    fread(buf, msg->content_length, 1, pfile);
                    buf[sizeof(buf) - 1] = '\0';

                    msg->content_data.uint32 = atol(buf);
                }
                break;

            default:
                {
                    ret = -1;
                    goto leave;
                }
        }
    }
    else if (msg->cmd == FSCTL_CMD_WRITE)
    {
        ret = 0;
    }
    else if (msg->cmd == FSCTL_CMD_EXEC)
    {
        ret = 0;
    }

leave:
    if (line)
    {
        free(line);
        line = NULL;
    }

    return ret;
}

static void
fsctl_close(
    FILE *fp)
{
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
}
