/*
 * sk_io.c
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <strings.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include <sk_io.h>

/*
 * On error, *old_flags will remain unchanged.
 */
int sk_io_be_nonblock(int fd, int *old_flags)
{
    int ret = 0;
    int tmp_old_flags;

    /*
     * old_flags can be NULL.
     */
    if (fd < 0)
    {
        ret = EINVAL;
        goto leave;
    }

    if ((tmp_old_flags = fcntl(fd, F_GETFL, 0)) < 0)
    {
        ret = sk_get_errno();
        SK_LOG_ERROR("fcntl() failed: %d", ret);
        goto leave;
    }
    if (!(tmp_old_flags & O_NONBLOCK))
        if (fcntl(fd, F_SETFL, tmp_old_flags | O_NONBLOCK) < 0)
        {
            ret = sk_get_errno();
            SK_LOG_ERROR("fcntl() failed: %d", ret);
            goto leave;
        }
    if (old_flags != NULL)
        *old_flags = tmp_old_flags;
leave:
    return ret;
}

/*
 * ip and port are in network byte order.
 */
int sk_io_connect_ipport(int ref_fd,
                         in_addr_t ip, in_port_t port,
                         int timeout,
                         int *result)
{
    int ret = 0;
    struct sockaddr_in server_address;

    if (result == NULL)
    {
        ret = EINVAL;
        goto leave;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = ip;
    server_address.sin_port = port;
    if ((ret = sk_io_connect_sockaddrin(ref_fd, &server_address, timeout, result)) != 0)
    {
        SK_LOG_ERROR("sk_io_connect_sockaddrin() failed: %d", ret);
        goto leave;
    }
leave:
    return ret;
}

/*
 * If timeout < 0, the connection is established without timeout, i.e., this function acts the same
 * as the connect system call.
 */
int sk_io_connect_sockaddrin(int ref_fd,
                             const struct sockaddr_in *server_address,
                             int timeout,
                             int *result)
{
    /*
     * See sections 16.3 and 16.4 of UNIX Network Programming Volume 1 (3rd Edition) for nonblocking
     * connect().
     */

    int ret = 0;
    int en;
    int fd = -1;
    int flags = 0;

    if (server_address == NULL || result == NULL)
    {
        ret = EINVAL;
        goto leave;
    }

    if (ref_fd < 0)
    {
        if (ref_fd != SK_IO_NEW_FD)
            SK_LOG_WARN("ref_fd=%d != SK_IO_NEW_FD=%d", ref_fd, SK_IO_NEW_FD);
        if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            ret = sk_get_errno();
            SK_LOG_ERROR("socket() failed: %d", ret);
            goto failure;
        }
    }
    else
        fd = ref_fd;
    /*
     * nonblocking connect
     */
    if ((ret = sk_io_be_nonblock(fd, &flags)) != 0)
    {
        SK_LOG_ERROR("sk_io_be_nonblock() failed: %d", ret);
        goto failure;
    }
    en = connect(fd, server_address, sizeof(*server_address));
    if (en == 0) /* connect() succeeded. */
        goto done;
    else /* connect() failed, probably. */
    {
        ret = sk_get_errno();
        if (ret != EINPROGRESS) /* connect() failed. */
        {
            SK_LOG_ERROR("connect() failed: %d", ret);
            goto failure;
        }
        else /* ret != EINPROGRESS */
            ret = 0;
    }

    /*
     * nonblocking connect and poll
     */
    {
        struct pollfd poll_fd[1];

        memset(&poll_fd, 0, sizeof(poll_fd));
        poll_fd[0].fd = fd;
        poll_fd[0].events = POLLIN | POLLOUT;
        poll_fd[0].revents = 0;

        if (timeout >= 0)
        {
            if (timeout > INT_MAX / 1000)
            {
                SK_LOG_WARN("timeout=%d is too big", timeout);
                timeout = INT_MAX / 1000;
            }
            timeout *= 1000;
        }

again:
        en = poll(poll_fd, 1, timeout);
        if (en < 0) /* poll() failed. */
        {
            if ((ret = sk_get_errno()) == EINTR)
            {
                SK_LOG_WARN("poll() failed: EINTR");
                ret = 0;
                goto again;
            }
            SK_LOG_ERROR("poll() failed: %d", ret);
            goto failure;
        }
        else if (en == 0) /* poll() timed out. */
        {
            ret = ETIMEDOUT;
            goto failure;
        }
        if (poll_fd[0].revents & (POLLIN | POLLOUT)) /* poll() succeeded, probably. */
        {
            int error;
            socklen_t length = sizeof(error);

            /*
             * If the connection completed successfully, error will be 0.
             */
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0)
            {
                ret = sk_get_errno();
                SK_LOG_ERROR("getsockopt() failed: %d", ret);
                goto failure;
            }
            if (error)
            {
                ret = error;
                goto failure;
            }
        }
        else /* It's an error of the operating system. */
        {
            ret = EIO;
            SK_LOG_ERROR("Internal Errors: poll_fd[0].revents=%d", (int)(poll_fd[0].revents));
            goto failure;
        }
    }

done:
    /*
     * Restore the original flags.
     */
    if (fcntl(fd, F_SETFL, flags) < 0)
    {
        ret = sk_get_errno();
        SK_LOG_ERROR("fcntl() failed: %d", ret);
        goto failure;
    }
    *result = fd;
leave:
    return ret;

failure:
    if (fd >= 0 && ref_fd < 0) /* fd is created by ourself */
        if ((en = close(fd)) != 0)
            SK_LOG_ERROR("close(%d) failed: %d", fd, sk_get_errno());
    goto leave;
}

int sk_io_write(int fd, const void *buffer, size_t count)
{
    int ret = 0;
    const char *buf = (const char *)buffer;

    if (fd < 0 || buf == NULL || count < 0)
    {
        ret = EINVAL;
        goto leave;
    }
    if (count == 0)
        SK_LOG_WARN("count=0");
    while (count > 0)
    {
        int n = write(fd, buf, count);
        if (n < 0)
        {
            ret = sk_get_errno();
            SK_LOG_ERROR("write() failed: %d", ret);
            goto leave;
        }
        buf += n;
        count -= n;
    }
leave:
    return ret;
}

/*
 * Read data from fd into buffer until (i) buffer is full or (ii) end of file. *count should be the
 * length of buffer. On success, 0 is returned and *count contains the length of data in buffer. On
 * error, a non-zero error number is returned and the value of *count is undefined.
 */
int sk_io_readn(int fd, void *buffer, size_t *count)
{
    int ret = 0;
    char *begin;
    size_t remain;

    if (fd < 0 || buffer == NULL || count == NULL || *count < 0)
    {
        ret = EINVAL;
        goto leave;
    }
    if (*count == 0)
        SK_LOG_WARN("*count == 0");

    begin = (char *)buffer;
    remain = *count;
    *count = 0;
    while (remain > 0)
    {
        int n = read(fd, begin, remain);
        if (n == 0) /* end of file */
            break;
        else if (n < 0) /* error */
        {
            ret = sk_get_errno();
            SK_LOG_ERROR("read() failed: %d", ret);
            goto leave;
        }
        else /* n > 0 */
        {
            *count += n;
            begin += n;
            remain -= n;
        }
    }
leave:
    return ret;
}

#ifndef SK_NO_SENDFILE

int sk_io_sendfile(int fd_out, int fd_in, off_t offset, size_t count)
{
    int ret = 0;

    if (fd_out < 0 || fd_in < 0 || offset < 0 || count < 0)
    {
        ret = EINVAL;
        goto leave;
    }
    if (count == 0)
        SK_LOG_WARN("count=0");
    while (count > 0)
    {
        int n = sendfile(fd_out, fd_in, &offset, count);
        if (n < 0)
        {
            ret = sk_get_errno();
            SK_LOG_ERROR("sendfile() failed: %d", ret);
            goto leave;
        }
        count -= n;
    }
leave:
    return ret;
}

#else /* SK_NO_SENDFILE */
//#warning SK_NO_SENDFILE is defined.

int sk_io_sendfile(int fd_out, int fd_in, off_t offset, size_t count)
{
    int ret = 0;
    off_t fd_in_offset = (off_t)-1;

    if (fd_out < 0 || fd_in < 0 || offset < 0 || count < 0)
    {
        ret = EINVAL;
        goto leave;
    }
    if (count == 0)
    {
        SK_LOG_WARN("count=0");
        goto leave;
    }
    /*
     * Backup the offset of fd_in.
     */
    if ((fd_in_offset = lseek(fd_in, 0, SEEK_CUR)) == (off_t)-1)
    {
        ret = sk_get_errno();
        SK_LOG_ERROR("lseek() failed: %d", ret);
        goto leave;
    }
    if (lseek(fd_in, offset, SEEK_SET) == (off_t)-1)
    {
        ret = sk_get_errno();
        SK_LOG_ERROR("lseek() failed: %d", ret);
        goto leave;
    }
    while (count > 0)
    {
        int n;
        char buffer[SK_IO_BUFFER_SIZE];

        if ((n = read(fd_in, buffer, sizeof(buffer))) < 0)
        {
            ret = sk_get_errno();
            SK_LOG_ERROR("read() failed: %d", ret);
            goto leave;
        }
        if (n == 0)
        {
            ret = EIO;
            goto leave;
        }
        if ((ret = sk_io_write(fd_out, buffer, n)) != 0)
        {
            SK_LOG_ERROR("sk_io_write() failed: %d", ret);
            goto leave;
        }
        count -= n;
    }
leave:
    /*
     * Restore the offset of fd_in.
     */
    if (fd_in_offset != (off_t)-1)
        if (lseek(fd_in, fd_in_offset, SEEK_SET) == (off_t)-1)
        {
            int en;
            sk_update_errno(&ret, en = sk_get_errno());
            SK_LOG_ERROR("lseek() failed: %d", ret);
        }
    return ret;
}

#endif /* SK_NO_SENDFILE */

#define SK_IO_IP(a__, b__, c__, d__) ((a__) << 24 | (b__) << 16 | (c__) << 8 | (d__))

#define SK_IO_MASK_8  (0xFF << 24)
#define SK_IO_MASK_12 (SK_IO_MASK_8  | 0xF0 << 16)
#define SK_IO_MASK_16 (SK_IO_MASK_8  | 0xFF << 16)
#define SK_IO_MASK_24 (SK_IO_MASK_16 | 0xFF <<  8)

typedef struct
{
    in_addr_t prefix;
    in_addr_t mask;
}
sk_io_private_ip_t;

static const sk_io_private_ip_t m_private_ip[]
    = {{.prefix = SK_IO_IP(  0,   0, 0, 0), .mask = SK_IO_MASK_8},
       {.prefix = SK_IO_IP( 10,   0, 0, 0), .mask = SK_IO_MASK_8},
       {.prefix = SK_IO_IP(127,   0, 0, 0), .mask = SK_IO_MASK_8},
       {.prefix = SK_IO_IP(169, 254, 0, 0), .mask = SK_IO_MASK_16},
       {.prefix = SK_IO_IP(172,  16, 0, 0), .mask = SK_IO_MASK_12},
       {.prefix = SK_IO_IP(192, 168, 0, 0), .mask = SK_IO_MASK_16}};

/*
 * Return true iff ip is a private IP address. ip is in network byte order.
 */
int sk_io_private_ip(in_addr_t ip)
{
    int i;

    ip = ntohl(ip);
    for (i = 0; i < SK_NUMOF(m_private_ip); i++)
        if (m_private_ip[i].prefix == (ip & m_private_ip[i].mask))
            return 1;
    return 0;
}

typedef int sk_getxxxxname_t(int s, struct sockaddr *name, socklen_t *namelen);

static int sk_io_getxxxxname(sk_getxxxxname_t getxxxxname,
                             int fd, in_addr_t *ip, in_port_t *port)
{
    int ret = 0;
    struct sockaddr_in sa;
    socklen_t length = sizeof(sa);

    assert(getxxxxname == getsockname || getxxxxname == getpeername);
    if (fd < 0)
    {
        ret = EINVAL;
        goto leave;
    }
    if (ip == NULL && port == NULL)
        SK_LOG_WARN("ip == NULL && port == NULL");

    if (getxxxxname(fd, (struct sockaddr *)&sa, &length) != 0)
    {
        ret = sk_get_errno();
        SK_LOG_ERROR("%s() failed: %d",
                     getxxxxname == getsockname ? "getsockname" : "getpeername",
                     ret);
        goto leave;
    }
    if (length != sizeof(sa) || sa.sin_family != AF_INET)
    {
        ret = EINVAL;
        SK_LOG_ERROR("Internal Errors: length != sizeof(sa) || sa.sin_family != AF_INET");
        goto leave;
    }
    if (ip != NULL)
        *ip = ntohl(sa.sin_addr.s_addr);
    if (port != NULL)
        *port = ntohs(sa.sin_port);
leave:
    return ret;
}

int sk_io_getsockname(int fd, in_addr_t *ip, in_port_t *port)
{
    return sk_io_getxxxxname(getsockname, fd, ip, port);
}

int sk_io_getpeername(int fd, in_addr_t *ip, in_port_t *port)
{
    return sk_io_getxxxxname(getpeername, fd, ip, port);
}

/*
 * Timeout will be disabled if "timeout" is a non-positive integer. "timeout" is in seconds.
 */
int sk_io_timedwrite(int fd,
                     const void *buffer, size_t count,
                     int timeout,
                     int (*housekeeper)(void *context), void *context)
{
    int ret = 0;
    int en;
    int need_to_restore_flag = 0;
    int flag = 0;

    if (fd < 0 || buffer == NULL || count == 0)
    {
        ret = EINVAL;
        goto leave;
    }

    if (timeout <= 0) /* without timeout */
        ret = sk_io_write(fd, buffer, count);
    else /* with timeout */
    {
        int poll_timeout = 1000 * timeout;
        const char *begin = (const char *)buffer;
        const char *end = begin + count;

        if ((ret = sk_io_be_nonblock(fd, &flag)) != 0)
        {
            SK_LOG_ERROR("sk_io_be_nonblock() failed: %d", ret);
            goto leave;
        }
        need_to_restore_flag = 1;
        while (begin < end)
        {
            struct pollfd poll_fd[1];

            if ((void *)begin != buffer && housekeeper != NULL)
                if ((ret = housekeeper(context)) != 0)
                {
                    SK_LOG_ERROR("housekeeper() failed: %d", ret);
                    goto leave;
                }

            memset(&poll_fd, 0, sizeof(poll_fd));
            poll_fd[0].fd = fd;
            poll_fd[0].events = POLLOUT;
            poll_fd[0].revents = 0;
again:
            en = poll(poll_fd, SK_NUMOF(poll_fd), poll_timeout);
            if (en < 0) /* error */
            {
                if ((ret = sk_get_errno()) == EINTR)
                {
                    SK_LOG_WARN("poll() failed: EINTR");
                    ret = 0;
                    goto again;
                }
                SK_LOG_ERROR("poll() failed: %d", ret);
                goto leave;
            }
            else if (en == 0) /* timed out */
            {
                ret = ETIMEDOUT;
                SK_LOG_DEBUG("poll() failed: ETIMEDOUT");
                goto leave;
            }

            en = write(fd, begin, end - begin);
            if (en < 0) /* error */
            {
                ret = sk_get_errno();
                SK_LOG_ERROR("send() failed: %d", ret);
                goto leave;
            }
            begin += en; /* It's okay if en is 0. */
        } /* while */
    } /* if */
leave:
    if (need_to_restore_flag)
        if (fcntl(fd, F_SETFL, flag) < 0)
        {
            en = sk_get_errno();
            SK_LOG_ERROR("fcntl() failed: %d", en);
            sk_update_errno(&ret, en);
        }
    return ret;
}

/*
 * Read the content of file into buffer. See sk_io_readn() for the meaning of buffer, content, and
 * return values.
 */
int sk_io_cat(const char *file, void *buffer, size_t *count)
{
    int ret = 0;
    int fd = -1;

    if (file == NULL || buffer == NULL || count == NULL || *count < 0)
    {
        ret = EINVAL;
        goto leave;
    }

    if ((fd = open(file, O_RDONLY)) < 0)
    {
        ret = sk_get_errno();
        SK_LOG_ERROR("open(\"%s\", O_RDONLY) failed: %d", file, ret);
        goto leave;
    }
    if ((ret = sk_io_readn(fd, buffer, count)) != 0)
    {
        SK_LOG_ERROR("readn() failed: %d", ret);
        goto leave;
    }
leave:
    if (fd >= 0)
        if (close(fd) != 0)
            SK_LOG_ERROR("close() failed: %d", sk_get_errno());
    return ret;
}
