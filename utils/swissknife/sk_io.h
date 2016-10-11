/*
 * sk_io.h
 */

#ifndef SK_IO_H
#define SK_IO_H

#include <netinet/in.h> /* struct sockaddr_in */

#include <sk_common.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define SK_IO_CONNECT_TIMEOUT (60) /* 1 minute */
#define SK_IO_BUFFER_SIZE (8 * 1024)

int sk_io_be_nonblock(int fd, int *old_flags);

#define SK_IO_NEW_FD (-1)

int sk_io_connect_ipport(int ref_fd,
                         in_addr_t ip, in_port_t port,
                         int timeout,
                         int *result);
int sk_io_connect_sockaddrin(int ref_fd,
                             const struct sockaddr_in *server_address,
                             int timeout,
                             int *result);

int sk_io_write(int fd, const void *buffer, size_t count);
int sk_io_readn(int fd, void *buffer, size_t *count);

int sk_io_sendfile(int fd_out, int fd_in, off_t offset, size_t count);

int sk_io_private_ip(in_addr_t ip);

int sk_io_getsockname(int fdes, in_addr_t *ip, in_port_t *port);
int sk_io_getpeername(int fdes, in_addr_t *ip, in_port_t *port);

int sk_io_timedwrite(int fd,
                     const void *buffer, size_t count,
                     int timeout,
                     int (*housekeeper)(void *context), void *context);

int sk_io_cat(const char *file, void *buffer, size_t *count);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SK_IO_H */
