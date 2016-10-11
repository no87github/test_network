/*
 * test_sk_io_connect.c
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sk_io.h>

#ifdef NDEBUG
#warning NDEBUG is undefined.
#undef NDEBUG
#endif /* NDEBUG */

int main(int argc, char *argv[])
{
    in_addr_t ip;
    in_port_t port;
    int timeout;
    int fd_src = -1;
    int fd_dst = -1;
    off_t size;

    if (argc < 5)
    {
        fputs("usage: test_sk_io <ip> <port> <timeout> <file>\n", stderr);
        exit(EXIT_FAILURE);
    }
    if ((ip = inet_addr(argv[1])) == INADDR_NONE)
    {
        perror("inet_addr");
        exit(EXIT_FAILURE);
    }
    port = atoi(argv[2]);
    timeout = atoi(argv[3]);
    {
        struct in_addr ia = {ip};
        printf("ip=%s port=%d timeout=%d\n", inet_ntoa(ia), port, timeout);
    }
    if ((errno = sk_io_connect_ipport(SK_IO_NEW_FD, ip, htons(port), timeout, &fd_dst)) != 0)
    {
        perror("sk_io_connect_ipport");
        exit(EXIT_FAILURE);
    }
    puts("sk_io_connect_ipport() succeeded");
    if ((fd_src = open(argv[4], O_RDONLY)) < 0)
    {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if ((size = lseek(fd_src, 0, SEEK_END)) == (off_t)-1)
    {
        perror("lseek");
        exit(EXIT_FAILURE);
    }
    assert(lseek(fd_src, size / 2, SEEK_SET) == size / 2);
    if ((errno = sk_io_sendfile(fd_dst, fd_src, 0, size)))
    {
        perror("sk_io_sendfile");
        exit(EXIT_FAILURE);
    }
    assert(lseek(fd_src, 0, SEEK_CUR) == size / 2);
    puts("sk_io_sendfile() succeeded");
    return 0;
}
