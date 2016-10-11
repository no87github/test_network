#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <msg_utils.h>

#define OUTPUT_F_FILE "./output_f.eml"
#define OUTPUT_M_FILE "./output_m.eml"

int main(int argc, char *argv[])
{
    struct stat file_buf = {0};
    size_t total = 0;
    int fd_in = -1;
    int fd_out_f = -1;
    int fd_out_m = -1;
    void *ptr;
    
    if(argc != 2)
    {
        printf("usage:%s <filename>\n",argv[0]);
        return -1;
    }
    
    if((fd_in = open(argv[1],O_RDWR,0666)) < 0)
    {
        printf("Failed to open(%s), errno = %d\n", argv[1], errno);
        return -1;
    }
    
    if((fd_out_f = open(OUTPUT_F_FILE,O_CREAT|O_RDWR,0666)) < 0)
    {
        printf("Failed to open(%s), errno = %d\n", OUTPUT_F_FILE, errno);
        return -1;
    }
    if((fd_out_m = open(OUTPUT_M_FILE,O_CREAT|O_RDWR,0666)) < 0)
    {
        printf("Failed to open(%s), errno = %d\n", OUTPUT_M_FILE, errno);
        return -1;
    }
    
    fstat(fd_in,&file_buf);
    
    total = file_buf.st_size;
    
    ptr = mmap (NULL, total, PROT_READ, MAP_SHARED, fd_in, 0);
    if (ptr == MAP_FAILED) 
    {
        printf("Failed to mmap\n");
        return -1;
    }
    
    if(mu_sendmail_m(0, fd_out_m, ptr, total) != 0)
    {
        printf("Failed to mu_sendmail_f\n");
        return -1;
    }
    
    if(mu_sendmail_f(0, fd_out_f, fd_in, 0, total) != 0)
    {
        printf("Failed to mu_sendmail_f\n");
        return -1;
    }
    
    munmap(ptr, total);
    
    close(fd_in);
    close(fd_out_f);
    close(fd_out_m);
    
    return 0;
}
