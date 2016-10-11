#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h> /* for control fd */
#include <arpa/inet.h> /* for control fd */
//#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <poll.h>
#include <locale.h>
#include <libintl.h>
#include <ctype.h>
#include <stdarg.h>

#include "list.h"
#include "fs.h"
#include "fsctl.h"
#include "fsctl_vscan.h"
#include "fsctl_config.h"
#include "glcfg.h"
#include "sk_common.h"
#include "sk_io.h"
#include "utility.h"
#include "tpool.h"
#include <mcheck.h>
#include <sys/prctl.h>
#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************/
/* MACRO DECLARATIONS                                                       */
/****************************************************************************/
#define PRAGNAME    "fs2"
#define DEFAULT_PID_FILE        "/var/run/filescan.pid"
#define DEFAULT_CONF_FILE       PROJECT_RUNTIME_PATH"/etc/filescan.conf"

#define DEFAULT_FD_POLL_TIMEOUT	10

#define min(a, b) ((a)<(b)?(a):(b))

#ifdef USE_AF_LOCAL
#define FSCTL_PATH  "/tmp/."
#endif
    
#define FSCTL_LISTEN_BACKLOG (SOMAXCONN)    /* defined in socket.h */
#define DEFAULT_SYSLOG_MODULE "system"

#ifndef PROJECT_RUNTIME_PATH
#warning "PROJECT_RUNTIME_PATH not defined"
#define DEFAULT_FS_TEXT_FILE       "/opt/TrendMicro/_PRJNAME_/etc/filescan.text"
#else
#define DEFAULT_FS_TEXT_FILE       PROJECT_RUNTIME_PATH "/etc/filescan.text"
#endif

#define ATSE_RELOAD_INDICATOR_INIT     1000000 
/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/

/****************************************************************************/
/* STATIC GLOBAL VARIABLES                                                  */
/****************************************************************************/
static volatile int gterminate = 0;
char var_config_file[NAME_MAX] = {0};
vscan_config_t gvscan_config;
VscanHandle *g_handle_vsh = NULL;
tmSyslog_t * g_sys_vlog = NULL;
tmSyslog_t * g_sys_log = NULL;
int queue_size = 0;
unsigned int *pg_atse_reload_indicator = NULL; /* ATSE reload indicators for each thread, when engine, pattern or config reload.*/
VSCTYPE** ppg_thread_vsc = NULL;

#ifdef __cplusplus
} /* extern "C" */
#endif

static void 
go_terminate_handler(int signum)
{
   gterminate = 1;
}

static void 
task_handler(void *ptr, size_t tasklen);

static int 
handle_server_sd(thread_data_t* data) {
    struct msghdr msg = {0};
    char cmsg_buf[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(struct timeval))];  /* ancillary data buffer */
    unsigned char filename[1] = {0}; /* filename is not using, resize it form 1024 to 1 for better performance.*/
    struct iovec iov[8];
    int fd = -1;
    int ret;
    
    iov[0].iov_base = &data->sinfo;
    iov[0].iov_len	= sizeof(data->sinfo);
    iov[1].iov_base = &data->file_id;
    iov[1].iov_len  = sizeof(data->file_id);
    iov[2].iov_base = &data->pattern_id;
    iov[2].iov_len  = sizeof(data->pattern_id);
    iov[3].iov_base = &data->pattern_ver;
    iov[3].iov_len  = sizeof(data->pattern_ver);
    iov[4].iov_base = &data->session_id;
    iov[4].iov_len  = sizeof(data->session_id);
    iov[5].iov_base = &data->file_size;
    iov[5].iov_len  = sizeof(data->file_size);
    iov[6].iov_base = &data->over_sized;
    iov[6].iov_len  = sizeof(data->over_sized);
    iov[7].iov_base = &data->file_sha1;
    iov[7].iov_len  = sizeof(data->file_sha1);
    /* iov[8].iov_base = &filename; // Bug, for  struct iovec iov[8], access iov[8] will overflow.
    iov[8].iov_len  = sizeof(filename);
    */

    msg.msg_name		= NULL;
    msg.msg_namelen		= 0;
    msg.msg_iov			= iov;
    msg.msg_iovlen		= sizeof(iov)/sizeof(struct iovec);
    msg.msg_control		= cmsg_buf;
    msg.msg_controllen	= sizeof(cmsg_buf);	
    ret = recvmsg(data->sd, &msg, 0);
    if(ret<=0) {
        LOGERROR("recvmsg: failed, ret:%d, %m, qid=%s", ret, data->qid);
        return ret;
    }

    {
        struct cmsghdr *cmsg;
        /* Receive auxiliary data in msgh */
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg,cmsg)) {
            if(cmsg->cmsg_level == SOL_SOCKET) {
                if(cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
                    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
                }
            }
        }
    }

    if(0 > fd) {
        LOGDEBUG("handle_server_sd: failed, reason=%m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
        return -1;
    } else {
        filename[sizeof(filename)-1] = 0;
        LOGDEBUG("handle_server_sd: fid:0x%08x, fd=%d, name=%s, sid=0x%08x, pid=%d, qid=%s", data->file_id, fd, filename, data->session_id, data->pattern_id, data->qid);
        data->fd = fd;
        /* XXX XXX XXX Must free filename before task_handler leave!!!! */
	if(data->filename) {
		free(data->filename);
	}
        data->filename = (unsigned char*) strdup((char*) filename);
        data->vsh = g_handle_vsh;

        task_handler(data, sizeof(thread_data_t));
    }
    return ret;
}

static int
make_sockaddr(struct sockaddr_un *addr, const char* fmt, ...)
{
	va_list   args;
	socklen_t len = sizeof(addr->sun_family) + 1;

	addr->sun_family  = AF_UNIX;
	addr->sun_path[0] = '\0';

	va_start(args, fmt);
	len += vsnprintf(addr->sun_path + 1, sizeof(*addr) - sizeof(addr->sun_family) - 1, fmt, args);
	va_end(args);
	return len;
}

static inline const char*
make_suffix(int ndx)
{
	if(ndx == 0) {
		return "";
	}
	if(ndx >= 1 && ndx <= 100) {
		static const char digit[] =
			"00\0" "01\0" "02\0" "03\0" "04\0" "05\0" "06\0" "07\0" "08\0" "09\0"
			"10\0" "11\0" "12\0" "13\0" "14\0" "15\0" "16\0" "17\0" "18\0" "19\0"
			"20\0" "21\0" "22\0" "23\0" "24\0" "25\0" "26\0" "27\0" "28\0" "29\0"
			"30\0" "31\0" "32\0" "33\0" "34\0" "35\0" "36\0" "37\0" "38\0" "39\0"
			"40\0" "41\0" "42\0" "43\0" "44\0" "45\0" "46\0" "47\0" "48\0" "49\0"
			"50\0" "51\0" "52\0" "53\0" "54\0" "55\0" "56\0" "57\0" "58\0" "59\0"
			"60\0" "61\0" "62\0" "63\0" "64\0" "65\0" "66\0" "67\0" "68\0" "69\0"
			"70\0" "71\0" "72\0" "73\0" "74\0" "75\0" "76\0" "77\0" "78\0" "79\0"
			"80\0" "81\0" "82\0" "83\0" "84\0" "85\0" "86\0" "87\0" "88\0" "89\0"
			"90\0" "91\0" "92\0" "93\0" "94\0" "95\0" "96\0" "97\0" "98\0" "99\0";

		return &digit[(ndx - 1) * 3];
	}
	return NULL;
}

static int 
allocate_server_sd(int * fd, int ndx)
{
	int sd         = -1;
	int file_flags = 0;
	int ret        = 0;

#ifdef DEBUG
	LOGDEBUG("++ allocate_server_sd ++");
#endif

	sd = socket(PF_UNIX, SOCK_DGRAM, 0);

	if(sd == -1) {
		LOGERROR("socket(PF_UNIX, SOCK_DGRAM, 0): %m");
		ret = -1;
		goto close_socket;
	}

	{
		struct sockaddr_un sa;
		const char*        suffix = make_suffix(ndx);
		socklen_t          len    = 0;
		
		if(suffix == NULL) {
			LOGERROR("index %d for socket name was out of range", ndx);
			return -1;
		}
		
		len = make_sockaddr(&sa, "FSE%s", suffix);
		
		if(bind(sd, (struct sockaddr*)&sa, len) < 0) {
			LOGERROR("bind(): %m");
			ret = -1;
			goto close_socket;
		}
	}

	if (0 > (ret = sk_io_be_nonblock(sd, &file_flags))) {
		LOGERROR("sk_io_benonblock: failed, %m");
		ret = -1;
		goto close_socket;
	}
	*fd = sd;
	return 0;

close_socket:
	if(0 > sd) {
		close(sd);
		sd = -1;
	}
#ifdef DEBUG
	LOGDEBUG("-- allocate_server_sd --");
#endif
	return ret;
}

static int
handle_control_sd(int fd)
{
    int ret = 0;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int sock = -1;
    //char command[1024] = {0};
    //int cmdlen = sizeof(command);
#ifdef DEBUG
    LOGDEBUG("++ handle_control_sd ++");
#endif
    if (0 > (sock = accept(fd, (struct sockaddr *)&addr, &addrlen)))
    {
        LOGERROR("handle_control_sd: accept(): %m");
        return -1;
    }

    if (0 > (ret = fsctl_svr(sock)))
    {
        LOGERROR("fsctl_svr: failed %d, %m", ret);
    }
    
    if (sock >= 0)
    {
        (void)close(sock);
        sock = -1;
    }
#ifdef DEBUG
    LOGDEBUG("-- handle_control_sd --");
#endif
    return ret;
}

static int
allocate_control_sd(int * cd)
{
    int ret = -1;
    int file_flags = 0;
    int sd = -1;
    struct sockaddr_in addr;
    socklen_t addrlen;
    int optval;
    socklen_t optlen;

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0)
    {
        LOGERROR("allocate_control_sd: socket() %m");
        goto close_socket;
    }

    optval = 1;
    optlen = sizeof(optval);
    if (0 > (ret = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, optlen)))
    {
        LOGERROR("allocate_control_sd: setsockopt() %m");
        goto close_socket;
    }

    (void)memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(FSCTL_SVR_ADDR);
    addr.sin_port = htons(FSCTL_SVR_PORT);
    addrlen = sizeof(addr);

    if (0 > (ret = bind(sd, (struct sockaddr *)&addr, addrlen)))
    {
        LOGERROR("allocate_control_sd: bind() %m");
        goto close_socket;
    }

    if (0 > (ret = sk_io_be_nonblock(sd, &file_flags))) {
        LOGERROR("sk_io_benonblock: failed, %m");
        ret = -1;
        goto close_socket;
    }

    if (0 > (ret = listen(sd, FSCTL_LISTEN_BACKLOG)))
    {
        LOGERROR("allocate_control_sd: listen() %m");
        goto close_socket;
    }
    *cd = sd;
    return 0;
close_socket:
    if (sd >= 0)
    {
        (void)close(sd);
        sd = -1;
    }
    return ret;
}

static void 
show_virus_result(thread_data_t *data, VirusResult *virus_result)
{
    VirusResult *vr=NULL;
#ifdef DEBUG
    LOGDEBUG("++Virus Result++");
#endif
    if (!data)
        return;
    LOGDEBUG("fd: %d, filename:%s", data->fd, data->filename);
    vr = virus_result;
    /* attach on */
    while(vr)
    {
        if(vr->filename && vr->virusname && vr->majortype)
        {
            LOGDEBUG("vr->filename[%s], vr->virusname[%s], vr->majortype[%s], vr->minortype[%s]",
                    vr->filename,
                    vr->virusname,
                    vr->majortype,
                    vr->minortype);
        }
        else 
        {
            LOGDEBUG("vr->filename[%s], vr->virusname[%s], vr->majortype[%s]", "NoVirus", "NoVirus", "NoType");
        }
        vr = vr->next;
    }
#ifdef DEBUG
    LOGDEBUG("--Virus Result--");
#endif
}

static void 
show_scan_result(int fd, char * filename, vscan_result_t *scan_result)
{
#ifdef DEBUG
    LOGDEBUG("++Scan Result++");
#endif
    LOGDEBUG("fd: %d,"
            "filename: %s,"
            "cb:%d,"
            "no_virus:%d,"
            "virus:%d,"
            "spy:%d,"
            "bot:%d,"
            "clean_ok:%d,"
            "clean_err:%d,"
            "err_comp:%d,"
            "err_fsize:%d,"
            "err_fcount%d,"
            "err_fratio:%d,"
            "err_unhandle:%d,"
            "err_max_scan_loop:%d",
            fd,
            filename,
            scan_result->scan_cb_count,
            scan_result->no_virus_count,
            scan_result->virus_count,
            scan_result->spyware_count,
            scan_result->bot_count,
            scan_result->clean_ok_count,
            scan_result->clean_err_count,
            scan_result->err_compressdeep_count,
            scan_result->err_filesize_count,
            scan_result->err_filecount_count,
            scan_result->err_fileratio_count,
            scan_result->err_unhandle_count,
            scan_result->err_max_scan_loop);
#ifdef DEBUG
    LOGDEBUG("--Scan Result--");
#endif
}

static int
write_pidfile(
    const char *pidfile,
    pid_t pid)
{
    int ret = -1;
    int fd = -1;
    FILE *fp = NULL;

    if (pidfile == NULL)
    {
        errno = EINVAL;
        goto leave;
    }

    if ((fd = open(pidfile, O_RDWR | O_CREAT, 0644)) < 0)
        goto leave;

    if ((fp = fdopen(fd, "r+")) == NULL)
        goto leave;

    if (flock(fd, LOCK_EX | LOCK_NB) != 0)
        goto leave;

    if (fprintf(fp, "%d\n", pid) <= 0)
        goto leave;

    (void)fflush(fp);

    if (flock(fd, LOCK_UN) != 0)
        goto leave;
    if (fp)
        fclose(fp);
    ret = 0;

leave:
    if (fd >= 0)
    {
        (void)close(fd);
        fd = -1;
    }

    return ret;
}

static int 
setup_signal_handler()
{
    struct sigaction act;
    act.sa_handler = go_terminate_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGTERM,&act,NULL);
    sigaction(SIGINT, &act,NULL);
    return 0;
}

static void
task_free_func(void *data, size_t tasklen)
{
    thread_data_t *my_data = NULL;
    my_data = (thread_data_t *)data;
    /*
     * 2006.05.16 Sam Tsai
     * close fd in fs_cav(), cause queued fd should not been closed first
     */
//    close(my_data->fd);
    if (my_data->filename)
        free(my_data->filename); /* filename came from strdup in handle_server_sd */

    if(my_data->cav_sd >= 0) {
	close(my_data->cav_sd);
    }
    free(data);
}

static int save_temp_file(int fd, const char *tmp_filename)
{
    char tmpbuf[1024];
    char *ptmpbuf;
    int readbyte = 0;
    int writebyte = 0;
    int tmpfd = 0;
    int filesize = 0;
    int ret = 0;
    int ret2 = 0;

    // create temp file
    tmpfd = open(tmp_filename, O_RDWR|O_TRUNC|O_CREAT, 0644);
    if (tmpfd == -1)
    {
        LOGERROR("open() return %d. errno=%d",tmpfd, errno);
        ret = -1;
        goto exit;
    }

    // set offset of fd to beginning of file
    ret = lseek(fd, 0, SEEK_SET);
    if (ret != 0)
    {
        LOGERROR("lseek() return %d. errno=%d",ret, errno);
        ret = -1;
        goto exit_open;
    }

    while (1)
    {
        readbyte = read(fd, tmpbuf, sizeof(tmpbuf));
        if (readbyte == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                LOGERROR("open() return %d. errno=%d",tmpfd, errno);
                ret = -1;
                goto exit_offset;
            }
        }
        else if (readbyte == 0)
        {
            break;
        }
        else
        {
            ptmpbuf = tmpbuf;
            while(1)
            {
                LOGDEBUG("ptmpbuf = 0x%p, readbyte=%d", ptmpbuf,readbyte);
                writebyte = write(tmpfd, ptmpbuf, readbyte);
                if (writebyte == -1)
                {
                    LOGERROR("open() return %d. errno=%d",tmpfd, errno);
                    ret = -1;
                    goto exit_offset;
                }
                filesize += writebyte;
                LOGDEBUG("filesize = %d, writebyte=%d",filesize , writebyte);
                if (writebyte == readbyte)
                {
                    LOGDEBUG("writebyte == readbyte");
                    break;
                }
                else
                {
                    readbyte -= writebyte;
                    ptmpbuf += writebyte;
                    LOGDEBUG("readbyte = %d, ptmpbuf=0x%p",readbyte , ptmpbuf);
                }
            }
        }
    }
    fsync(tmpfd);
    close(tmpfd);
    tmpfd = 0;

exit_offset:
    // set offset of fd to beginning of file
    ret2 = lseek(fd, 0, SEEK_SET);
    if (ret2 != 0)
    {
        LOGERROR("lseek() return %d. errno=%d",ret2, errno);
    }

exit_open:
    if (tmpfd)
    {
        close(tmpfd);
        tmpfd = 0;
    }

exit:
    return ret;
}


static void calc_sha1(int fd, unsigned char *sha1)
{
    SHA_CTX sha1_ctx;
    unsigned char buf[64*1024];
    int ret = 0;
    
    SHA1_Init(&sha1_ctx);
    
    lseek(fd, 0, SEEK_SET);
    while(0<(ret = read(fd, buf, sizeof(buf)))) {
        SHA1_Update(&sha1_ctx, buf, ret);
    }
    lseek(fd, 0, SEEK_SET);
    
    SHA1_Final(sha1, &sha1_ctx);
}


static void task_handler(void *ptr, size_t tasklen) {
    int ret = 0;
    thread_data_t *data = NULL;
    FileScanResult *fs_result = NULL;
    const int filename_max_buf = 64;
    char tmp_filename[filename_max_buf+1];
    int temp_file_saved = 0;

    unsigned char sha1[SHA_DIGEST_LENGTH] = {0};
    static unsigned char dummy_sha1[SHA_DIGEST_LENGTH] = {0};

    data = (thread_data_t *)ptr;
    if (gfilescan_config.enable_scan && 0 == data->over_sized) {
        if (gfilescan_config.save_scanning_file) {
            const char* suffix = data->qid;

            snprintf(tmp_filename, filename_max_buf, TEMP_SCANNING_FILENAME,
                    (long) data->file_id, suffix && *suffix? "_": "", suffix? suffix: "");
            tmp_filename[filename_max_buf] = '\0';

            LOGDEBUG("data->fd=%d, tmp_filename=%s, sid=0x%08x, pid=%d, qid=%s", data->fd, tmp_filename, data->session_id, data->pattern_id, data->qid);
            ret = save_temp_file(data->fd, tmp_filename);
            if (ret == 0) {
                LOGDEBUG("Save temp file %s success. sid=0x%08x, pid=%d, qid=%s", tmp_filename, data->session_id, data->pattern_id, data->qid);
                temp_file_saved = 1;
            } else {
                LOGERROR("Save temp file %s fail. sid=0x%08x, pid=%d, qid=%s", tmp_filename, data->session_id, data->pattern_id, data->qid);
            }
        } else {
            LOGDEBUG("gfilescan_config.save_scanning_file=%d, sid=0x%08x, pid=%d, qid=%s",gfilescan_config.save_scanning_file, data->session_id, data->pattern_id, data->qid);
        }

        LOGDEBUG("#KK: fs_cache NCIE,    sha1=%*b, sid=0x%08x, pid=%d, qid=%s", SHA_DIGEST_LENGTH, data->file_sha1, data->session_id, data->pattern_id, data->qid);
        if(memcmp(data->file_sha1, dummy_sha1, SHA_DIGEST_LENGTH)!=0) {
            if(gfilescan_config.use_fse_sha1) {
                memcpy(sha1, data->file_sha1, SHA_DIGEST_LENGTH);
            } else {
                calc_sha1(data->fd, sha1);
                if(memcmp(data->file_sha1, sha1, SHA_DIGEST_LENGTH)!=0) {
                    LOGERROR("#KK: fs_cache SHA1 mismatch, sha1=%*b, NCIE_sha1=%*b, sid=0x%08x, pid=%d, qid=%s", SHA_DIGEST_LENGTH, sha1, SHA_DIGEST_LENGTH, data->file_sha1, data->session_id, data->pattern_id, data->qid);
                }
            }
        } else {
            calc_sha1(data->fd, sha1);
        }

        if (gfilescan_config.enable_scan) {
            if(gfilescan_config.hit_rate_limit >= 0 && gfilescan_config.hit_rate_limit < 1.0) {
                fs_result = FileScanResultCache_get_simulated(sha1, gfilescan_config.hit_rate_limit);
            } else {
                fs_result = FileScanResultCache_get(sha1);
            }

            if(NULL!=fs_result) {
                LOGDEBUG("#KK: fs_cache hit,     sha1=%*b, sid=0x%08x, pid=%d, qid=%s", SHA_DIGEST_LENGTH, sha1, data->session_id, data->pattern_id, data->qid);
                ret = VSCAN_SUCCESS;
            } else {
                LOGDEBUG("#KK: fs_cache miss,    sha1=%*b, sid=0x%08x, pid=%d, qid=%s", SHA_DIGEST_LENGTH, sha1, data->session_id, data->pattern_id, data->qid);
                fs_result = FileScanResult_new();
                if(fs_result==NULL) {
                    LOGERROR("FileScanResult_new(): %m");
                    goto out_FileScanResult_new;
                }

                if(data->file_size<=data->scanbuf_size) {
                    off_t offset;
                    ssize_t byte_read;
                    offset = lseek(data->fd, 0, SEEK_SET);
                    if(offset!=0) {
                        LOGERROR("lseek: %m");
                        goto fallback_to_vscan_fd;
                    }
                    byte_read = read(data->fd, data->scanbuf, data->file_size);
                    if(byte_read!=data->file_size) {
                        LOGERROR("read: byte_read=%zd, file_size=%lld, %m", byte_read, data->file_size);
                        goto fallback_to_vscan_fd;
                    }
                    ret = vscan_scan_mem(data->vsh,
                            &(data->thread_vsc),
                            data->patse_reload_indicator,
                            data->scanbuf,
                            data->file_size,
                            (char*) data->filename,
                            fs_result->virus_result,
                            &fs_result->scan_result,
#ifdef USE_ATSE
                            fs_result->evae_result
#endif
                            );
                } else  {
fallback_to_vscan_fd:
                    ret = vscan_scan_fd(data->vsh,
                            &(data->thread_vsc),
                            data->patse_reload_indicator,
                            data->fd,
                            0,
                            (char*) data->filename,
                            fs_result->virus_result,
                            &fs_result->scan_result,
#ifdef USE_ATSE
                            fs_result->evae_result
#endif
                            );
                }
                if(ret == VSCAN_SUCCESS) {
                    FileScanResultCache_add(fs_result, sha1);
                    LOGDEBUG("#KK: fs_cache add,     sha1=%*b, sid=0x%08x, pid=%d, qid=%s", SHA_DIGEST_LENGTH, sha1, data->session_id, data->pattern_id, data->qid);
                }
            }
            if(ret == VSCAN_SUCCESS) {
                show_virus_result(data, fs_result->virus_result);
            }
        }
        if (temp_file_saved && !gfilescan_config.force_save_scanning_file) {
            // remove temp file
            ret = unlink(tmp_filename);
            if (ret != 0) {
                LOGERROR("unlink() return %d. errno=%d, sid=0x%08x, pid=%d, qid=%s",ret, errno, data->session_id, data->pattern_id, data->qid);
            } else {
                LOGDEBUG("unlink(%s) success. sid=0x%08x, pid=%d, qid=%s",tmp_filename, data->session_id, data->pattern_id, data->qid);
            }
        }
        else
        {
            if (temp_file_saved && gfilescan_config.force_save_scanning_file)
            {
                LOGDEBUG("temp file %s saved, sid=0x%08x, pid=%d, qid=%s", tmp_filename,data->session_id, data->pattern_id, data->qid);
            }
        }
        show_scan_result(data->fd, (char*) data->filename, &fs_result->scan_result);
    }

out_FileScanResult_new:
    /*
     * Even not scaned, cav has to receive trigger related to this file
     */
    if (0 > fs_cav(
                fs_result==NULL?NULL:fs_result->virus_result, 
#ifdef USE_ATSE
                fs_result==NULL?NULL:fs_result->evae_result,
#endif
                data,
                sha1)) {
        LOGERROR("fs_cav: failed, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
    }

    if(fs_result!=NULL) {
        FileScanResult_put(fs_result);
    }

    LOGDEBUG("Thread #%lx finished fileid:%d, fd:%d filename:%s, sid=0x%08x, pid=%d, qid=%s", pthread_self(), data->file_id, data->fd, data->filename, data->session_id, data->pattern_id, data->qid);
    return;
}

static void*
worker_thread(void* ptr)
{
    thread_data_t* data = (thread_data_t*) ptr;
    char thread_name[17];
    snprintf(thread_name, sizeof(thread_name), "filescan-%s", data->qid && *data->qid? data->qid: "default");
    prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL);

    int sd  = data->sd;

    while(!gterminate) {
        struct pollfd poll_fd;

        memset(&poll_fd, 0, sizeof(poll_fd));
        poll_fd.fd = sd;
        poll_fd.events = POLLIN;
        poll_fd.revents = 0;

        int ret = poll(&poll_fd, 1, -1); //DEFAULT_FD_POLL_TIMEOUT * 1000);

        if (ret < 0) /* poll() failed. */
        {
            if ((ret = sk_get_errno()) == EINTR)
            {
                LOGDEBUG("service_loop: poll() EINTR, qid=%s", data->qid);
                continue;
            }
            LOGERROR("service_loop: poll() failed: %d, reason:%m", ret);
            continue;
        }
        if (poll_fd.revents & (POLLIN)) /* poll() succeeded, probably. */
        {
            int       error  = 0;
            socklen_t length = sizeof(error);

            /*
             * If the connection completed successfully, error will be 0.
             */
            if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, &length) < 0)
            {
                ret = sk_get_errno();
                LOGERROR("service_loop: getsockopt() server sd failed: %d, qid=%s", ret, data->qid);
                continue;
            }
            if (error)
            {
                ret = error;
                LOGERROR("service_loop: getsockopt() server sd error: %d, %m, qid=%s", ret, data->qid);
                continue;
            }
            if (0 > (ret = handle_server_sd(data)))
            {
                LOGERROR("service_loop: handle_server_sd() failed, reason=%m, qid=%s", data->qid);
               
                /* break; // the "break" will terminte this worker thead, */
                gterminate = 1; /* instead of terminate current worker thead, terminate the process is perferred. */
            }
        }
    }
    task_free_func(ptr, sizeof(thread_data_t));
    return NULL;
}

static int 
service_loop(int cd)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

    while(!gterminate) {
        ret = 0;
        /*
         * nonblocking connect and poll
         */
        struct pollfd poll_fd;

        memset(&poll_fd, 0, sizeof(poll_fd));
        poll_fd.fd = cd;
        poll_fd.events = POLLIN;
        poll_fd.revents = 0;

        ret = poll(&poll_fd, 1, DEFAULT_FD_POLL_TIMEOUT * 1000);
        if (ret < 0) /* poll() failed. */
        {
            if ((ret = sk_get_errno()) == EINTR)
            {
                LOGDEBUG("service_loop: poll() EINTR");
                continue;
            }
            LOGERROR("service_loop: poll() failed: %d, reason:%m", ret);
            break;
        }
        else if (ret == 0) /* poll() timed out. */
        {
            /* LOGDEBUG("service_loop: poll() timeout, %m"); */
            continue;
        }
        else if (poll_fd.revents & (POLLIN)) /* poll() succeeded, probably. */
        {
            handle_control_sd(poll_fd.fd);
        }
        else /* It's an error of the operating system. */
        {
            ret = EIO;
            LOGERROR("Internal Errors: poll_fd.revents=%d", (int)(poll_fd.revents));
            break;
        }
    }
    return ret;
}

static void set_fs_ready_flag(int status)
{
        int fd;
        char str[16];
	int retry = 15;
	char *procname="/proc/sys/net/toe/fs_ready";


RETRY:
        fd = open(procname, O_RDWR);
        if(fd < 0) {
		LOGERROR("open %s failed, retry=%d, reason: %m", procname, retry);
		if(retry < 1)
			return;
		else {
			retry--;
			sleep(1);
			goto RETRY;
		}
        }

        snprintf(str, sizeof(str), "%d", status);
        if(write(fd, str, strlen(str)) < 0) {
		LOGERROR("write %s failed, reason: %m", procname);
	} else {
		LOGDEBUG("write %d to %s", status, procname);
	}

        close(fd);
}

static int filescand() {
    int *sd = NULL; /* server file descriptor */
    int cd  = -1; /* control file descriptor */
    int ret = 0;
    pthread_t *threads = NULL;
    int i;

    // Load system config
    memset(var_config_file, 0, NAME_MAX);
    memcpy(var_config_file, (DEFAULT_CONF_FILE), strlen(DEFAULT_CONF_FILE));
    if (0 > (ret = fsctl_config_init(var_config_file))) {
        fs_syslog(FILESCAN_LOGEVT_WARN_INFO, FILESCAN_LOGSVT_ERR, FILESCAN_LOGMSG_CONFIG_CORRUPT);
        LOGERROR("load_config: failed, ret=%d, reason=%m", ret);
        goto leave_filescand;
    }

    /* 
     * Install the signal handler
     */
    if (0 > (ret = setup_signal_handler())) {
        fs_syslog(FILESCAN_LOGEVT_WARN_INFO, FILESCAN_LOGSVT_ERR, FILESCAN_LOGMSG_INTERNAL_ERROR);
        LOGERROR("setup_signal_handler: failed");
        goto leave_filescand;
    }
#ifdef DEBUG
    LOGDEBUG("setup_signal_handler");
#endif

    /*
     * initialize VSAPI
     */
    if (0 > (ret = fsctl_vscan_init(&gvscan_config))) {
        fs_syslog(FILESCAN_LOGEVT_WARN_INFO, FILESCAN_LOGSVT_ERR, FILESCAN_LOGMSG_VSCAN_ERROR);
        LOGERROR("Failed to vscan_init\n");
        ret = -1;
        goto leave_filescand;
    }
    //    handle_vsh = vscan_create_handle(gvscan_config.protocol);
    //    g_handle_vsh = handle_vsh;
#ifdef DEBUG
    LOGDEBUG("vscan init done");
#endif

    if(0!=FileScanResultCache_init(gfilescan_config.hash_size, gfilescan_config.cache_size)) {
        LOGERROR("FileScanResultCache_init: %m");
        ret = -1;
        goto stop_pool;
    }

    /* 
     * Initialize thread pool
     * Firstly, you must initialize it to get a pool handler 
     */

#ifdef DEBUG
    LOGDEBUG("thread pool init done");
#endif

    if(queue_size <= 0) {
        glcfg_t ggb_conf = glcfg_open("/etc/conf/ggb.conf", GLCFG_MODE_READ);

        if(ggb_conf) {
            const char* value = glcfg_get_param_value(ggb_conf, "toe", "cpu_number", NULL);

            if(value && *value) {
                queue_size = atoi(value);
                LOGDEBUG("loaded cpu_number = %d from toe/cpu_number of ggb.conf", queue_size);
            }
            glcfg_close(ggb_conf);
        }
    }
    if(queue_size <= 0) {
        FILE *fp = fopen("/proc/cpuinfo", "r");
        if(fp) {
            const char   tag[] = "processor";
            const size_t len   = sizeof(tag) - 1;
            char         buf[2048];

            queue_size = 0;

            while(fgets(buf, sizeof(buf), fp)) {
                if(strncasecmp(buf, tag, len) == 0 && isblank(buf[len])) {
                    queue_size++;
                }
            }
            fclose(fp);

            LOGDEBUG("loaded cpu_number = %d from /proc/cpuinfo", queue_size);
        }
    }
    if(queue_size < 0) {
        queue_size = 0;
    }

    queue_size++;  //preserve for original socket
    LOGDEBUG("set queue_size = %d", queue_size);

    sd = (int*) malloc(queue_size * sizeof(int));
    if(sd == NULL) {
        LOGERROR("sd=malloc(%d*%zd): %m", queue_size, sizeof(int));
        ret = -1;
        goto stop_pool;
    }
    memset(sd, -1, sizeof(int) * queue_size);

    pg_atse_reload_indicator = (unsigned int*) malloc(queue_size * sizeof(unsigned int));
    if(pg_atse_reload_indicator == NULL) {
          LOGERROR("pg_atse_reload_indicator=malloc(%d*%zd): %m", queue_size, sizeof(unsigned int));
          ret = -1;
          goto stop_pool;
    }
    for (i=0;i<queue_size;i++) {
       *(pg_atse_reload_indicator+i) = ATSE_RELOAD_INDICATOR_INIT;
       LOGDEBUG("indicator[%d] (addr:value) is: (%p:%d)", i, pg_atse_reload_indicator+i, *(pg_atse_reload_indicator+i));
    }

    ppg_thread_vsc = (VSCTYPE **) malloc(queue_size * sizeof(VSCTYPE*));
    if(ppg_thread_vsc == NULL) {
       LOGERROR("ppg_thread_vsc=malloc(%d*%zd): %m", queue_size, sizeof(VSCTYPE*));
       ret = -1;
       goto stop_pool;
    }
     memset(ppg_thread_vsc, 0, sizeof(VSCTYPE*) * queue_size);



    threads = (pthread_t*) malloc(queue_size * sizeof(pthread_t));
    if(threads==NULL) {
       LOGERROR("threads=malloc(%d*%zd): %m", queue_size, sizeof(pthread_t));
       ret = -1;
       goto stop_pool;
    }
    memset(threads, 0, sizeof(pthread_t) * queue_size);

    for(i = 0; i < queue_size; i++) {
        const char* suffix = make_suffix(i);

        if(suffix == NULL) {
            queue_size = i;
            LOGDEBUG("change queue_size = %d because index %d was out of range", queue_size, i);
            break;
        }
        /* 
         * Allocate Server sd 
         */
        if(0 > (ret = allocate_server_sd(&sd[i], i)) || -1 == sd[i]) {
            fs_syslog(FILESCAN_LOGEVT_WARN_INFO, FILESCAN_LOGSVT_ERR, FILESCAN_LOGMSG_SCAN_SVR_START_ERR);
            LOGERROR("allocate_server_sd: failed for qid=%s", suffix);
            ret = -1;
            goto stop_pool;
        }
        thread_data_t *data = (thread_data_t*) calloc(1, sizeof(thread_data_t)+gfilescan_config.scanbuf_size);

        if(data == NULL) {
            LOGERROR("allocate_server_sd: failed to allocate thread_data_t for qid=%s", suffix);
            close(sd[i]);
            ret = -1;
            goto stop_pool;
        }
        data->qid         = suffix;
        data->sd          = sd[i];
        data->patse_reload_indicator = pg_atse_reload_indicator + i;
        data->thread_vsc = VSCTYPE_INVALID;
        data->cav_sd      = socket(PF_UNIX, SOCK_DGRAM, 0);
        data->cav_socklen = make_sockaddr(&data->cav_sockname, "VAC%s", suffix);
        data->scanbuf_size = gfilescan_config.scanbuf_size;

        if(pthread_create(&threads[i], NULL, worker_thread, data) != 0) {
            if(data->cav_sd >= 0) {
                close(data->cav_sd);
            }
            free(data);
            LOGERROR("allocate_server_sd: failed to create thread for qid=%s", suffix);
            ret = -1;
            goto stop_pool;
        }

        LOGDEBUG("allocate_server_sd: allocated socket @FSE%s (qid=%s)", suffix, suffix);
        ppg_thread_vsc[i] = &(data->thread_vsc);
    }

    /* 
     * Allocate control fd 
     */
    if(0 > (ret = allocate_control_sd(&cd)) || -1 == cd) {
        fs_syslog(FILESCAN_LOGEVT_WARN_INFO, FILESCAN_LOGSVT_ERR, FILESCAN_LOGMSG_CTRL_SVR_START_ERR);
        LOGERROR("allocate_control_sd: failed");
        ret = -1;
        goto stop_pool;
    }

    // notify TOE that filescan is ready
    set_fs_ready_flag(1);

    /*
     * Start service loop
     */
    if (0 > (ret = service_loop(cd))) {
        fs_syslog(FILESCAN_LOGEVT_WARN_INFO, FILESCAN_LOGSVT_ERR, FILESCAN_LOGMSG_SCAN_SERVICE_ERR);
        LOGERROR("service_loop: failed");
    }

    // notify TOE that filescan is not ready
    set_fs_ready_flag(0);

stop_pool:
    gterminate = 1;

    if(cd >= 0) {
        close(cd);
    }
    if(sd != NULL) {
        for(i = 0; i < queue_size; i++) {
            if(sd[i] >= 0) {
                close(sd[i]);
            }
        }
        free(sd);
    }

    if(threads != NULL) {
        for(i = 0; i < queue_size; i++) {
            if(threads[i]) {
                pthread_cancel(threads[i]);
                pthread_join(threads[i], NULL);
            }
        }
        free(threads);
    }
    if(pg_atse_reload_indicator != NULL) {
       free(pg_atse_reload_indicator);
       pg_atse_reload_indicator = NULL;
    }

    FileScanResultCache_fini();
    vscan_delete_handle(g_handle_vsh);
    fsctl_vscan_exit();
    fsctl_config_exit();
leave_filescand:
    return ret;
}

static void 
usage(const char *prg) 
{
    fprintf(stderr, "Usage: %s [options]...\n", prg);
    fprintf(stderr, "  -h,  --help                print this help.\n");
    fprintf(stderr, "  -d,  --daemon              run as daemon.\n");
    fprintf(stderr, "  -m                         enable mtrace\n");
    fprintf(stderr, "  -q <queue_count>           set queue count; default: 0, depending on actual number of CPUs.\n");
    fprintf(stderr, "  -y <tmdebug_level>         set the debug level; default: from config\n");
}

int main(int argc, char * argv[]) 
{
    int daemon_f = 0;
    int f_tmdebug_level = 0;
    int f_mtrace = 0;
    int tmdebug_level = -1;
    int ret = 0;


    setlocale(LC_ALL, "");
    bindtextdomain(PRAGNAME, NULL);
    textdomain(PRAGNAME);

    { /* Parse command line options */
        int c;

        while (-1 != (c = getopt(argc, argv, "hdmy:q:")))
        {
            switch (c)
            {
                case 'y':
                    f_tmdebug_level = 1;
                    tmdebug_level = strtoul(optarg, 0, 0);
                    fprintf(stderr, "tmdebug_level=0x%08x\n", tmdebug_level);
                    break;

                case 'm':
                    f_mtrace = 1;
                    fprintf(stderr, "enable mtrace()\n");
                    break;

                case 'd':
                    {
                        daemon_f = 1;
                    }
                    break;

                case 'q':
                    queue_size = strtoul(optarg, 0, 0);
                    fprintf(stderr, "queue_size=%d (+1)\n", queue_size);
                    break;

                case 'h':
                default:
                    {
                        usage(PRAGNAME);
                        exit(0);
                    }
            }
        }
    }
    register_printf_buffer();
    if (f_mtrace) {
        mtrace();
    }
    ret = tmDebugOpenDefault(TmDebugFile, DEFAULT_DEBUGLOG_FILE);
    if (ret) {
        fprintf(stderr, "tmDebugOpenDefault: failed, ret=%d, %m\n", ret);
        return -1;
    }

    if (daemon_f)
    {
        if (daemon(0, 0) != 0)
        {
            ret = -2;
            goto close_debuglog;
        }
    }
    if (0 > write_pidfile(DEFAULT_PID_FILE, getpid()))
    {
        LOGERROR("%s: Error write pid file\n", PRAGNAME);
        ret = -3;
        goto close_debuglog;
    }
    if (NULL == (g_sys_log = tmSyslog_openlog(DEFAULT_SYSLOG_MODULE, NULL, &ret)) || 0 > ret)
    {
        LOGERROR("tmSyslog_openlog: failed, ret:%d, %m", ret);
        goto close_syslog;
    }
    if (g_sys_log->shm_ptr == (void*)-1) {
        g_sys_log->shm_ptr = NULL;
    }

    tmSyslog_setmask(g_sys_log, TM_LOG_UPTO(TM_SYSLOG_DEBUG));

    ret = filescand();

close_syslog:
    if (g_sys_log)
        tmSyslog_closelog(g_sys_log);
close_debuglog:
    tmDebugCloseDefault();
    if (f_mtrace) {
        muntrace();
    }

    unregister_printf_buffer();
    return ret;
}


