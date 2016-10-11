#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "list.h"
#include "fs.h"
#include "vscan.h"

/****************************************************************************/
/* MACRO DECLARATIONS                                                       */
/****************************************************************************/
#define MAX_FILE_TRIGGER_SIZE   (16000)

#define SSID_BEGIN_OF_BLOCK     0x00
#define SSID_END_OF_BLOCK       0xff
#define SSID_FILE_INFO_BEGIN    0x11
#define SSID_FILE_INFO_MORE     0x12

#define SS_FIELD_SESSION_ID_OFF (2)
#define SS_FIELD_FLAG_OFF       (6)
#define SS_FIELD_DATA_OFF       (7)

#define TRIGGER_INFO_LEN        (16)

//#define TRID_FILE_ISPACKED      0x20c
#define TRID_FILE_NAME          0x20d
#define TRID_FILE_SIZE          0x20f
#define TRID_FILE_ARCHIVE_ISSTORE   0x215
#define TRID_FILE_SHA1_FROM_FILESCAN  0x0a5d
#define TRID_VSAPI1_AFI_PEINFO  0x7ea
#define TRID_VSAPI1_SYSCLEAN    0x7eb
#define TRID_FILE_ISOVERSIZED   0x7ed
#define TRID_VSAPI1_MAJORTYPE   0x7ee
#define TRID_VSAPI1_POTENTIALRISK  0x7ef
#define TRID_FILE_INFO_BEGIN    0x7f0
#define TRID_VSAPI1_VIRUS_NAME  0x7f1
#define TRID_VSAPI1_RETCODE     0x7f2
#define TRID_FILE_TRUETYPE      0x7f3
#define TRID_FILE_FCRC32        0x7f4
#define TRID_FILE_SCRIPTCRC     0x7f5
#define TRID_IS_LAYERED_ATTACH  0x7f6
#define TRID_SOFTMICE_POLYM     0x7f7
#define TRID_IS_MULTIPACKED     0x7f8
#define TRID_HAS_MACRO          0x7f9
#define TRID_ARCHIVE_FILENAME   0x7fa
#define TRID_ARCHIVE_FILESIZE   0x7fb
#define TRID_SOFTMICE_META      0x7fc
#define TRID_ARCHIVE_FCRC32     0x7fd
#define TRID_FILE_INFO_END      0x7fe
#define TRID_VSAPI1_DETECTION_LEVEL 0x7ff


#define TR_FIELD_BYTECOUNT_BIT  0x10
#define TR_FIELD_FRAGMENT_BIT   0x80
#define TR_FIELD_PID_OFF        (2) // offset of pattern id field
#define TR_FIELD_BYTECOUNT_OFF  (4) // offset of byte count field
#define TR_FIELD_DATA_OFF       (4) // offset of data field
#define TR_FIELD_DATA_B_OFF     (5) // offset of data field when byte count filed is turned on 

#define VEC_IDX_BOF             (0)
#define VEC_IDX_FILE_INFO       (1)
#ifdef TEST_WITH_TRIGGER_PARSE
#define VEC_IDX_EOF             (2)
#endif

/****************************************************************************/
/* STATIC GLOBAL VARIABLES                                                  */
/****************************************************************************/
static int set_session_info(unsigned char * buf, uint32_t sid, uint8_t flag, uint32_t data);

/****************************************************************************/
/* STATIC FNUCTION                                                          */
/****************************************************************************/
static int
handle_fi_virusinfo(
        int sd,
        cav_msg_t ** ppcavmsg,
        struct iovec tr[],
        unsigned int tr_len,
        thread_data_t * data,
        VirusResult * vr);

static trigger_buf_t * create_trigger_buf(struct iovec iov[], unsigned int iovlen)
{
    trigger_buf_t * tr_buf = NULL;
    int buf_len = 0;
    int i = 0;
    if (!iov || 0 >= iovlen) {
        LOGERROR("Invalid input argument, iov:%p, len:%u", iov, iovlen);
        return NULL;
    }
    
    for (i = 0; i < iovlen; i++) {
        buf_len += iov[i].iov_len;
    }
    tr_buf = calloc(1, sizeof(trigger_buf_t));
    if (!tr_buf) {
        LOGERROR("Failed to alloc trigger_buf_t!");
        return NULL;
    }

    tr_buf->piov[0].iov_base = calloc(1, buf_len);
    if (!tr_buf->piov[0].iov_base) {
        LOGERROR("Failed to alloc trigger_buf_t iov_base!");
        free(tr_buf);
        return NULL;
    }
    buf_len = 0;
    for (i = 0; i < iovlen; i++) {
        memcpy(tr_buf->piov[0].iov_base + buf_len, iov[i].iov_base, iov[i].iov_len);
        buf_len += iov[i].iov_len;
    }
    tr_buf->piov[0].iov_len = buf_len;
    list_head_init(&(tr_buf->list));
    LOGDEBUG("ALLOC:tr_buf:%p,buf:%p,len:%lu", tr_buf, tr_buf->piov[0].iov_base, tr_buf->piov[0].iov_len);
    return tr_buf;
}

static void free_trigger_buf(trigger_buf_t * tr_buf)
{
    if (!tr_buf) {
        LOGERROR("Invalid input argument");
        return;
    }
    LOGDEBUG("FREE:tr_buf:%p,buf:%p,len:%lu", tr_buf, tr_buf->piov[0].iov_base, tr_buf->piov[0].iov_len);
    if (tr_buf->piov[0].iov_base) {
        free(tr_buf->piov[0].iov_base);
        tr_buf->piov[0].iov_base = NULL;
    }
    free(tr_buf);
}

/*
 * create_cav_msg
 * Do call free_cav_msg after cav_msg is of no longer use
 */
static cav_msg_t * create_cav_msg(thread_data_t * data) 
{
    cav_msg_t * cav_msg = NULL;
    if (!data) {
        LOGERROR("Invalid input argument");
        return NULL;
    }
    
    cav_msg  = calloc(1, sizeof(cav_msg_t));
    if (!cav_msg) {
        LOGERROR("Failed to alloc cav_msg!");
        return NULL;
    }
    list_head_init(&(cav_msg->trigger_buf_list));
    cav_msg->id = data->file_id;
    cav_msg->fd = data->fd;
    LOGDEBUG("ALLOC:cav_msg:%p, fid:0x%08x, fd:%d", cav_msg, cav_msg->id, cav_msg->fd);
    return cav_msg;
}

/* 
 * free_cav_msg
 * input cav_msg_t must been detached from a list first
 */
static void free_cav_msg(void * data)
{
    list_head * ptr_list = NULL;
    list_head * ptr_next = NULL;
    
    assert(data);
    cav_msg_t * cav_msg = (cav_msg_t *)data;
    if (!cav_msg) {
        LOGERROR("Invalid input argument!");
        return ;
    }
    LOGDEBUG("FREE:cav_msg:%p, fid:0x%08x, fd:%d", cav_msg, cav_msg->id, cav_msg->fd);
    list_for_each_safe(ptr_list, ptr_next, &(cav_msg->trigger_buf_list)) {
        trigger_buf_t * tr_buf = list_entry(ptr_list, trigger_buf_t, list);
        list_del(ptr_list);
        free_trigger_buf(tr_buf);
    }
    close(cav_msg->fd);
    free(cav_msg);
}

/* 
 * queue_cav_msg
 * queue trigger data into a thread specific storage
 */
static int queue_cav_msg(cav_msg_t ** ppcavmsg, struct iovec iov[], unsigned int iovlen, thread_data_t * data) {
    int ret = 0;
    cav_msg_t * cavmsg = NULL;
    assert(ppcavmsg);

#ifndef TEST_WITH_TRIGGER_PARSE
    if (0 > (ret = set_session_info(iov[VEC_IDX_BOF].iov_base, data->file_id, SSID_FILE_INFO_MORE, 0))) {
        LOGERROR("set_session_info() FILE_INFO_MORE failed, ret:%d", ret);
    }
#endif 
    if (!(*ppcavmsg)) {
        cavmsg = create_cav_msg(data);
        if (!cavmsg) { // XXX FIXME cav would wait file id infinitely
            LOGERROR("Error allocate cav_msg_t");
            return -1;
        }
        *ppcavmsg = cavmsg;
    }
    else
        cavmsg = *ppcavmsg;
    if (cavmsg) {
        trigger_buf_t * tr_buf = create_trigger_buf(iov, iovlen);
        if (!tr_buf) {
            LOGERROR("Error allocate trigger_buf_t");
            ret = -2;
            free_cav_msg((void *)cavmsg);
            *ppcavmsg = NULL;
            return ret;
        }
        list_add_tail(&(tr_buf->list), &(cavmsg->trigger_buf_list));
    }
    return ret;
}

static int send_trigger(int s, thread_data_t* data, struct iovec iov[], unsigned int iovlen, int fd) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char cmsg_buf[CMSG_SPACE(sizeof(int))];  /* ancillary data buffer */

    msg.msg_name        = (void *)&data->cav_sockname;
    msg.msg_namelen     = data->cav_socklen;
    msg.msg_iov         = iov;
    msg.msg_iovlen      = iovlen;
    msg.msg_flags       = 0;
    
    if(0 <= fd) {
        msg.msg_control     = cmsg_buf;
        msg.msg_controllen  = sizeof(cmsg_buf);

        cmsg                = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level    = SOL_SOCKET;
        cmsg->cmsg_type     = SCM_RIGHTS;
        cmsg->cmsg_len      = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    }
    else {
        msg.msg_control     = NULL;
        msg.msg_controllen  = 0;
    }

    if(sendmsg(s, &msg, MSG_NOSIGNAL) < 0) {
	LOGDEBUG("send_trigger: sendmsg failed, error: %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
	return -1;
    }
    return 0;
}

static int send_trigger_cav_msg(int s, thread_data_t* data, cav_msg_t * cavmsg)
{
    list_head * ptr_list = NULL;
    list_head * ptr_next = NULL;
    int fd = 0;
    int ret = 0;
    
    if(!cavmsg || 0 == &cavmsg->trigger_buf_list) { 
        LOGERROR("Invalid input argument, cavmsg:%p, sid=0x%08x, pid=%d, qid=%s", cavmsg, data->session_id, data->pattern_id, data->qid);
        return -1;
    }
    ptr_list = &cavmsg->trigger_buf_list;
    fd = cavmsg->fd;
    list_for_each_safe(ptr_list, ptr_next, &(cavmsg->trigger_buf_list)) {
        trigger_buf_t * tr_buf = list_entry(ptr_list, trigger_buf_t, list);
        if (list_is_tail(ptr_list, &(cavmsg->trigger_buf_list))) {
            if (0 > (ret = send_trigger(s, data, tr_buf->piov, 1, fd))) {
                LOGDEBUG("Error sendmsg, %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                return ret;
            }
		}
		else {
			if (0 > (ret = send_trigger(s, data, tr_buf->piov, 1, -1))) {
				LOGDEBUG("Error sendmsg, %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
				return ret;
			}
		}
	}

	return ret;
}

static int
send_cav(int s, cav_msg_t **ppcavmsg, struct iovec iov[], unsigned int iovlen, thread_data_t *data) 
{
    assert(ppcavmsg);

    int        ret    = 0;
    cav_msg_t* cavmsg = *ppcavmsg;

    *ppcavmsg = NULL;

    if (cavmsg) {
	/* queued trigger buf in fs_cav stack, means this is last */
#ifndef TEST_WITH_TRIGGER_PARSE
        if (0 > (ret = set_session_info(iov[VEC_IDX_BOF].iov_base, data->file_id, SSID_FILE_INFO_BEGIN, 0))) {
            LOGERROR("set_session_info() FILE_INFO_BEGIN failed, ret:%d, sid=0x%08x, pid=%d, qid=%s", ret, data->session_id, data->pattern_id, data->qid);
        }
#endif
        trigger_buf_t* tr_buf = create_trigger_buf(iov, iovlen);
        if (!tr_buf) {
            LOGERROR("Failed to allocate trigger_buf, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
            free_cav_msg(cavmsg);
            return -1;
        }
        list_add_tail(&(tr_buf->list), &(cavmsg->trigger_buf_list));

	send_trigger_cav_msg(s, data, cavmsg);
	LOGDEBUG("send_trigger_with_fid: 0x%08x, 0x%08x, sid=0x%08x, pid=%d, qid=%s", data->file_id, cavmsg->id, data->session_id, data->pattern_id, data->qid);
	free_cav_msg((void *)cavmsg);
	cavmsg = NULL;
    } else {
	LOGDEBUG("send_trigger_with_fid: 0x%08x, sid=0x%08x, pid=%d, qid=%s", data->file_id, data->session_id, data->pattern_id, data->qid);
	send_trigger(s, data, iov, iovlen, data->fd);
	close(data->fd);
	data->fd = -1;
    }
    return ret;
}

static int
set_session_info(unsigned char * buf, uint32_t sid, uint8_t flag, uint32_t data)
{
    if (!buf)
        return -1;
    __set_B16(buf, 0xffff);
    __set_B32(buf+SS_FIELD_SESSION_ID_OFF, sid);
    __set_B8(buf+SS_FIELD_FLAG_OFF, flag);
//    __set_B32(buf+TR_FIELD_DATA_B_OFF, data);

    return 0;
}

static int
set_ndword_trigger(unsigned char * buf, int tid, uint16_t pid, uint32_t data)
{
    if (!buf)
        return -1;
    __set_B16(buf, tid);
    __set_B16(buf+TR_FIELD_PID_OFF, pid);
    *buf |= TR_FIELD_BYTECOUNT_BIT;  // turn on byte count bit
    __set_B8(buf+TR_FIELD_BYTECOUNT_OFF, 4);
    __set_B32(buf+TR_FIELD_DATA_B_OFF, data);

    return 0;
}

/*
 * set_string_trigger
 * INPUT buf the buffer to be setting trigger data
 * INPUT tid the trigger id
 * INPUT pid the pattern id
 * INPUT data the buffer of data string
 * INPUT len the length of data string
 * RETURN the length of data string put in trigger, 
 *       >0:normal return, <0:error
 */
static int
set_string_trigger(unsigned char * buf, int tid, uint16_t pid, unsigned char * data, int len)
{
    int ret = 0;
    if (!buf || !data || 0 >= len)
        return -1;
    __set_B16(buf, tid);
    __set_B16(buf+TR_FIELD_PID_OFF, pid);
    if (12 <= len) // max data field length compare to len
    {
        memcpy(buf+TR_FIELD_DATA_OFF, data, 12);
        if (12 < len)
            *buf |= TR_FIELD_FRAGMENT_BIT;  // turn on more fragment bit, caller has to call set_string_trigger again
        ret = 12;
    }
    else
    {
        *buf |= TR_FIELD_BYTECOUNT_BIT;  // turn on byte count bit
        __set_B8(buf+TR_FIELD_BYTECOUNT_OFF, len);
        memcpy(buf+TR_FIELD_DATA_B_OFF, data, len);
        ret = len;
    }

    return ret;
}

static int
handle_fi_delimiter(
        int sd,
        struct iovec tr[],
        thread_data_t * data)
{
    int ret = 0;
    LOGDEBUG("++ handle_fi_delimiter ++");
    if (-1 == sd || !tr || !data)
        return -1;
#ifdef TEST_WITH_TRIGGER_PARSE
    if (0 > (ret = set_session_info(tr[VEC_IDX_BOF].iov_base, 0, SSID_BEGIN_OF_BLOCK, 0))) {
        LOGERROR("set_session_info() BEGIN_OF_BLOCK failed, ret:%d", ret);
    }
    if (0 > (ret = set_session_info(tr[VEC_IDX_EOF].iov_base, 0, SSID_END_OF_BLOCK, 0))) {
        LOGERROR("set_session_info() END_OF_BLOCK failed, ret:%d", ret);
    }
#else
    if (0 > (ret = set_session_info(tr[VEC_IDX_BOF].iov_base, data->file_id, SSID_FILE_INFO_BEGIN, 0))) {
        LOGERROR("set_session_info() FILE_INFO_BEGIN failed, ret:%d", ret);
    }
#endif
    LOGDEBUG("-- handle_fi_delimiter --");
    return ret;
}

typedef enum enum_fileinfo_type_t {
    ENUM_FILEINFO_TYPE_SHA1=0,
    ENUM_FILEINFO_TYPE_FILE_TRUETYPE,
    ENUM_FILEINFO_TYPE_IS_STORE,
    ENUM_FILEINFO_TYPE_FILE_NAME,
    ENUM_FILEINFO_TYPE_FILE_SIZE,
    ENUM_FILEINFO_TYPE_VSAPI1_RETCODE,
    ENUM_FILEINFO_TYPE_PE_FILE_INFO,
    ENUM_FILEINFO_TYPE_NONE, 
} enum_fileinfo_type;


#ifdef USE_ATSE
static int
handle_fi_fileinfo(
        int sd,
        cav_msg_t ** ppcavmsg,
        struct iovec tr[],
        unsigned int tr_len,
        thread_data_t * data,
        scan_evae_result_t * er)
{
    int ret = 0;
    int leave = 0;
    unsigned char * buf;
    size_t *plen;
    int max_size;
    uint16_t ptn_id = data->pattern_id;
    scan_evae_result_node_t *en = NULL;
    enum_fileinfo_type type;
    struct list_head *iter;
    int first_layer;
    static const unsigned char dummy_sha1[20] = {0};

    assert(ppcavmsg);
    LOGDEBUG("++ handle_fi_fileinfo ++, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
    if (-1 == sd || !tr || !data || !er || !tr[1].iov_base)
        return -1;
    if (0 >= (max_size = sizeof(tr[VEC_IDX_FILE_INFO].iov_base)))
        return -1;
    buf = tr[VEC_IDX_FILE_INFO].iov_base + tr[VEC_IDX_FILE_INFO].iov_len;
    plen = &tr[1].iov_len;
    
    // working with buf & plen
    //   1. plen is safe now
    //   2. append to buffer
    //   3. check the plen for flush

    if(!list_empty(&er->list_head)) {
        en = list_entry(er->list_head.next, scan_evae_result_node_t, list_node);
        first_layer = en->layer;
        list_for_each(iter, &er->list_head) {
            en = list_entry(iter, scan_evae_result_node_t, list_node);

            if (0 > (ret = set_ndword_trigger(buf, TRID_FILE_INFO_BEGIN, ptn_id, en->layer))) {
                LOGWARN("set_ndword_trigger() failed, TRID_FILE_INFO_BEGIN, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                break;
            }
            *plen += TRIGGER_INFO_LEN;
            buf += TRIGGER_INFO_LEN;
            if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                    LOGERROR("queue_cav_msg(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                }
                buf = tr[VEC_IDX_FILE_INFO].iov_base;
                *plen = 0;
            }

            //LOGDEBUG("Begin Dump Trigger layer:%d, fname:%s", en->layer, en->file_name);
            type = ENUM_FILEINFO_TYPE_SHA1;
            leave = 0;
            while(!leave) {
                switch (type) {
                    case ENUM_FILEINFO_TYPE_SHA1:
                        if(memcmp(en->sha1, dummy_sha1, 20) != 0) {
                            //check available space for at least two fragments to fit a SHA1.
                            unsigned char *sha1 = en->sha1;
                            int sha1_len=SHA_DIGEST_LENGTH;

                            LOGDEBUG("sha1 = %20b", sha1);
                            while(0<sha1_len) {
                                if(0>(ret=set_string_trigger(buf, TRID_FILE_SHA1_FROM_FILESCAN, ptn_id, sha1, sha1_len))) {
                                    LOGWARN("set_string_trigger() failed, TRID_FILE_SHA1_FROM_FILESCAN");
                                    leave = 1;
                                    break;
                                }

                                sha1+=ret;
                                sha1_len-=ret;
                                buf += TRIGGER_INFO_LEN;
                                *plen += TRIGGER_INFO_LEN;

                                if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                                    if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                                        LOGERROR("queue_cav_msg(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                    }
                                    buf = tr[VEC_IDX_FILE_INFO].iov_base;
                                    *plen = 0;
                                }
                            }
                        } else {
                            LOGDEBUG("Skipped empty SHA1, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                        }
                        type = ENUM_FILEINFO_TYPE_FILE_TRUETYPE;
                        break;
                    case ENUM_FILEINFO_TYPE_FILE_TRUETYPE:
                        /*
                         * Sam Tsai 2006/07/19
                         * combine file_type and file_sub_type in 
                         * payload of trigger
                         */
                        {
                            uint32_t composite_filetype = en->file_type << 16;
                            composite_filetype |= en->file_sub_type;
                            if (0 > (ret = set_ndword_trigger(buf, TRID_FILE_TRUETYPE, ptn_id, composite_filetype))) {
                                LOGWARN("set_ndword_trigger() failed, TRID_FILE_TRUETYPE, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                leave = 1;
                                break;
                            }
                        }
                        *plen += TRIGGER_INFO_LEN;
                        buf += TRIGGER_INFO_LEN;
                        type = ENUM_FILEINFO_TYPE_IS_STORE;
                        break;
                    case ENUM_FILEINFO_TYPE_IS_STORE:
                        if (en->isStore) {
                            if (0 > (ret = set_ndword_trigger(buf, TRID_FILE_ARCHIVE_ISSTORE, ptn_id, en->isStore))) {
                                LOGWARN("set_ndword_trigger() failed, TRID_FILE_ARCHIVE_ISSTORE, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                leave = 1;
                                break;
                            }
                            *plen += TRIGGER_INFO_LEN;
                            buf += TRIGGER_INFO_LEN;
                        }
                        type = ENUM_FILEINFO_TYPE_FILE_SIZE;
                        break;
                    case ENUM_FILEINFO_TYPE_FILE_SIZE:
                        /* 2006.08.01 Sam Tsai
                         * Send file size trigger no matter layer, because 
                         * fpga pattern may not be able to send the file size 
                         */
                        if (0 > (ret = set_ndword_trigger(buf, TRID_FILE_SIZE, ptn_id, en->file_size))) {
                            LOGWARN("set_ndword_trigger() failed, TRID_FILE_SIZE, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                            leave = 1;
                            break;
                        }
                        *plen += TRIGGER_INFO_LEN;
                        buf += TRIGGER_INFO_LEN;

                        type = ENUM_FILEINFO_TYPE_PE_FILE_INFO;
                        break;
                     case ENUM_FILEINFO_TYPE_PE_FILE_INFO:
                        if(en->pe_flags) {
                           LOGDEBUG("set_ndword_trigger() , TRID_VSAPI1_AFI_PEINFO, pe_flags = %d", en->pe_flags);
                           if (0 > (ret = set_ndword_trigger(buf, TRID_VSAPI1_AFI_PEINFO, ptn_id, en->pe_flags))) {
                              LOGWARN("set_ndword_trigger() failed, TRID_VSAPI1_AFI_PEINFO, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                              leave = 1;
                              break;
                           }
                           *plen += TRIGGER_INFO_LEN;
                           buf += TRIGGER_INFO_LEN;
                        }
                        type = ENUM_FILEINFO_TYPE_FILE_NAME;
                        break;
                     case ENUM_FILEINFO_TYPE_FILE_NAME:
                        if (0 < en->layer) {
                            LOGDEBUG("++ ENUM_FILEINFO_TYPE_FILE_NAME ++, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                            int name_len;
                            if (0 < (name_len = strlen(en->file_name))) {
                                unsigned char * arc_filename = (unsigned char*) en->file_name;
                                while (0 < name_len) {
                                    if (0 > (ret = set_string_trigger(buf, TRID_FILE_NAME, ptn_id, arc_filename, name_len))) {
                                        LOGWARN("set_string_trigger() failed, TRID_FILE_NAME, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                        leave = 1;
                                        break;
                                    }

                                    arc_filename += ret;
                                    name_len -= ret;
                                    buf += TRIGGER_INFO_LEN;
                                    *plen += TRIGGER_INFO_LEN;
                                    if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                                        if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                                            LOGERROR("queue_cav_msg(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                        }
                                        buf = tr[VEC_IDX_FILE_INFO].iov_base;
                                        *plen = 0;
                                    }
                                }

                            }
                            LOGDEBUG("-- ENUM_FILEINFO_TYPE_FILE_NAME --, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                        }
                        type = ENUM_FILEINFO_TYPE_VSAPI1_RETCODE;
                        break;
                    case ENUM_FILEINFO_TYPE_VSAPI1_RETCODE:
                        if (0 > en->ret_code) {
                            LOGDEBUG("ENUM_FILEINFO_TYPE_VSAPI1_RETCODE: %d, sid=0x%08x, pid=%d, qid=%s", en->ret_code, data->session_id, data->pattern_id, data->qid);
                            if (0 > (ret = set_ndword_trigger(buf, TRID_VSAPI1_RETCODE, ptn_id, en->ret_code))) {
                                LOGWARN("set_ndword_trigger() failed, TRID_VSAPI1_RETCODE, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                leave = 1;
                                break;
                            }

                            *plen += TRIGGER_INFO_LEN;
                            buf += TRIGGER_INFO_LEN;
                            if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                                if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                                    LOGERROR("queue_cav_msg(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                }
                                buf = tr[VEC_IDX_FILE_INFO].iov_base;
                                *plen = 0;
                            }
                        }
                        else {
                            if (en->vr) {
                                //LOGDEBUG("handle_fi_virusinfo(), layer:%d, fname:%s, vname:%s, tr:%p, qtrlen:%d", en->layer, en->file_name, en->vr->virusname, tr, tr[1].iov_len);
                                if (0 > (ret = handle_fi_virusinfo(sd, ppcavmsg, &tr[0], tr_len, data, en->vr))) {
                                    LOGERROR("handle_fi_virusinfo(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                                }
                                buf = tr[VEC_IDX_FILE_INFO].iov_base + tr[VEC_IDX_FILE_INFO].iov_len;
                            }
                        }
                        LOGDEBUG("End Dump Trigger layer:%d, fname:%s, sid=0x%08x, pid=%d, qid=%s", en->layer, en->file_name, data->session_id, data->pattern_id, data->qid);
                        type = ENUM_FILEINFO_TYPE_NONE;
                        leave = 1;
                        break;
                    case ENUM_FILEINFO_TYPE_NONE:
                        leave = 1;
                        break ;
                    default:
                        LOGERROR("invalid type in handle_fi_fileinfo(), type:%d, sid=0x%08x, pid=%d, qid=%s", type, data->session_id, data->pattern_id, data->qid);
                        break;
                }
                if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                    if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                        LOGERROR("queue_cav_msg(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                    }
                    buf = tr[VEC_IDX_FILE_INFO].iov_base;
                    *plen = 0;
                }
            }
            {
                int now_layer = en->layer;
                int next_layer = 0;
                if (en->list_node.next!=&er->list_head) {
                    next_layer = list_entry(en->list_node.next, scan_evae_result_node_t, list_node)->layer;
                } else {
                    next_layer = first_layer;
                }
                while (now_layer >= next_layer) {
                    if (0 > (ret = set_ndword_trigger(buf, TRID_FILE_INFO_END, ptn_id, now_layer))) {
                        LOGWARN("set_ndword_trigger() failed, TRID_FILE_INFO_END, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                        break;
                    }
                    *plen += TRIGGER_INFO_LEN;
                    buf += TRIGGER_INFO_LEN;
                    if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                        if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                            LOGERROR("queue_cav_msg(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
                        }
                        buf = tr[VEC_IDX_FILE_INFO].iov_base;
                        *plen = 0;
                    }
                    --now_layer;
                }
            }
        }
    }
    LOGDEBUG("-- handle_fi_fileinfo --, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
    return ret;
}
#endif

typedef enum enum_virusinfo_type_t {
    ENUM_VIRUSINFO_TYPE_MAJORTYPE=0,
    ENUM_VIRUSINFO_TYPE_VIRUS_MAYBE,
    ENUM_VIRUSINFO_TYPE_DETECTION_LEVEL,
    ENUM_VIRUSINFO_TYPE_VIRUS_NAME,
    ENUM_VIRUSINFO_TYPE_SYSCLEAN,
    ENUM_VIRUSINFO_TYPE_NONE,
} enum_virusinfo_type;

static int
handle_fi_virusinfo(
        int sd,
        cav_msg_t ** ppcavmsg,
        struct iovec tr[],
        unsigned int tr_len,
        thread_data_t * data,
        VirusResult * vr)
{
    int ret = 0;
    unsigned char * buf;
    size_t *plen;
    VirusResult * vr_ptr;
    int leave = 0;

    assert(ppcavmsg);
    enum_virusinfo_type type = ENUM_VIRUSINFO_TYPE_MAJORTYPE;
    LOGDEBUG("++ handle_fi_virusinfo ++");
    if (-1 == sd || !tr || !data || !vr)
        return -1;
    
    buf = tr[VEC_IDX_FILE_INFO].iov_base + tr[VEC_IDX_FILE_INFO].iov_len;
    plen = &tr[VEC_IDX_FILE_INFO].iov_len;
    vr_ptr = vr;

    if (!vr_ptr->virusname) {
        LOGDEBUG("-- handle_fi_virusinfo --");
        return ret;
    }
    leave = 0;
    type = ENUM_VIRUSINFO_TYPE_MAJORTYPE;
    while(!leave) {
        switch (type) {
            case ENUM_VIRUSINFO_TYPE_MAJORTYPE:
                {
                    int type_len = strlen(vr_ptr->majortype);
                    unsigned char * type_ptr = (unsigned char*) vr_ptr->majortype;
                    //if (0 < type_len)
                    //    LOGDEBUG("Dump virus majortype");
                    while (0 < type_len) {
                        if (0 > (ret = set_string_trigger(buf, TRID_VSAPI1_MAJORTYPE, data->pattern_id, type_ptr, type_len))) {
                            LOGERROR("set_string_trigger() failed, ret:%d", ret);
                        }
                        else {
                            buf += TRIGGER_INFO_LEN;
                            *plen += TRIGGER_INFO_LEN;
                            type_ptr += ret;
                            type_len -= ret;
                        }

                        if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                            if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                                LOGERROR("queue_cav_msg(): %m");
                            }
                            buf = tr[VEC_IDX_FILE_INFO].iov_base;
                            *plen = 0;
                        }
                    }
                    type = ENUM_VIRUSINFO_TYPE_VIRUS_MAYBE;
                    break;
                }
            case ENUM_VIRUSINFO_TYPE_VIRUS_MAYBE:
                //LOGDEBUG("Dump virus maybe");
                if (0 > (ret = set_ndword_trigger(buf, TRID_VSAPI1_POTENTIALRISK, data->pattern_id, vr->virus_maybe))) {
                    LOGERROR("set_ndword_trigger() failed, ret:%d", ret);
                }
                else {
                    buf += TRIGGER_INFO_LEN;
                    *plen += TRIGGER_INFO_LEN;
                }
                type = ENUM_VIRUSINFO_TYPE_SYSCLEAN;
                break;
            case ENUM_VIRUSINFO_TYPE_SYSCLEAN:
                //LOGDEBUG("Dump sysclean: %d", vr->system_clean);
                if (0 > (ret = set_ndword_trigger(buf, TRID_VSAPI1_SYSCLEAN, data->pattern_id, vr->system_clean))) {
                    LOGERROR("set_ndword_trigger(TRID_VSAPI1_SYSCLEAN) failed, ret:%d", ret);
                }
                else {
                    buf += TRIGGER_INFO_LEN;
                    *plen += TRIGGER_INFO_LEN;
                }
                type = ENUM_VIRUSINFO_TYPE_DETECTION_LEVEL;
                break;
            case ENUM_VIRUSINFO_TYPE_DETECTION_LEVEL:
                //LOGDEBUG("Dump Detection Level: %d", vr->detection_level);
                if (0 > (ret = set_ndword_trigger(buf, TRID_VSAPI1_DETECTION_LEVEL, data->pattern_id, vr->detection_level))) {
                    LOGERROR("set_ndword_trigger(TRID_VSAPI1_DETECTION_LEVEL) failed, ret:%d", ret);
                }
                else {
                    buf += TRIGGER_INFO_LEN;
                    *plen += TRIGGER_INFO_LEN;
                }
                type = ENUM_VIRUSINFO_TYPE_VIRUS_NAME;
                break;
            case ENUM_VIRUSINFO_TYPE_VIRUS_NAME:
                {
                    /* 2009.02.06 Sam Tsai
                     * Keep virus name as the last state
                     * CAV would insert a vsapi log when receiving a VIRUS_NAME
                     * if any other trigger before VIRUS_NAME, those trigger would not be in that log
                     */
                    int name_len = strlen(vr_ptr->virusname);
                    unsigned char * name_ptr = (unsigned char*) vr_ptr->virusname;
                    //if (0 < name_len)
                    //    LOGDEBUG("Dump virus name");
                    while (0 < name_len) {
                        if (0 > (ret = set_string_trigger(buf, TRID_VSAPI1_VIRUS_NAME, data->pattern_id, name_ptr, name_len))) {
                            LOGERROR("set_string_trigger() failed, ret:%d", ret);
                        }
                        else {
                            buf += TRIGGER_INFO_LEN;
                            *plen += TRIGGER_INFO_LEN;
                            name_ptr += ret;
                            name_len -= ret;
                        }

                        if (MAX_FILE_TRIGGER_SIZE <= *plen) {
                            if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                                LOGERROR("queue_cav_msg(): %m");
                            }
                            buf = tr[VEC_IDX_FILE_INFO].iov_base;
                            *plen = 0;
                        }
                    }
                    type = ENUM_VIRUSINFO_TYPE_NONE;
                    leave = 1;
                    break;
                }
            case ENUM_VIRUSINFO_TYPE_NONE:
                leave = 1;
                break;
            default:
                LOGERROR("Invalid virusinfo type, type:%d", type);
                break;
        }
        if (MAX_FILE_TRIGGER_SIZE <= *plen) {
            if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                LOGERROR("queue_cav_msg(): %m");
            }
            buf = tr[VEC_IDX_FILE_INFO].iov_base;
            *plen = 0;
        }
    }
    LOGDEBUG("-- handle_fi_virusinfo --");
    return ret;
}

static int
handle_oversized(
        int sd,
        cav_msg_t ** ppcavmsg,
        struct iovec tr[],
        unsigned int tr_len,
        thread_data_t * data)
{
    int ret = 0;
    unsigned char * buf;
    size_t *plen;
    int max_size;
    uint16_t ptn_id;

    assert(ppcavmsg);
    LOGDEBUG("++ handle_oversized ++");
    if (-1 == sd || !tr || !data || !tr[VEC_IDX_FILE_INFO].iov_base)
        return -1;
    if (0 >= (max_size = sizeof(tr[VEC_IDX_FILE_INFO].iov_base)))
        return -1;

    ptn_id = data->pattern_id;
    buf = tr[VEC_IDX_FILE_INFO].iov_base + tr[VEC_IDX_FILE_INFO].iov_len;
    plen = &tr[VEC_IDX_FILE_INFO].iov_len;

    {
        if (0 > (ret = set_ndword_trigger(buf,
                        TRID_FILE_INFO_BEGIN,
                        ptn_id,
                        0))) {
            LOGWARN("set_ndword_trigger() failed, TRID_FILE_INFO_BEGIN");
        }
        *plen += TRIGGER_INFO_LEN;
        buf += TRIGGER_INFO_LEN;
        if (0 > (ret = set_ndword_trigger(buf,
                        TRID_FILE_SIZE,
                        ptn_id,
                        data->file_size))) {
            LOGWARN("set_ndword_trigger() failed, TRID_FILE_SIZE");
        }
        *plen += TRIGGER_INFO_LEN;
        buf += TRIGGER_INFO_LEN;
        if (0 > (ret = set_ndword_trigger(buf,
                        TRID_FILE_ISOVERSIZED,
                        ptn_id,
                        data->over_sized))) {
            LOGWARN("set_ndword_trigger() failed, TRID_FILE_ISOVERSIZED");
        }
        *plen += TRIGGER_INFO_LEN;
        buf += TRIGGER_INFO_LEN;
        if (0 > (ret = set_ndword_trigger(buf,
                        TRID_FILE_INFO_END,
                        ptn_id,
                        0))) {
            LOGWARN("set_ndword_trigger() failed, TRID_FILE_INFO_END");
        }
        *plen += TRIGGER_INFO_LEN;
        buf += TRIGGER_INFO_LEN;
        if (MAX_FILE_TRIGGER_SIZE <= *plen) {
            if (0 > queue_cav_msg(ppcavmsg, tr, tr_len, data)) {
                LOGERROR("queue_cav_msg(): %m");
            }
            buf = tr[1].iov_base;
            *plen = 0;
        }
    }
    LOGDEBUG("-- handle_oversized --");
    return ret;
}

int
fs_cav(
        VirusResult *vr,
#ifdef USE_ATSE
        scan_evae_result_t *er,
#endif
        thread_data_t *data,
        unsigned char *sha1)
{
    int ret = 0;
    cav_msg_t * cavmsg = NULL;
#ifdef TEST_WITH_TRIGGER_PARSE
    struct iovec piov[3];
#else
    struct iovec piov[2];
#endif
    int sd = 0;
    unsigned int piov_len = sizeof(piov)/sizeof(piov[0]);
    unsigned char bofi[16] = {0};
    unsigned char fileinfo[MAX_FILE_TRIGGER_SIZE] = {0};
#ifdef TEST_WITH_TRIGGER_PARSE
    unsigned char eofi[16] = {0};
#endif
LOGDEBUG("++ fs_cav ++, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
    if (!data)
        return -1;
    
    sd = data->cav_sd;

    if(sd==-1) {
        LOGERROR("alloc_cav_sd(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
        return -1;
    }

    piov[VEC_IDX_BOF].iov_base = bofi;
    piov[VEC_IDX_BOF].iov_len = sizeof(bofi);
    piov[VEC_IDX_FILE_INFO].iov_base = fileinfo;
    piov[VEC_IDX_FILE_INFO].iov_len = 0;
#ifdef TEST_WITH_TRIGGER_PARSE
    piov[VEC_IDX_EOF].iov_base = eofi;
    piov[VEC_IDX_EOF].iov_len = sizeof(eofi);
#endif
    /*
     * Initialize bofi and eofi
     */
    if (0 > (ret = handle_fi_delimiter(sd, piov, data))) {
        LOGERROR("handle_fi_delimiter(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
    }

    if (data->over_sized && 0 > (ret = handle_oversized(sd, &cavmsg, piov, piov_len, data))) {
        LOGERROR("handle_oversized(): ret=%d, sid=0x%08x, pid=%d, qid=%s", ret, data->session_id, data->pattern_id, data->qid);
    }
    else {
        /*
         * Generate and send trigger content related to file information
         */
#ifdef USE_ATSE
        if (er && 0 > (ret = handle_fi_fileinfo(sd, &cavmsg, piov, piov_len, data, er))) {
            LOGERROR("handle_fi_fileinfo(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
        }
#endif
    }

#if 0
    /* 2006.07.28 Sam Tsai
     * Generate virus info in each file info
     */
    /*
     * Generate and send trigger content related to virus information
     */
    if (vr && 0 > (ret = handle_fi_virusinfo(sd, &cavmsg, piov, piov_len, data, vr))) {
        LOGERROR("handle_fi_virusinfo(): %m");
    }
#endif

    /*
     * Send out trigger only when there are content
     */
    if (0 > send_cav(sd, &cavmsg, piov, (0 < piov[VEC_IDX_FILE_INFO].iov_len)?piov_len:1, data)) {
        LOGERROR("send_cav(): %m, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
    }
#ifdef DEBUG
    if (cavmsg) {
        LOGFATAL("Leaving with thread specific cavmsg not NULL!, cavmsg:%p, sid=0x%08x, pid=%d, qid=%s", cavmsg, data->session_id, data->pattern_id, data->qid);
    }    
#endif
    LOGDEBUG("-- fs_cav --, sid=0x%08x, pid=%d, qid=%s", data->session_id, data->pattern_id, data->qid);
    return ret;
}
