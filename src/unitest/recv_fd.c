#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/types.h>
#include <asm/types.h>

#define __LITTLE_ENDIAN_BITFIELD
#include "vsapi2_btscan.h"

#define BUF_LEN	(CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct timeval)))
#define IOV_LEN		9

int recv_fd(int s) 
{
	struct msghdr msg = {0};
	char cmsg_buf[BUF_LEN];  /* ancillary data buffer */
	struct iovec iov[IOV_LEN];
	int fd = -1, rc;
	struct cmsghdr *cmsg;
	struct btheader_npu2fpga hdr;
	unsigned short pid;
	unsigned int ver, sid, fid;
	unsigned char file_sha1[20];
	char filename[128];
	int i, size;
	loff_t truesize;
	int oversize;

	iov[0].iov_base = &hdr;
	iov[0].iov_len	= sizeof(hdr);
	iov[1].iov_base = &fid;
	iov[1].iov_len	= sizeof(fid);
	iov[2].iov_base = &pid;
	iov[2].iov_len	= sizeof(pid);
	iov[3].iov_base = &ver;
	iov[3].iov_len	= sizeof(ver);
	iov[4].iov_base = &sid;
	iov[4].iov_len	= sizeof(sid);
	iov[5].iov_base = &truesize;
	iov[5].iov_len	= sizeof(truesize);
	iov[6].iov_base = &oversize;
	iov[6].iov_len	= sizeof(oversize);
	iov[7].iov_base = file_sha1;
	iov[7].iov_len	= sizeof(file_sha1);
	iov[8].iov_base = filename;
	iov[8].iov_len	= sizeof(filename);

	for (i = 0, size= 0; i < IOV_LEN - 1; i++) {
		size +=  iov[i].iov_len;
	}
	

	msg.msg_name		= NULL;
	msg.msg_namelen		= 0;
	msg.msg_iov		= iov;
	msg.msg_iovlen		= IOV_LEN;
	msg.msg_control		= cmsg_buf;
	msg.msg_controllen	= sizeof(cmsg_buf);
	msg.msg_flags		= 0;

	rc = recvmsg(s, &msg, 0);

	if (rc <= 0 || rc <= size) {
		fprintf(stderr, "fail to recvmsg ret=%d\n", rc);
		return -1;
	}

	fprintf(stderr, "rc=%d fid=%u pid=%hu ver=%u sid=%u "
			"truesize=%ld oversize=%d filename=%s\n", 
			 rc, fid, pid, ver, sid, truesize, oversize, filename);

	/* Receive auxiliary data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&msg); 
	     cmsg != NULL; 
	     cmsg = CMSG_NXTHDR(&msg,cmsg)) {

		if (cmsg->cmsg_level == SOL_SOCKET) {

			if (cmsg->cmsg_type == SCM_RIGHTS && 
			   cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
				memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
			}
		}
	}

	return fd;
}

int server_sd(char *name) 
{
	int sd;
	int ulen;


	struct sockaddr_un sa = {
		.sun_family = AF_UNIX,
		.sun_path = "",
	};

	sd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0) {
		fprintf(stderr, "socket(PF_UNIX, SOCK_DGRAM, 0): %m\n");
		goto out;
	}

	ulen = snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1, "%s", name);

	if (bind(sd, (struct sockaddr*)&sa, 2 + 1 + ulen) < 0) {
		fprintf(stderr, "bind(\\0%s): %m\n", name);
		goto close_socket;
	}

	return sd;

close_socket:
	close(sd);
out:
	return sd;
}

int main(int argc, char **argv) 
{
	int sd;
	unsigned int serial = 0;
	int dump = 1;
	int ret;


	if (argc < 2) {
		printf("Usage:\n\trecv_fd NAME [noudmp]\n");
		ret = -1;
		goto out;
	}

	if (argc == 3 && !strcmp(argv[1], "nodump"))
		dump = 0;

	sd = server_sd(argv[1]);

	if (sd < 0) {
		ret = -2;
		goto out;
	} else {
        	printf("Listening on socket [\\0%s]\n", argv[1]);
	}

	for (;;) {
		int fd;
		ssize_t len, len2;
		char buf[4*1024];
		char name[1024];
		unsigned int size = 0;
		int fd2;
		
		memset(name, 0, sizeof(name));

		fd = recv_fd(sd);
		if (fd < 0) {
			fprintf(stderr, "fail to recv_fd\n");
			break;
		}
		fprintf(stderr, "recv_fd: fd=%d ...", fd);
		fflush(stderr);

		snprintf(name, sizeof(name), "file.%u", serial++);
		if (dump) {
			fd2 = open(name, O_WRONLY|O_CREAT|O_TRUNC, 0644);
			if (fd2 < 0) {
				fprintf(stderr, "fail to open [%s] %m\n", name);
				goto out;
			}
		}

		lseek(fd, 0, SEEK_SET);
		for (;;) {
			/* TODO: random size */
			len = read(fd, buf, sizeof(buf));
			if (len < 0) 
				fprintf(stderr, "Fail to read: %m\n");

			if (len <= 0) 
				break;

			size += len;

			if (dump) {
				if(len > 4*1024)
					len = 4*1024;
				len2 = write(fd2, buf, len);
				assert(len == len2);
			}
		}
		fprintf(stderr, "write %u bytes to [%s]\n\n", size, name);
		if (dump) {
			close(fd2);
		}
out:
		close(fd);
		
	}

	close(sd);
	return 0;
}
