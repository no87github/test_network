#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include "openssl/sha.h"

#define __LITTLE_ENDIAN_BITFIELD

#include "vsapi2_btscan.h"

#define PRAGNAME "send_fsd"

int gover_sized = 0;
long long gfile_size = 0;

int send_fsd(int s, int fd, int queue, char *data_buf, size_t data_buf_len, uint32_t file_id, unsigned char *file_sha1) {
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	char cmsg_buf[CMSG_SPACE(sizeof(int))];  /* ancillary data buffer */
	struct sockaddr_un sa = {
		.sun_family = AF_UNIX,
		.sun_path = "\0"
	};
	struct iovec iov[10];
	struct btheader_npu2fpga sinfo = {
		.msg_type = 0x0,
		.res = {0x00, 0x00, 0x00},
		.npu_session_id = 0x0,
		.fpga_session_id = 0x0,
		.fpga_scan_direction = 0x0,
		.fpga_session_id1 = 0x0,
		.server_mac = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		.client_mac = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		.physical_port = 0x1,
		.vlan_tag = 0x0,
		.client_ip = 0x01020304,
		.client_port = 0x0900,
		.server_port = 0x0800,
		.server_ip = 0x04030201,
		.block_offset = 0x0,
		.end_of_session = 0x0,
		.res1 = 0x0,
		.block_length = 0x0,
	};
	uint16_t pattern_id = 0x1111;
	uint32_t pattern_ver = 0x2222;
	uint32_t session_id = 0x3333;

	iov[0].iov_base = &sinfo;
	iov[0].iov_len  = sizeof(sinfo);
	iov[1].iov_base = &file_id;
	iov[1].iov_len  = sizeof(file_id);
	iov[2].iov_base = &pattern_id;
	iov[2].iov_len  = sizeof(pattern_id);
	iov[3].iov_base = &pattern_ver;
	iov[3].iov_len  = sizeof(pattern_ver);
	iov[4].iov_base = &session_id;
	iov[4].iov_len  = sizeof(session_id);
	iov[5].iov_base = &gfile_size;
	iov[5].iov_len  = sizeof(gfile_size);
	iov[6].iov_base = &gover_sized;
	iov[6].iov_len  = sizeof(gover_sized);
	iov[7].iov_base = file_sha1;
	iov[7].iov_len  = SHA_DIGEST_LENGTH;
	iov[8].iov_base = "FSE:";
	iov[8].iov_len  = 4;
	iov[9].iov_base = data_buf;
	iov[9].iov_len	= data_buf_len;

	snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1, "%s%02d", "FSE", queue);

	msg.msg_name		= &sa;
	msg.msg_namelen		= 8; //sizeof(sa);
	msg.msg_iov			= iov;
	msg.msg_iovlen		= sizeof(iov)/sizeof(iov[0]);
	msg.msg_control		= cmsg_buf;
	msg.msg_controllen	= sizeof(cmsg_buf);

	cmsg				= CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level	= SOL_SOCKET;
	cmsg->cmsg_type		= SCM_RIGHTS;
	cmsg->cmsg_len		= CMSG_LEN(sizeof(int));

	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	return sendmsg(s, &msg, 0);
}

int client_sd() {
	int sd;

	sd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if(sd == -1) {
		fprintf(stderr, "socket(PF_UNIX, SOCK_DGRAM, 0): %m\n");
		return -1;
	}

	return sd;
}

	static void 
usage(const char *prg) 
{
	fprintf(stderr, 
			"Usage: %s -q QUEUE [-i <FID>] -f <FILE_PATH>\n"
			"  -q <QUEUE>,          Queue id.\n"
			"  -i <FID>,            Optional, assign fid.\n"
			"  -f <FILE_PATH>,      File path sent to filescan.\n"
			"  -s <FILE_SHA1>,      File sha1 sent to filescan in hexdecimal string.\n"
			"  -h, --help           print this help.\n",
			prg);
}

int main(int argc, char *argv[]) {
	int sd;
	char *filename = NULL;
	char *file_sha1_param = NULL;
	unsigned char file_sha1[SHA_DIGEST_LENGTH] = {0};
	char file_sha1_hexstr[SHA_DIGEST_LENGTH * 2 + 1] = {0};
	int queue = -1;

	int c;
	uint32_t fid = 0;
	int fd = -1;
        struct stat st;
	if(argc == 1) {
		usage(PRAGNAME);
		return 1;
	}
	sd = client_sd();
	if(sd==-1) {
		fprintf(stderr, "client_sd(): %m\n");
		return 3;
	}
	while (-1 != (c = getopt(argc, argv, "q:i:f:s:h")))
	{
		switch (c)
		{
			case 'i':
				fid = strtoul(optarg, 0, 0);
				fprintf(stderr, "fid: 0x%08x\n", fid);
				break;
			case 'f':
				filename = optarg;
				break;
			case 's':
				file_sha1_param = optarg;
				break;
			case 'q':
				queue = atoi(optarg);
				break;
			case 'h':
			default:
				{
					usage(PRAGNAME);
					exit(0);
				}
		}
	}
	if(!filename || (queue < 0)) {
		usage(PRAGNAME);
		exit(0);
	}
	fd = open(filename, O_RDONLY);
	if(fd==-1) {
		fprintf(stderr, "open(%s, O_RDONLY): %m\n", filename);
		exit(-1);
	}

	if(file_sha1_param) {
		if(strlen(file_sha1_param) != 2 * SHA_DIGEST_LENGTH) {
			fprintf(stderr, "sha1 format error for its length should equals to %d rather than %ld\n", 2 * SHA_DIGEST_LENGTH, strlen(file_sha1_param));
			exit(-1);
		}

		char*          in    = file_sha1_param;
		unsigned char* out   = file_sha1;
		unsigned char* limit = file_sha1 + sizeof(file_sha1);

		for(; in[0] && in[1]; in += 2) {
			if(out >= limit) {
				fprintf(stderr, "sha1 format error, out of buffer space??\n");
				exit(-1);
			}
			if(!isxdigit(in[0]) || !isxdigit(in[1])) {
				fprintf(stderr, "sha1 format error with non-hexdecimal digits.\n");
				exit(-1);
			}

#define HEXVAL(ch) (((ch) >= '0' && (ch) <= '9')? ((ch) - '0'): \
		((ch) >= 'A' && (ch) <= 'F')? ((ch) - 'A' + 10): \
		((ch) >= 'a' && (ch) <= 'f')? ((ch) - 'a' + 10): 0)
			*out++ = HEXVAL(in[0]) * 16 + HEXVAL(in[1]);
#undef HEXVAL
		}
	} else {
		int ret = 0;
		SHA_CTX sha1_ctx;
		unsigned char buf[64 * 1024];
		SHA1_Init(&sha1_ctx);

		lseek(fd, 0, SEEK_SET);

		while(0 < (ret = read(fd, buf, sizeof(buf)))) {
			SHA1_Update(&sha1_ctx, buf, ret);
		}
		lseek(fd, 0, SEEK_SET);

		SHA1_Final(file_sha1, &sha1_ctx);

		fprintf(stderr, "generated sha1 from file content\n");
	}

	{
		unsigned char* in        = file_sha1;
		unsigned char* in_limit  = file_sha1 + sizeof(file_sha1);
		char*          out       = file_sha1_hexstr;
		char*          out_limit = file_sha1_hexstr + sizeof(file_sha1_hexstr) - 1;

		for(; in < in_limit && out + 1 < out_limit; in++) {
#define HEXCHAR(n) (((n) >= 10)? (n) - 10 + 'a': (n) + '0')
			*out++ = HEXCHAR(((*in) >> 4) & 0x0f);
			*out++ = HEXCHAR(((*in) >> 0) & 0x0f);
		}
		*out = '\0';
	}

	fprintf(stderr, "send_fsd(0x%08x, %d, %s, %s)\n", fid, fd, filename, file_sha1_hexstr);
	//gover_sized = 1;
	//gfile_size = 210000000;
        if(!fstat(fd,&st)){
           gfile_size = st.st_size;
           if(-1==send_fsd(sd, fd, queue, filename, strlen(filename)+1, fid, file_sha1)) {
              fprintf(stderr, "send_fsd(0x%08x, %d, %s, %s) failed, %m\n", fid, fd, filename, file_sha1_hexstr);
           }
        }
        else {
           fprintf(stderr, "Failed to get file size \n");
        }

	close(fd);

	close(sd);
	return 0;
}
