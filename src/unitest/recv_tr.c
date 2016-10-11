#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


struct sockaddr_un addr = {
	.sun_family = AF_UNIX,
	.sun_path = "",
};

int main(int argc, char **argv)
{
	int fd;
	ssize_t len;
	unsigned char buf[32*1024];
	int i;
	int verbose = 0;
	int ulen;
	int ret;


	if (argc < 2) {
		printf("Usage:\n\trecv_tr NAME -v\n");
		ret = 1;
		goto out;
	}

	if (argc == 3 && !strcmp(argv[2], "-v")) {
		fprintf(stderr, "verbose mode\n");
		verbose = 1;
	}

	printf("Listening on socket [\\0%s]\n", argv[1]);
	ulen = snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "%s", argv[1]);

	if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Fail to create sock\n");
		ret = 2;
		goto out;
	}

	if (bind(fd, (struct sockaddr *) &addr, 2 + 1 + ulen) < 0) {
		fprintf(stderr, "Fail to bind(\\0%s): %m\n", argv[1]);
		ret = 3;
		goto err;
	}

	while (1) {

		len = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);

		if (len <= 0) {
			printf("[%s] len=%ld %m\n", argv[1], len);
			break;
		}
		printf("[%s] Receive Trigger %ld bytes\n", argv[1], len);

		if (!verbose)
			continue;

		for (i = 0; i < len; i++) {
			printf("%02x ", buf[i]);
		}
		printf("\n");
	}

	ret = 0;

err:
	close(fd);
out:
	return 0;
	
}

