#include <stdlib.h>
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

#define SIZE	2
int main(int argc, char **argv)
{
	int fd[SIZE];
	int i;
	unsigned char buf[SIZE];
	int len[SIZE];
	unsigned int pos;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s FILE1 FILE2\n", argv[0]);
		exit(1);
	}

	for (i = 0; i < SIZE; i++) {
		fd[i] = open(argv[1+i], O_RDONLY);
		if (fd[i] < 0) {
			fprintf(stderr, "fail to open [%s]: %m\n", argv[1+i]);
			exit(1);
		}
	}

	for (pos = 0; ; pos++) {
		for (i = 0; i < SIZE; i++) {
			len[i] = read(fd[i], &buf[i], sizeof(buf[i]));
		}
		if (len[0] != len[1]) {
			printf("sizes diff\n");
			break;
		}
		if (buf[0] != buf[1]) {
			printf("diff[%u]: %02x %02x\n", pos, buf[0], buf[1]);
			break;
		}
		if (len[0] == 0)
			break;
	}

	for (i = 0; i < SIZE; i++) {
		close(fd[i]);
	}
	
	return 0;
}
