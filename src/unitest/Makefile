
CC ?= gcc
CFLAGS = -Wall -g



PROG1 = recv_fd
PROG2 = bdiff
PROG3 = recv_tr
PROG4 = send_fd

TARGET = $(PROG1) $(PROG2) $(PROG3) $(PROG4)

all: $(TARGET)

$(PROG1): $(PROG1).c
	$(CC) $(CFLAGS) $(INC_FPGA) -o $@ $(PROG1).c

$(PROG2): $(PROG2).c
	$(CC) $(CFLAGS) -o $@ $(PROG2).c

$(PROG3): $(PROG3).c
	$(CC) $(CFLAGS) -o $@ $(PROG3).c

$(PROG4): $(PROG4).c
	$(CC) $(CFLAGS) -o $@ $(PROG4).c \
		-I../../../../system/src/openssl/include \
		-L../../../../system/src/openssl/lib -Wl,-rpath,../../../../system/src/openssl/lib -lcrypto

install:
	@echo "Do nothing here ....."

clean:
	rm -f $(TARGET) file.*

