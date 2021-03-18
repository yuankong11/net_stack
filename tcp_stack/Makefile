TARGET = tcp_stack
all: $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Iinclude
LDFLAGS =

LIBS = -lpthread

HDRS = ./include/*.h

SRCS = arp.c arpcache.c icmp.c ip.c main.c packet.c rtable.c rtable_internal.c \
	   tcp.c tcp_apps.c tcp_in.c tcp_out.c tcp_sock.c tcp_timer.c

OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

clean:
	rm -f *.o $(TARGET)

md5sum:
	md5sum client-input.dat
	md5sum server-output.dat

server: tcp_stack
	./tcp_stack server 10001

client: tcp_stack
	./tcp_stack client 10.0.0.1 10001
