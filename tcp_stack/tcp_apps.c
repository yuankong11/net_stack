#include "tcp_sock.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stddef.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
// void *tcp_server(void *arg)
// {
// 	u16 port = *(u16 *)arg;
// 	struct tcp_sock *tsk = alloc_tcp_sock();

// 	struct sock_addr addr;
// 	addr.ip = htonl(0);
// 	addr.port = port;
// 	if (tcp_sock_bind(tsk, &addr) < 0) {
// 		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
// 		exit(1);
// 	}

// 	if (tcp_sock_listen(tsk, 3) < 0) {
// 		log(ERROR, "tcp_sock listen failed");
// 		exit(1);
// 	}

// 	log(DEBUG, "listen to port %hu.", ntohs(port));

// 	struct tcp_sock *csk = tcp_sock_accept(tsk);

// 	log(DEBUG, "accept a connection.");

// 	FILE *f = fopen("./server-output.dat", "w");
// 	char buf[1024];
// 	int len, tot_len = 0;
// 	while(1)
// 	{
// 		len = tcp_sock_read(csk, buf, 1024);
// 		if(len == 0)
// 		{
// 			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
// 			break;
// 		}
// 		else if(len > 0)
// 		{
// 			fwrite(buf, 1, len, f);
// 			tot_len += len;
// 		}
// 		else
// 		{
// 			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
// 			exit(1);
// 		}
// 	}
// 	printf("recv %d bytes.\n", tot_len);
// 	fclose(f);

// 	// char rbuf[1001];
// 	// char wbuf[1024];
// 	// int rlen = 0;
// 	// while (1) {
// 	// 	rlen = tcp_sock_read(csk, rbuf, 1000);
// 	// 	if (rlen == 0) {
// 	// 		log(DEBUG, "tcp_sock_read return 0, finish transmission.");
// 	// 		break;
// 	// 	}
// 	// 	else if (rlen > 0) {
// 	// 		rbuf[rlen] = '\0';
// 	// 		sprintf(wbuf, "server echoes: %s", rbuf);
// 	// 		if (tcp_sock_write(csk, wbuf, strlen(wbuf)) < 0) {
// 	// 			log(DEBUG, "tcp_sock_write return negative value, something goes wrong.");
// 	// 			exit(1);
// 	// 		}
// 	// 	}
// 	// 	else {
// 	// 		log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
// 	// 		exit(1);
// 	// 	}
// 	// }

// 	// sleep(2);

// 	log(DEBUG, "close this connection.");

// 	tcp_sock_close(csk);

// 	return NULL;
// }

// // tcp client application, connects to server (ip:port specified by arg), each
// // time sends one bulk of data and receives one bulk of data
// void *tcp_client(void *arg)
// {
// 	struct sock_addr *skaddr = arg;

// 	struct tcp_sock *tsk = alloc_tcp_sock();

// 	if (tcp_sock_connect(tsk, skaddr) < 0) {
// 		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.",
// 				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
// 		exit(1);
// 	}

// 	sleep(1);

// 	char buf[1024];
// 	int len, tot_len = 0;
// 	FILE *f = fopen("./client-input.dat", "r");
// 	if(!f)
// 	{
// 		printf("Error: open file failed.\n");
// 		exit(-1);
// 	}
// 	len = fread(buf, 1, 1024, f);
// 	while(len == 1024)
// 	{
// 		tcp_sock_write(tsk, buf, 1024);
// 		tot_len += 1024;
// 		len = fread(buf, 1, 1024, f);
// 	}
// 	if(feof(f))
// 	{
// 		tcp_sock_write(tsk, buf, len);
// 		tot_len += len;
// 	}
// 	else
// 	{
// 		printf("fread error.\n");
// 		exit(-1);
// 	}
// 	printf("send %d bytes.\n", tot_len);
// 	fclose(f);

// 	// char *wbuf = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
// 	// int wlen = strlen(wbuf);
// 	// char rbuf[1000];
// 	// int rlen = 0;
// 	// int n = 10;
// 	// for (int i = 0; i < n; i++) {
// 	// 	if (tcp_sock_write(tsk, wbuf + i, wlen - n) < 0)
// 	// 		break;

// 	// 	rlen = tcp_sock_read(tsk, rbuf, 1000);
// 	// 	if (rlen == 0) {
// 	// 		log(DEBUG, "tcp_sock_read return 0, finish transmission.");
// 	// 		break;
// 	// 	}
// 	// 	else if (rlen > 0) {
// 	// 		rbuf[rlen] = '\0';
// 	// 		fprintf(stdout, "%s\n", rbuf);
// 	// 	}
// 	// 	else {
// 	// 		log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
// 	// 		exit(1);
// 	// 	}
// 	// 	sleep(1);
// 	// }

// 	// sleep(1);

// 	tcp_sock_close(tsk);

// 	return NULL;
// }

void error(char *s)
{
    printf("%s", s);
    exit(-1);
}

void *tcp_server(void *arg)
{
    // create socket
	struct tcp_sock *tsk = alloc_tcp_sock();

    // bind
    struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = htons(10001);
	tcp_sock_bind(tsk, &addr);

    // listen
    tcp_sock_listen(tsk, 1);

    // accept
    struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

    // receive
    unsigned int file_name_len, begin, end;
    char msg[100];
    int msg_len;

    // receive length of file name
    msg_len = tcp_sock_read(csk, (char *)&file_name_len, sizeof(file_name_len));
    file_name_len = ntohl(file_name_len);
    if(file_name_len >= 100)
        error("too long file name\n");
    printf("length of file name: %d\n", file_name_len);

    // receive file name
    msg_len = tcp_sock_read(csk, msg, file_name_len);
    msg[msg_len] = 0;
    printf("file name: %s\n", msg);

    // receive begin position
    msg_len = tcp_sock_read(csk, (char *)&begin, sizeof(begin));
    begin = ntohl(begin);
    printf("begin: %d\n", begin);

    // receive end position
    msg_len = tcp_sock_read(csk, (char *)&end, sizeof(end));
    end = ntohl(end);
    printf("end: %d\n", end);

    // count
    FILE *file = fopen(msg, "r");
    if(!file)
        error("open file failed\n");
    fseek(file, begin, SEEK_SET);

    unsigned int count[26];
    int i;
    for(i = 0; i < 26; ++i)
        count[i] = 0;

    char c;
    while(begin < end)
    {
        fread((void *)&c, 1, 1, file);
        if(c >= 'a' && c <= 'z')
            ++count[c - 'a'];
        if(c >= 'A' && c <= 'Z')
            ++count[c - 'A'];
        ++begin;
    }

    // send result
    for(i = 0; i < 26; ++i)
    {
        count[i] = htonl(count[i]);
        tcp_sock_write(csk, (char *)&count[i], sizeof(count[0]));
    }

	//sleep(1);

    // close
    tcp_sock_close(csk);

    sleep(1);

    exit(0);

    return NULL;
}

#define MAX_WORKERS 2

off_t size;
char *file_name = "war_and_peace.txt";
unsigned int file_name_len, file_name_len_big;
unsigned int count[26];
int workers_index;
struct tcp_sock *s[MAX_WORKERS]; // socket

void *thread_link(void *arg)
{
    unsigned int interval = size / workers_index;
    unsigned int begin, end; // [begin, end)
    unsigned int begin_big, end_big;
    int i = *((int *)arg);

    if(i == 0)
        begin = 3;
    else
        begin = i*interval;
    if(i == workers_index - 1)
        end = size;
    else
        end = (i+1)*interval;

    // send task
    tcp_sock_write(s[i], (char *)&file_name_len_big, 4);
    tcp_sock_write(s[i], file_name, file_name_len);
    printf("task of worker %d: begin: %d, end: %d\n", i + 1, begin, end);
    begin_big = htonl(begin);
    end_big = htonl(end);
    tcp_sock_write(s[i], (char *)&begin_big, 4);
    tcp_sock_write(s[i], (char *)&end_big, 4);

    // receive result
    unsigned int t;
    int j;
    for (j = 0; j < 26; ++j)
    {
        tcp_sock_read(s[i], (char *)&t, sizeof(t));
        t = ntohl(t);
        __sync_fetch_and_add(&count[j], t);
    }

    // close
    tcp_sock_close(s[i]);

    return NULL;
}

void *tcp_client(void *arg)
{
    // get file size
    struct stat st;
    file_name_len = strlen(file_name);
    file_name_len_big = htonl(file_name_len);
    stat(file_name, &st);
    size = st.st_size;
    printf("number of characters(BOM & EOF ignored) is: %ld\n", size - 3);

    // read config & connect to workers
    char *config = "workers.conf";
    FILE *file = fopen(config, "r");
    char ip_addr[17];
    int i, failed = 0;

    while(fgets(ip_addr, 17, file) != NULL)
    {
        for(i = 0; ip_addr[i] && ip_addr[i] != '\n'; ++i)
            ;
        if(ip_addr[i]) ip_addr[i] = 0;
        else error("wrong config\n");
        printf("found worker: %s, connecting to it\n", ip_addr);

        if(!failed)
            s[workers_index] = alloc_tcp_sock();
        if(s[workers_index] == NULL)
            error("create socket failed\n");

		struct sock_addr skaddr;
		skaddr.ip = inet_addr(ip_addr);
		skaddr.port = htons(10001);
        if(tcp_sock_connect(s[workers_index], &skaddr) == -1)
        {
            printf("connect to %s failed\n", ip_addr);
            failed = 1;
            continue;
        }
        printf("connect to %s succeed\n", ip_addr);

        ++workers_index;
        failed = 0;
        if(workers_index >= MAX_WORKERS)
            break;
    }

    if(workers_index == 0)
        error("no worker alive\n");
    printf("%d worker(s) connected\n", workers_index);

    // create thread
    pthread_t thread_id[MAX_WORKERS];
    for(i = 0; i < workers_index; ++i)
    {
        pthread_create(&thread_id[i], NULL, thread_link, &i);
        pthread_join(thread_id[i], NULL);
    }

    // print result
    for (i = 0; i < 26; ++i)
    {
        printf("#'%c': %d", i + 'a', count[i]);
        if(((i+1) & 0x3) == 0)
            putchar('\n');
        else
            putchar('\t');
    }
    putchar('\n');

    sleep(1);

    exit(0);

    return NULL;
}
