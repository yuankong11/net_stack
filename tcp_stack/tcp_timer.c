#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

struct list_head timer_list;
pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

int resend_packet(struct tcp_sock *tsk)
{
	if(tsk->retrans_timer.type == 6)
	{
		tcp_send_control_packet(tsk, TCP_RST);
		return -1;
	}
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL << tsk->retrans_timer.type;
	++tsk->retrans_timer.type;
	sent_packet_t *p = list_entry(tsk->snd_buf.next, sent_packet_t, list);
	char *packet = (char *)malloc(p->len);
	memcpy(packet, p->packet, p->len);
	pthread_mutex_lock(&tsk->cwnd_lock);
	tsk->ssthresh = tsk->cwnd/2;
	tsk->cwnd = 1;
	tsk->num_ack_cv = 0;
	tsk->num_dup_ack = 0;
	tsk->rp_valid = 0;
	pthread_mutex_unlock(&tsk->cwnd_lock);
	ip_send_packet(packet, p->len);
	return 0;
}

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	struct tcp_timer *p, *q;
	pthread_mutex_lock(&timer_list_lock);
	list_for_each_entry_safe(p, q, &timer_list, list)
	{
		p->timeout -= TCP_TIMER_SCAN_INTERVAL;
		if(p->timeout <= 0)
		{
			if(p->type == 0)
			{
				list_delete_entry(&p->list);
				struct tcp_sock *tsk = timewait_to_tcp_sock(p);
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unhash(tsk);
				if(!tsk->parent)
					tcp_bind_unhash(tsk);
				//exit(0);
			}
			else
			{
				struct tcp_sock *tsk = retranstimer_to_tcp_sock(p);
				assert(resend_packet(tsk) == 0);
			}
		}
	}
	pthread_mutex_unlock(&timer_list_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	pthread_mutex_lock(&timer_list_lock);
	tsk->timewait.type = 0;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	tsk->timewait.enable = 1;
	list_add_tail(&tsk->timewait.list, &timer_list);
	pthread_mutex_unlock(&timer_list_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
