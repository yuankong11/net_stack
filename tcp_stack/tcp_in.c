#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

#include <time.h>
#include <pthread.h>
#include <unistd.h>

// update the adv_wnd of tcp_sock
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if(cb->flags & TCP_ACK)
	{
		pthread_mutex_lock(&tsk->adv_wnd_lock);
		tsk->adv_wnd = cb->rwnd;
		wake_up(tsk->wait_send);
		pthread_mutex_unlock(&tsk->adv_wnd_lock);
	}
}

// update the adv_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if((cb->flags & TCP_ACK) &&
		less_or_equal_32b(tsk->snd_una, cb->ack) &&
		less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	// if(cb->seq != tsk->rcv_nxt)
	// {
	// 	printf("cb->seq: %u, rcv_nxt: %d\n", cb->seq, tsk->rcv_nxt);
	// }
	// return (cb->seq == tsk->rcv_nxt);
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	return(less_than_32b(cb->seq, rcv_end));
}

void free_sent_packet(sent_packet_t *p)
{
	free(p->packet);
	list_delete_entry(&p->list);
	free(p);
}

void unset_retrans_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);
	tsk->retrans_timer.enable = 0;
	pthread_mutex_unlock(&timer_list_lock);
}

void update_retrans_timer(struct tcp_sock *tsk)
{
	if(list_empty(&tsk->snd_buf))
	{
		tsk->retrans_timer.enable = 0;
		list_delete_entry(&tsk->retrans_timer.list);
	}
	else
	{
		tsk->retrans_timer.type = 1;
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	}
}

void resend_first_pkt(struct tcp_sock *tsk)
{
	assert(!list_empty(&tsk->snd_buf));
	sent_packet_t *p = list_entry(tsk->snd_buf.next, sent_packet_t, list);
	char *packet = (char *)malloc(p->len);
	memcpy(packet, p->packet, p->len);
	ip_send_packet(packet, p->len);
}

void ack_update(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if(cb->flags & TCP_ACK)
	{
		sent_packet_t *p, *q;
		pthread_mutex_lock(&tsk->cwnd_lock);
		if(tsk->snd_una == cb->ack)
		{
			if(!tsk->rp_valid)
			{
				++tsk->num_dup_ack;
				if(tsk->num_dup_ack == 3)
				{
					tsk->num_ack_cv = 0;
					tsk->num_dup_ack = 0;
					if(!list_empty(&tsk->snd_buf))
					{
						tsk->cwnd /= 2;
						if(tsk->cwnd == 0)
							tsk->cwnd = 1;
						tsk->ssthresh = tsk->cwnd;
						tsk->recovery_point = tsk->snd_nxt;
						tsk->rp_valid = 1;
						pthread_mutex_lock(&timer_list_lock);
						update_retrans_timer(tsk);
						pthread_mutex_unlock(&timer_list_lock);
						resend_first_pkt(tsk);
					}
				}
			}
		}
		else
		{
			tsk->num_dup_ack = 0;
			tsk->snd_una = cb->ack;
			wake_up(tsk->wait_send);
			list_for_each_entry_safe(p, q, &tsk->snd_buf, list)
			{
				if(less_or_equal_32b(p->seq_end, cb->ack))
				{
					pthread_mutex_lock(&timer_list_lock);
					free_sent_packet(p);
					update_retrans_timer(tsk);
					pthread_mutex_unlock(&timer_list_lock);
					if(tsk->rp_valid)
					{
						if(cb->ack >= tsk->recovery_point)
						{
							tsk->rp_valid = 0;
						}
						else
						{
							pthread_mutex_lock(&timer_list_lock);
							update_retrans_timer(tsk);
							pthread_mutex_unlock(&timer_list_lock);
							resend_first_pkt(tsk);
						}
					}
					else
					{
						if(tsk->cwnd < tsk->ssthresh)
						{
							++tsk->cwnd;
							wake_up(tsk->wait_send);
						}
						else
						{
							++tsk->num_ack_cv;
							if(tsk->num_ack_cv == tsk->cwnd)
							{
								++tsk->cwnd;
								tsk->num_ack_cv = 0;
								wake_up(tsk->wait_send);
							}
						}
					}
				}
				else
					break;
			}
		}
		pthread_mutex_unlock(&tsk->cwnd_lock);
	}
}

void update_ofo_buf(struct tcp_sock *tsk)
{
	ofo_packet_t *p, *q;
	list_for_each_entry_safe(p, q, &tsk->rcv_ofo_buf, list)
	{
		if(tsk->rcv_nxt == p->seq)
		{
			tsk->rcv_nxt = p->seq + p->len;
			pthread_mutex_lock(&tsk->rcv_wnd_lock);
			assert(tsk->rcv_wnd >= p->len);
			tsk->rcv_wnd -= p->len;
			pthread_mutex_unlock(&tsk->rcv_wnd_lock);
			pthread_mutex_lock(&tsk->rcv_buf_lock);
			if(ring_buffer_full(tsk->rcv_buf))
			{
				pthread_mutex_unlock(&tsk->rcv_buf_lock);
				sleep_on(tsk->wait_read);
				pthread_mutex_lock(&tsk->rcv_buf_lock);
			}
			write_ring_buffer(tsk->rcv_buf, p->packet, p->len);
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			list_delete_entry(&p->list);
			free(p);
			wake_up(tsk->wait_recv);
		}
		else if(less_than_32b(tsk->rcv_nxt, p->seq))
		{
			break;
		}
		else
		{
			log(ERROR, "invalid rcv_nxt & seq");
			exit(-1);
		}
	}
}

void insert_ofo_buf(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	ofo_packet_t *p = (ofo_packet_t *)malloc(sizeof(ofo_packet_t));
	char *data_cpy = (char *)malloc(cb->pl_len);
	assert(data_cpy != NULL);
	memcpy(data_cpy, cb->payload, cb->pl_len);
	p->packet = data_cpy;
	p->len = cb->pl_len;
	p->seq = cb->seq;
	ofo_packet_t *q;
	list_for_each_entry(q, &tsk->rcv_ofo_buf, list)
	{
		if(less_or_equal_32b(p->seq, q->seq))
			break;
	}
	list_insert(&p->list, q->list.prev, &q->list);
	update_ofo_buf(tsk);
	tcp_send_control_packet(tsk, TCP_ACK);
}

// Process the incoming packet according to TCP state machine.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	if(tsk == NULL)
	{
		return;
	}
	if(cb->flags & TCP_RST)
	{
		log(DEBUG, "RST arrived");
		return;
	}
	if(tsk->state != TCP_LISTEN && tsk->state != TCP_SYN_SENT)
	{
		assert(is_tcp_seq_valid(tsk, cb));
	}
	switch(tsk->state)
	{
		case TCP_LISTEN:
		{
			assert(cb->flags == TCP_SYN);
			struct tcp_sock *child = alloc_tcp_sock();
			child->sk_sip = tsk->sk_sip;
			child->sk_sport = tsk->sk_sport;
			child->sk_dip = cb->saddr;
			child->sk_dport = cb->sport;
			tcp_set_state(child, TCP_SYN_RECV);
			tcp_hash(child);
			child->parent = tsk;
			list_add_tail(&child->list, &tsk->listen_queue);
			child->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(child, TCP_SYN | TCP_ACK);
			break;
		}
		case TCP_SYN_RECV:
		{
			if(cb->flags != TCP_ACK)
			{
				if(cb->flags == TCP_SYN)
				{
					tcp_send_control_packet(tsk, TCP_SYN | TCP_ACK);
					break;
				}
			}
			tsk->adv_wnd = cb->rwnd;
			tcp_set_state(tsk, TCP_ESTABLISHED);
			assert(!tcp_sock_accept_queue_full(tsk->parent));
			tcp_sock_accept_enqueue(tsk);
			ack_update(tsk, cb);
			wake_up(tsk->parent->wait_accept);
			break;
		}
		case TCP_SYN_SENT:
		{
			assert(cb->flags == (TCP_SYN | TCP_ACK));
			ack_update(tsk, cb);
			tsk->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(tsk, TCP_ACK);
			tsk->adv_wnd = cb->rwnd;
			tcp_set_state(tsk, TCP_ESTABLISHED);
			wake_up(tsk->wait_connect);
			break;
		}
		case TCP_ESTABLISHED:
		{
			if(cb->flags & TCP_SYN)
			{
				tcp_send_control_packet(tsk, TCP_ACK);
				break;
			}
			ack_update(tsk, cb);
			tcp_update_window_safe(tsk, cb);
			if(cb->pl_len)
			{
				if(less_or_equal_32b(cb->seq_end, tsk->rcv_nxt))
					tcp_send_control_packet(tsk, TCP_ACK);
				else
					insert_ofo_buf(tsk, cb);
			}
			if(cb->flags & TCP_FIN)
			{
				if(cb->seq != tsk->rcv_nxt)
					break;
				++tsk->rcv_nxt;
				wait_exit(tsk->wait_recv);
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_state(tsk, TCP_CLOSE_WAIT);
			}
			break;
		}
		case TCP_FIN_WAIT_1:
		{
			assert(cb->flags & TCP_ACK);
			ack_update(tsk, cb);
			if(cb->flags & TCP_FIN)
			{
				++tsk->rcv_nxt;
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_timewait_timer(tsk);
				tcp_set_state(tsk, TCP_TIME_WAIT);
			}
			else
			{
				tcp_set_state(tsk, TCP_FIN_WAIT_2);
			}
			break;
		}
		case TCP_FIN_WAIT_2:
		{
			ack_update(tsk, cb);
			if(cb->flags & TCP_FIN)
			{
				++tsk->rcv_nxt;
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_timewait_timer(tsk);
				unset_retrans_timer(tsk);
				tcp_set_state(tsk, TCP_TIME_WAIT);
			}
			break;
		}
		case TCP_TIME_WAIT:
		{
			if(cb->flags == (TCP_FIN | TCP_ACK))
			{
				tcp_send_control_packet(tsk, TCP_ACK);
				pthread_mutex_lock(&timer_list_lock);
				assert(tsk->state == TCP_TIME_WAIT);
				tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
				pthread_mutex_unlock(&timer_list_lock);
			}
			break;
		}
		case TCP_CLOSE_WAIT:
		{
			if(cb->flags == TCP_FIN)
				tcp_send_control_packet(tsk, TCP_ACK);
			break;
		}
		case TCP_LAST_ACK:
		{
			if(cb->flags == TCP_FIN)
			{
				tcp_send_control_packet(tsk, TCP_ACK);
				break;
			}
			assert(cb->flags == TCP_ACK);
			ack_update(tsk, cb);
			unset_retrans_timer(tsk);
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unhash(tsk);
			//exit(0);
			break;
		}
		default:
		{
			log(ERROR, "unexpected state");
			exit(-1);
		}
	}
}
