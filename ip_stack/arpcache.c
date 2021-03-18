#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"
#include "ip.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

static inline void copy_mac(u8 mac_dst[ETH_ALEN], u8 mac_src[ETH_ALEN])
{
	memcpy((void *)mac_dst, (void *)mac_src, ETH_ALEN);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// if any, return 1 & mac address
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	// fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	// return 0;
	// log(DEBUG, "arpcache_lookup: ip: "IP_FMT"", HOST_IP_FMT_STR(ip4));
	pthread_mutex_lock(&arpcache.lock);
	for(int i = 0; i < MAX_ARP_SIZE; ++i)
	{
		if(arpcache.entries[i].valid)
			if(arpcache.entries[i].ip4 == ip4)
			{
				copy_mac(mac, arpcache.entries[i].mac);
				pthread_mutex_unlock(&arpcache.lock);
				return 1;
			}
	}
	pthread_mutex_unlock(&arpcache.lock);
	// log(DEBUG, "arpcache_lookup: end");
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	// fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	// log(DEBUG, "arpcache_append_packet: ip: "IP_FMT"", HOST_IP_FMT_STR(ip4));
	arp_req_t *p;
	int found = 0;
	cached_pkt_t *pkt = (cached_pkt_t *)malloc(sizeof(cached_pkt_t));
	pkt->len = len;
	pkt->packet = packet;
	pthread_mutex_lock(&arpcache.lock);
	list_for_each_entry(p, &arpcache.req_list, list)
	{
		if(p->ip4 == ip4 && p->iface == iface)
		{
			found = 1;
			break;
		}
	}
	if(!found)
	{
		p = (arp_req_t *)malloc(sizeof(arp_req_t));
		init_list_head(&p->cached_packets);
		p->iface = iface;
		p->ip4 = ip4;
		p->retries = 0;
		p->sent = time(NULL);
		list_add_tail(&p->list, &arpcache.req_list);
	}
	list_add_tail(&pkt->list, &p->cached_packets);
	pthread_mutex_unlock(&arpcache.lock);
	if(!found) arp_send_request(iface, ip4);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	// fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
	log(DEBUG, "arpcache_insert: ip: "IP_FMT", mac: "ETHER_STRING"",
		HOST_IP_FMT_STR(ip4), ETHER_FMT(mac));
	if(arpcache_lookup(ip4, mac)) return;
	int n = -1;
	pthread_mutex_lock(&arpcache.lock);
	for(int i = 0; i < MAX_ARP_SIZE; ++i)
		if(!arpcache.entries[i].valid)
		{
			n = i;
			break;
		}
	if(n == -1) n = rand() % MAX_ARP_SIZE;
	arpcache.entries[n].valid = 1;
	arpcache.entries[n].added = time(NULL);
	arpcache.entries[n].ip4 = ip4;
	copy_mac(arpcache.entries[n].mac, mac);
	arp_req_t *p1, *q1;
	cached_pkt_t *p2, *q2;
	list_for_each_entry_safe(p1, q1, &arpcache.req_list, list)
	{
		if(p1->ip4 == ip4)
		{
			list_for_each_entry_safe(p2, q2, &p1->cached_packets, list)
			{
				struct ether_header *eh = (struct ether_header *)p2->packet;
				copy_mac(eh->ether_dhost, mac);
				iface_send_packet(p1->iface, p2->packet, p2->len);
				list_delete_entry(&p2->list);
				free(p2);
			}
			list_delete_entry(&p1->list);
			free(p1);
			break;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg)
{
	while (1) {
		sleep(1);
		// fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		// log(DEBUG, "[arpcache_sweep]");
		pthread_mutex_lock(&arpcache.lock);
		time_t now = time(NULL);
		for(int i = 0; i < MAX_ARP_SIZE; ++i)
		{
			if(arpcache.entries[i].valid)
				if(now - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)
				{
					arpcache.entries[i].valid = 0;
					log(DEBUG, "arpcache_sweep: delete arpcache entry: %d", i);
				}
		}
		arp_req_t *req, *req1;
		list_for_each_entry_safe(req, req1, &arpcache.req_list, list)
		{
			if(now - req->sent > 1)
			{
				if(req->retries >= ARP_REQUEST_MAX_RETRIES)
				{
					log(DEBUG, "arpcache_sweep: delete arp request(ip: "IP_FMT"), reply ICMP unreachable",
						HOST_IP_FMT_STR(req->ip4));
					cached_pkt_t *pkt, *pkt1;
					list_for_each_entry_safe(pkt, pkt1, &req->cached_packets, list)
					{
						pthread_mutex_unlock(&arpcache.lock);
						icmp_send_packet(pkt->packet, pkt->len, 3, 1);
						pthread_mutex_lock(&arpcache.lock);
						// fix: insert here?
						free(pkt->packet);
						list_delete_entry(&pkt->list);
						free(pkt);
					}
					list_delete_entry(&req->list);
					free(req);
				}
				else
				{
					log(DEBUG, "arpcache_sweep: resend arp request(ip: "IP_FMT")",
						HOST_IP_FMT_STR(req->ip4));
					++req->retries;
					req->sent = now;
					arp_send_request(req->iface, req->ip4);
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
