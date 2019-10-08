#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	// fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	// log(DEBUG, "icmp_send_packet: type: %hhu, code: %hhu", type, code);
	int size;
	struct iphdr *ih_in = packet_to_ip_hdr(in_pkt);
	int ih_size = IP_HDR_SIZE(ih_in);
	if(type == ICMP_ECHOREPLY)
		size = len - ih_size + IP_BASE_HDR_SIZE;
	else
		size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + ih_size + 8;
	char *out_pkt = (char *)malloc(size);
	struct iphdr *ih_out = packet_to_ip_hdr(out_pkt);
	u32 saddr_in = ntohl(ih_in->saddr);
	rt_entry_t *rte = longest_prefix_match(saddr_in);
	if(!rte)
	{
		log(ERROR, "Could not find forwarding rule for IP when send ICMP packet (dst:"IP_FMT").",
			HOST_IP_FMT_STR(saddr_in));
		return;
	}
	u32 saddr_out = rte->iface->ip;
	ip_init_hdr(ih_out, saddr_out, saddr_in, size - ETHER_HDR_SIZE, IPPROTO_ICMP);
	struct icmphdr *icmph_out = (struct icmphdr *)((u8 *)ih_out + IP_BASE_HDR_SIZE);
	icmph_out->type = type;
	icmph_out->code = code;
	int icmp_len;
	if(type == ICMP_ECHOREPLY)
	{
		struct icmphdr *icmph_in = (struct icmphdr *)((u8 *)ih_in + ih_size);
		icmp_len = ntohs(ih_in->tot_len) - ih_size;
		memcpy((void *)&icmph_out->u, (void *)&icmph_in->u, icmp_len - ICMP_HDR_SIZE + 4);
	}
	else
	{
		icmp_len = ICMP_HDR_SIZE + ih_size + 8;
		*((u32 *)&icmph_out->u) = 0;
		memcpy((void *)((u8 *)icmph_out + ICMP_HDR_SIZE), (void *)ih_in, ih_size + 8);
	}
	icmph_out->checksum = icmp_checksum(icmph_out, icmp_len);
	ip_send_packet(out_pkt, size);
}
