#include "ip.h"
#include "rtable.h"
#include "arpcache.h"
#include "arp.h"
#include "icmp.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void copy_mac(u8 mac_dst[ETH_ALEN], u8 mac_src[ETH_ALEN])
{
	memcpy((void *)mac_dst, (void *)mac_src, ETH_ALEN);
}

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stderr, "TODO: handle ip packet.\n");
	struct iphdr *ih = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ih->daddr);
	log(DEBUG, "handle_ip_packet: daddr: "IP_FMT"", HOST_IP_FMT_STR(daddr));
	if(daddr == iface->ip)
	{
		u8 protocol = ih->protocol;
		if(protocol == IPPROTO_ICMP)
		{
			struct icmphdr *icmph = (struct icmphdr *)((u8 *)ih + IP_HDR_SIZE(ih));
			if(icmph->type == ICMP_ECHOREQUEST)
			{
				// log(DEBUG, "handle_ip_packet: icmp_reply");
				icmp_send_packet(packet, len, 0, 0);
				free(packet);
			}
		}
	}
	else
	{
		rt_entry_t *p = longest_prefix_match(daddr);
		if(p)
		{
			u8 ttl = ih->ttl;
			--ttl;
			if(ttl <= 0)
			{
				// log(DEBUG, "handle_ip_packet: ttl <= 0");
				icmp_send_packet(packet, len, 11, 0);
				free(packet);
			}
			else
			{
				// log(DEBUG, "handle_ip_packet: forward packet");
				ih->ttl = ttl;
				u16 checksum = ip_checksum(ih);
				ih->checksum = checksum; // checksum do not need to switch to network byte order
				u32 ip = (p->gw == 0) ? daddr : p->gw;
				iface_send_packet_by_arp(p->iface, ip, packet, len);
			}
		}
		else
		{
			log(DEBUG, "handle_ip_packet: longest_prefix_match fail");
			icmp_send_packet(packet, len, 3, 0);
			free(packet);
		}
	}
}
