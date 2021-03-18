#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"
#include "ip.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void copy_mac(u8 mac_dst[ETH_ALEN], u8 mac_src[ETH_ALEN])
{
	memcpy((void *)mac_dst, (void *)mac_src, ETH_ALEN);
}

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	// fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	log(DEBUG, "arp_send_request: ip: "IP_FMT"", HOST_IP_FMT_STR(dst_ip));
	int packet_len = ETHER_HDR_SIZE + ARP_PKT_SIZE;
	char *packet = (char *)malloc(packet_len);
	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_ARP);
	memset(eh->ether_dhost, -1, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	struct ether_arp *ah = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	ah->arp_hrd = htons(0x01);
	ah->arp_pro = htons(0x0800);
	ah->arp_hln = 6;
	ah->arp_pln = 4;
	ah->arp_op = htons(0x01);
	copy_mac(ah->arp_sha, iface->mac);
	ah->arp_spa = htonl(iface->ip);
	memset(ah->arp_tha, 0, ETH_ALEN);
	ah->arp_tpa = htonl(dst_ip);
	iface_send_packet(iface, packet, packet_len);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	// fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	// log(DEBUG, "[arp_send_reply]");
	int packet_len = ETHER_HDR_SIZE + ARP_PKT_SIZE;
	char *packet = (char *)malloc(packet_len);
	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_ARP);
	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	struct ether_arp *ah = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	ah->arp_hrd = htons(0x01);
	ah->arp_pro = htons(0x0800);
	ah->arp_hln = 6;
	ah->arp_pln = 4;
	ah->arp_op = htons(0x02);
	copy_mac(ah->arp_sha, iface->mac);
	ah->arp_spa = htonl(iface->ip);
	copy_mac(ah->arp_tha, req_hdr->arp_sha);
	ah->arp_tpa = req_hdr->arp_spa;
	iface_send_packet(iface, packet, packet_len);
	arpcache_insert(ntohl(req_hdr->arp_spa), req_hdr->arp_sha);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp *ah = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	u16 arp_op = ntohs(ah->arp_op);
	u32 dst = ntohl(ah->arp_tpa);
	u32 src = ntohl(ah->arp_spa);
	log(DEBUG, "handle_arp_packet: op: %s, src: "IP_FMT", dst: "IP_FMT"",
		(arp_op == ARPOP_REQUEST) ? "REQUEST" : "REPLY",
		HOST_IP_FMT_STR(src), HOST_IP_FMT_STR(dst));
	if(dst == iface->ip)
	{
		if(arp_op == ARPOP_REQUEST)
			arp_send_reply(iface, ah);
		else if(arp_op == ARPOP_REPLY)
			arpcache_insert(ntohl(ah->arp_spa), ah->arp_sha);
	}
	else
	{
		log(ERROR, "handle_arp_packet: ip != iface->ip");
	}
	free(packet);
}

// send (IP) packet through arpcache lookup
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	// log(DEBUG, "[iface_send_packet_by_arp]");
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	// log(DEBUG, "iface_send_packet_by_arp: found: %d", found);
	if (found) {
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
