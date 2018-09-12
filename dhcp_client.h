#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <errno.h>

#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H

#define BOOTP_REQUEST	1
#define BOOTP_REPLY	2

#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8

#define MSG_LEN 512

struct bootp_hdr {
		struct ethhdr ethh;
		struct iphdr iph;
		struct udphdr udph;
		uint8_t op;
		uint8_t htype;
		uint8_t hlen;
		uint8_t hops;
		__be32 xid;
		__be16 secs;
		__be16 flags;
		__be32 client_ip;
		__be32 your_ip;
		__be32 server_ip;
		__be32 relay_ip;
		uint8_t hw_addr[16];
		uint8_t serv_name[64];
		uint8_t boot_file[128];
		uint8_t exten[312];
} __attribute__((__packed__));

extern __be32 my_ip;
extern __be32 server_ip;

__u16 checksum(__u16 *buf, __u32 size);
int dhcp_eth_init(char *buf, uint8_t type);
int dhcp_ip_init(char *buf);
int dhcp_udp_init(char *buf);
int dhcp_bootp_init(char *buf, uint8_t adapt_type);
void set_opts(uint8_t *buf, uint8_t mt);
int is_dhcp_pack_for_me(char *buf, uint8_t mt, uint8_t adapt_type);
void save_ip(char *buf);
#endif
