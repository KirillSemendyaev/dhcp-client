#include "dhcp_client.h"

static const uint8_t my_enp_mac[6] = {0xe8, 0x03, 0x9a, 0xb6, 0xf2, 0xde};
static const uint8_t my_wlp_mac[6] = {0xb8, 0x03, 0x05, 0xab, 0x70, 0xc5};
static const uint8_t dhcp_cookie[4] = {0x63, 0x82, 0x53, 0x63};
static const uint8_t req_params[] = {
		1,		// Request netmask
		3,		// Request default gateway
//		6,		// Request DNS server
//		12,		// Request host name
//		15,		// Request domain name
//		17,		// Request bootfile path
//		26,		// Request MTU
//		40		// Request NIS domain name
};

__be32 my_ip = 0;
__be32 netmask = 0;
__be32 server_ip = 0;

__u16 checksum(__u16 *buf, __u32 size)
{
	if ((buf == NULL) || (size < 1)) {
		return 0;
	}
	__u32 sum = 0, ret;

	for (int i = 0; i < (size / 2); ++i) {
		sum += buf[i];
	}
	ret = (sum >> 16) + (sum & 0xffff);
	return ~ret;
}

int dhcp_eth_init(char *buf, uint8_t adapt_type)
{
	if (buf == NULL) {
		perror("eth_init");
		return -EFAULT;
	}

	if (adapt_type >> 1 > 0) {
		perror("eth_init");
		return -EINVAL;
	}

	struct bootp_hdr *bhdr = (struct bootp_hdr*)buf;
	bhdr->ethh.h_proto = htons(ETH_P_IP);
	memset(bhdr->ethh.h_dest, 0xff, 6); // broadcast mac
	if (adapt_type) {
		memcpy(bhdr->ethh.h_source, my_enp_mac, 6);
	} else {
		memcpy(bhdr->ethh.h_source, my_wlp_mac, 6);
	}
	return 0;
}

int dhcp_ip_init(char *buf)
{
	if (buf == NULL) {
		perror("ip_init");
		return -EFAULT;
	}
	struct bootp_hdr *bhdr = (struct bootp_hdr*) buf;
	bhdr->iph.version = 4;
	bhdr->iph.ihl = sizeof(struct iphdr) / 4;
	bhdr->iph.tos = 0;
	bhdr->iph.tot_len = htons(MSG_LEN - sizeof(struct ethhdr));
	bhdr->iph.id = htons(8008);
	bhdr->iph.frag_off = htons(IP_DF);
	bhdr->iph.ttl = 128;
	bhdr->iph.protocol = IPPROTO_UDP;
	bhdr->iph.daddr = inet_addr("255.255.255.255");
	bhdr->iph.check = checksum((__u16 *) &(bhdr->iph), sizeof(struct iphdr));
	return 0;
}

int dhcp_udp_init(char *buf)
{
	if (buf == NULL) {
		perror("udp_init");
		return -EFAULT;
	}

	struct bootp_hdr *bhdr = (struct bootp_hdr*) buf;
	bhdr->udph.dest = htons(67);
	bhdr->udph.source = htons(68);
	bhdr->udph.len = htons(MSG_LEN - sizeof(struct iphdr) - sizeof(struct ethhdr));
	return 0;
}

int dhcp_bootp_init(char *buf, uint8_t adapt_type)
{
	if (buf == NULL) {
		perror("bootp_init");
		return -EFAULT;
	}

	uint8_t mt = ((server_ip == 0) ? DHCPDISCOVER : DHCPREQUEST);

	struct bootp_hdr *bhdr = (struct bootp_hdr*) buf;

	bhdr->op = 1; 						// 1 - BOOTP_REQUEST, 2 - BOOTP_REPLY
	bhdr->htype = 1; 					// 1 - Ethernet 10Mbps
	bhdr->hlen = 6; 					// 6 - usual length
//	bhdr->hops = 0; 				//
	bhdr->xid = 999999;				// TODO: get random int
//	bhdr->secs = 0;						//
//	bhdr->flags = 0; 					// 0 - do nothing special
//	bhdr->client_ip = 0;			// 0, because we dont have clients
//	bhdr->your_ip = 0;				// 0, because we dont have it
//	bhdr->server_ip = 0;			// 0, because we dont have it
//	bhdr->relay_ip = 0;				// 0, because we dont have anything
	if (adapt_type) {
		memcpy(bhdr->hw_addr, my_enp_mac, 6);
	} else {
		memcpy(bhdr->hw_addr, my_wlp_mac, 6);
	}
	set_opts(bhdr->exten, mt);
}

void set_opts(uint8_t *buf, uint8_t mt)
{
	uint8_t *e = buf;
	memcpy(e, dhcp_cookie, 4);
	e += 4;

	*e++ = 53; 									// Option (53) - DHCP message type
	*e++ = 1;  									// Option (53) length
	*e++ = mt;									// Option (53) value

	if (mt == DHCPREQUEST) {
		*e++ = 54; 								// Option (54) - Server IP
		*e++ = 4;
		memcpy(e, &server_ip, 4);
		e += 4;

		*e++ = 50;								// Option (50) - Requested IP
		*e++ = 4;
		memcpy(e, &my_ip, 4);
		e += 4;
	}

	*e++ = 55; 									// Option (55) - Requested parameters
	*e++ = sizeof(req_params);
	memcpy(e, req_params, sizeof(req_params));
	e += sizeof(req_params);

	*e++ = 255;									// Option (255) - End of exten
}

int is_dhcp_pack_for_me(char *buf, uint8_t mt, uint8_t adapt_type) {
	struct bootp_hdr *bhdr = (struct bootp_hdr *) buf;
	int flag = 1;
	uint8_t *e = bhdr->exten;
	if (bhdr->op != BOOTP_REPLY) {
		return 0;
	}

	if (adapt_type) {
		flag = memcmp(bhdr->hw_addr, my_enp_mac, 6);
	} else {
		flag = memcmp(bhdr->hw_addr, my_wlp_mac, 6);
  }
	if (flag) {
		return 0;
	}

	if (memcmp(e, dhcp_cookie, 4)) {
		return 0;
	}

	e += 6;
	if (*e != mt) {
		return 0;
	}
	return 1;
}

void save_ip(char *buf)
{
	struct bootp_hdr *bhdr = (struct bootp_hdr*) buf;
	uint8_t *e = bhdr->exten;

	e += 4;

	while ((*e != 54) && (*e != 255)) {
//		printf("e: %d\n", *e);
		e++;
		e += *e + 1;
	}

	if (*e == 255) {
		return;
	}

	e += 2;

	memcpy(&server_ip, e, 4);
	my_ip = bhdr->your_ip;
}
/*int main(int argc, char **argv)
{
	char buf[512] = {0};
	int socket_fd, ret;
	size_t len;
	struct sockaddr_ll target;
	socklen_t target_size;

	memset(&target, 0, sizeof(target));
	target.sll_family = AF_PACKET;
	target.sll_ifindex = if_nametoindex("enp2s0");
	target.sll_halen = 6;
	target_size = sizeof(target);
	len = sizeof(buf);

	ethh = buf;
	iph = buf + sizeof(struct ethhdr);
	udph = buf + sizeof(struct iphdr) + sizeof(struct ethhdr);

	udph->check = 0;
	udph->dest = htons(atoi(argv[2]));
	udph->source = htons(60000);
	udph->len = htons(len - sizeof(struct iphdr) - sizeof(struct ethhdr));

	iph->version = 4;
	iph->ihl = sizeof(struct iphdr) / 4;
	iph->tos = 0;
	iph->tot_len = htons(len - sizeof(struct ethhdr));
	iph->id = htons(8008);
	iph->frag_off = 0x40;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = inet_addr(argv[3]);
	iph->daddr = inet_addr(argv[1]);
	iph->check = checksum((__u16 *)iph, sizeof(struct iphdr));

	sprintf(buf + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr), "Hello!");
	printf("%s\n", buf + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr));

	ret = sendto(socket_fd, buf, len, 0, (struct sockaddr*)&target, target_size);
	if (ret == -1) {
		perror("send");
		return -3;
	}

	do {
		ret = recvfrom(socket_fd, buf, len, 0, (struct sockaddr *) &target, &target_size);
		printf("%d: %s\n", ntohs(udph->dest), buf + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr));
	} while (ntohs(udph->dest) != 60000);
	printf("IN: %s\n", buf + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr));
	close(socket_fd);
	return 0;
}*/


