#include "dhcp_client.h"

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: ./DHCP_CLIENT [adapter] (adapter: 0 - wlp, 1 - enp)\n");
		return 0;
	}
	if (atoi(argv[1]) / 2 > 0) {
		return -EINVAL;
	}
	char msg[MSG_LEN];
	int socket_fd;
	int ret;
	struct sockaddr_ll target;
	socklen_t target_size;


	memset(&target, 0, sizeof(target));
	target.sll_family = AF_PACKET;
	if (atoi(argv[1])) {
		target.sll_ifindex = if_nametoindex("enp2s0");
	} else {
		target.sll_ifindex = if_nametoindex("wlp1s0");
	}
	target.sll_halen = 6;
	target_size = sizeof(target);

	socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (socket_fd == -1) {
		perror("socket");
		return -1;
	}

	memset(msg, 0, MSG_LEN);
	ret = dhcp_eth_init(msg, (uint8_t) atoi(argv[1]));
	if (ret < 0) {
		close(socket_fd);
		return ret;
	}

	dhcp_ip_init(msg);
	dhcp_udp_init(msg);
	dhcp_bootp_init(msg, (uint8_t) atoi(argv[1]));
	ret = sendto(socket_fd, msg, MSG_LEN, 0, (struct sockaddr*)&target, target_size);
	if (ret == -1) {
		perror("send");
		close(socket_fd);
		return ret;
	}
	do {
		ret = recvfrom(socket_fd, msg, MSG_LEN, 0, (struct sockaddr *) &target, &target_size);
	} while (!is_dhcp_pack_for_me(msg, DHCPOFFER, (uint8_t) atoi(argv[1])));

	save_ip(msg);

	memset(&target, 0, sizeof(target));
	target.sll_family = AF_PACKET;
	if (atoi(argv[1])) {
		target.sll_ifindex = if_nametoindex("enp2s0");
	} else {
		target.sll_ifindex = if_nametoindex("wlp1s0");
	}
	target.sll_halen = 6;
	target_size = sizeof(target);


	memset(msg, 0, MSG_LEN);
	ret = dhcp_eth_init(msg, (uint8_t) atoi(argv[1]));
	if (ret < 0) {
		close(socket_fd);
		return ret;
	}

	dhcp_ip_init(msg);
	dhcp_udp_init(msg);
	dhcp_bootp_init(msg, (uint8_t) atoi(argv[1]));
	ret = sendto(socket_fd, msg, MSG_LEN, 0, (struct sockaddr*)&target, target_size);
	if (ret == -1) {
		perror("send1");
		close(socket_fd);
		return ret;
	}
	do {
		ret = recvfrom(socket_fd, msg, MSG_LEN, 0, (struct sockaddr *) &target, &target_size);
	} while (!is_dhcp_pack_for_me(msg, DHCPACK, (uint8_t) atoi(argv[1])));

	struct in_addr ia;
	ia.s_addr = my_ip;
	printf("Your IP: %s\n", inet_ntoa(ia));
	ia.s_addr = server_ip;
	printf("Server IP: %s\n", inet_ntoa(ia));

	return 0;
}

