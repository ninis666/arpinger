
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include "arp_dev.h"
#include "err.h"

int arp_dev_init(int sock, struct arp_dev *res, const char *name)
{
	int ret = -1;
	struct ifreq req;
	int new_sock;

	if (sock < 0) {
		new_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (new_sock < 0) {
			err("socket : %m\n");
			goto err;
		}
		sock = new_sock;
	} else
		new_sock = -1;

	snprintf(req.ifr_name, sizeof req.ifr_name, "%s", name);

	if (ioctl(sock, SIOCGIFINDEX, &req, sizeof req) < 0) {
		err("ioctl SIOCGIFINDEX : %m\n");
		goto err_close;
	}
	res->index = req.ifr_ifindex;

	if (ioctl(sock, SIOCGIFFLAGS, &req, sizeof req) < 0) {
		err("ioctl SIOCGIFFLAGS : %m\n");
		goto err_close;
	}
	res->flags = req.ifr_flags;

	if (ioctl(sock, SIOCGIFPFLAGS, &req, sizeof req) < 0)
		res->private_flags = 0;
	else
		res->private_flags = req.ifr_flags;

	memset(&res->addr, 0, sizeof res->addr);
	if (ioctl(sock, SIOCGIFADDR, &req, sizeof req) >= 0) {
		if (req.ifr_addr.sa_family == AF_INET)
			res->addr = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr;
	}

	memset(&res->broadcast, 0, sizeof res->broadcast);
	if (ioctl(sock, SIOCGIFBRDADDR, &req, sizeof req) >= 0) {
		if (req.ifr_addr.sa_family == AF_INET)
			res->broadcast = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr;
	}

	memset(&res->netmask, 0, sizeof res->netmask);
	if (ioctl(sock, SIOCGIFNETMASK, &req, sizeof req) >= 0) {
		if (req.ifr_addr.sa_family == AF_INET)
			res->netmask = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr;
	}

	memset(&res->hwaddr, 0, sizeof res->hwaddr);
	if (ioctl(sock, SIOCGIFHWADDR, &req, sizeof req) >= 0) {
		if (req.ifr_addr.sa_family == ARPHRD_ETHER)
			memcpy(res->hwaddr, req.ifr_addr.sa_data, sizeof res->hwaddr);
	}

	res->name = strndup(req.ifr_name, IFNAMSIZ);
	if (res->name == NULL) {
		err("strndup: %m\n");
		goto err_close;
	}

	ret = 0;

err_close:
	if (new_sock >= 0)
		close(new_sock);
err:
	return ret;
}

void arp_dev_deinit(struct arp_dev *info)
{
	free(info->name);
	info->name = NULL;
}

ssize_t arp_dev_discover(struct arp_dev **res)
{
	int sock;
	struct ifconf ifconf;
	struct arp_dev *table;
	ssize_t count;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		err("socket SOCK_DGRAM: %m\n");
		goto err;
	}

	memset(&ifconf, 0, sizeof ifconf);
	if (ioctl(sock, SIOCGIFCONF, &ifconf, sizeof ifconf) < 0) {
		err("ioctl SIOCGIFCONF: %m\n");
		goto err_close;
	}

	if (ifconf.ifc_len <= 0) {
		ifconf.ifc_len = 0;
		goto end;
	}

	ifconf.ifc_len = ifconf.ifc_len;
	ifconf.ifc_req = calloc(1, ifconf.ifc_len);
	if (ifconf.ifc_req == NULL) {
		err("calloc: %m\n");
		goto err_close;
	}

	if (ioctl(sock, SIOCGIFCONF, &ifconf, sizeof ifconf + ifconf.ifc_len) < 0) {
		err("ioctl SIOCGIFCONF: %m\n");
		goto err_free_ifconf;
	}

	if (ifconf.ifc_len <= 0) {
		count = 0;
		goto end;
	}

	table = NULL;
	count = ifconf.ifc_len / sizeof ifconf.ifc_req[0];

	table = calloc(count, sizeof table[0]);
	if (table == NULL) {
		err("calloc: %m\n");
		goto err_free_ifconf;
	}

	for (ssize_t i = 0 ; i < count ; i++) {
		if (arp_dev_init(sock, &table[i], ifconf.ifc_req[i].ifr_name) < 0)
			goto err_free_table;
	}

end:
	free(ifconf.ifc_req);
	close(sock);
	*res = table;
	return count;

err_free_table:
	for (int i = 0 ; i < count ; i++)
		free(table[i].name);
	free(table);
err_free_ifconf:
	free(ifconf.ifc_req);
err_close:
	close(sock);
err:
	*res = NULL;
	return -1;
}

void arp_dev_dump(const struct arp_dev *info)
{
	printf("[%d] %s\n", info->index, info->name);
	printf("\taddr	    : %s\n", inet_ntoa(info->addr));
	printf("\tnetmask   : %s\n", inet_ntoa(info->netmask));
	printf("\tbroadcast : %s\n", inet_ntoa(info->broadcast));
	printf("\thwaddress : %02x:%02x:%02x:%02x:%02x:%02x\n", info->hwaddr[0], info->hwaddr[1], info->hwaddr[2], info->hwaddr[3], info->hwaddr[4], info->hwaddr[5]);
}
