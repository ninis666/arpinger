
#include <stdio.h>
#include <string.h>
#include "arp_frame.h"
#include "log.h"

void arp_frame_req(const struct arp_dev *dev, struct arp_frame *req)
{
	struct in_addr dest;

	/*
	 * Ethernet HDR
	 */
	memset(&req->eth.ether_dhost, 0xFF, sizeof req->eth.ether_dhost);
	memcpy(&req->eth.ether_shost, dev->hwaddr, sizeof req->eth.ether_shost);
	req->eth.ether_type = htons(ETHERTYPE_ARP);

	/*
	 * ARP HDR
	 */
	req->arp.arp_hrd = htons(ARPHRD_ETHER);
	req->arp.arp_pro = htons(ETHERTYPE_IP);
	req->arp.arp_hln = ETH_ALEN;
	req->arp.arp_pln = 4;
	req->arp.arp_op = htons(ARPOP_REQUEST);
	memcpy(&req->arp.arp_sha, dev->hwaddr, sizeof dev->hwaddr);
	memcpy(&req->arp.arp_spa, &dev->addr, sizeof dev->addr);
	memset(&req->arp.arp_tha, 0xFF, sizeof dev->hwaddr);

	dest.s_addr = dev->broadcast.s_addr + htonl(1);
	memcpy(&req->arp.arp_tpa, &dest, sizeof dest);
}

struct in_addr arp_frame_get_target_addr(const struct arp_frame *frame)
{
	return *((struct in_addr *)frame->arp.arp_tpa);
}

void arp_frame_set_target_addr(struct arp_frame *frame, const struct in_addr addr)
{
	*((struct in_addr *)frame->arp.arp_tpa) = addr;
}

struct in_addr arp_frame_get_source_addr(const struct arp_frame *frame)
{
	return *((struct in_addr *)frame->arp.arp_spa);
}

const uint8_t *arp_frame_get_source_hwaddr(const struct arp_frame *frame)
{
	return frame->arp.arp_sha;
}

int arp_frame_check(const struct arp_frame *frame)
{

	if (frame->eth.ether_type != htons(ETH_P_ARP))
		return 0;

	if (frame->arp.arp_hrd != htons(ARPHRD_ETHER))
		return 0;

	if (frame->arp.arp_pro != htons(ETHERTYPE_IP))
		return 0;

	if (frame->arp.arp_hln != sizeof frame->arp.arp_sha)
		return 0;

	if (frame->arp.arp_pln != sizeof frame->arp.arp_spa)
		return 0;

	return 1;
}

size_t arp_frame_dump(const struct arp_frame *frame, char **res)
{
	FILE *fp;
	char *ptr = NULL;
	size_t size = 0;

	fp = open_memstream(&ptr, &size);
	if (fp == NULL) {
		err("open_memstream failed : %m\n");
		goto err;
	}

	fprintf(fp, "eth.ether_dhost : %02x:%02x:%02x:%02x:%02x:%02x\n", frame->eth.ether_dhost[0], frame->eth.ether_dhost[1], frame->eth.ether_dhost[2], frame->eth.ether_dhost[3], frame->eth.ether_dhost[4], frame->eth.ether_dhost[5]);
	fprintf(fp, "eth.ether_shost : %02x:%02x:%02x:%02x:%02x:%02x\n", frame->eth.ether_shost[0], frame->eth.ether_shost[1], frame->eth.ether_shost[2], frame->eth.ether_shost[3], frame->eth.ether_shost[4], frame->eth.ether_shost[5]);
	fprintf(fp, "eth.ether_type	: %#06x\n", htons(frame->eth.ether_type));

	if (frame->eth.ether_type != htons(ETH_P_ARP)) {
		fprintf(fp, "Unexpected ether_type (%#06x expected)\n", ETH_P_ARP);
		goto end;
	}

	fprintf(fp, "\tarp.arp_hrd = %#06x\n", htons(frame->arp.arp_hrd));
	if (frame->arp.arp_hrd != htons(ARPHRD_ETHER)) {
		fprintf(fp, "Unexpected arp.arp_hrd (%#06x expected)\n", ARPHRD_ETHER);
		goto end;
	}

	fprintf(fp, "\tarp.arp_pro = %#06x\n", htons(frame->arp.arp_pro));
	if (frame->arp.arp_pro != htons(ETHERTYPE_IP)) {
		fprintf(fp, "Unexpected arp.arp_pro (%#06x expected)\n", ETHERTYPE_IP);
		goto end;
	}

	fprintf(fp, "\tarp.arp_hln = %d\n", frame->arp.arp_hln);
	if (frame->arp.arp_hln != sizeof frame->arp.arp_sha) {
		fprintf(fp, "Unexpected arp.arp_hln (%zd expected)\n", sizeof frame->arp.arp_sha);
		goto end;
	}

	fprintf(fp, "\tarp.arp_pln = %d\n", frame->arp.arp_pln);
	if (frame->arp.arp_pln != sizeof frame->arp.arp_spa) {
		fprintf(fp, "Unexpected arp.arp_pln (%zd expected)\n", sizeof frame->arp.arp_spa);
		goto end;
	}

	fprintf(fp, "\tarp.arp_op  = %#06x\n", frame->arp.arp_op);

	fprintf(fp, "\tarp.arp_sha = %02x:%02x:%02x:%02x:%02x:%02x\n", frame->arp.arp_sha[0], frame->arp.arp_sha[1], frame->arp.arp_sha[2], frame->arp.arp_sha[3], frame->arp.arp_sha[4], frame->arp.arp_sha[5]);
	fprintf(fp, "\tarp.arp_tha = %02x:%02x:%02x:%02x:%02x:%02x\n", frame->arp.arp_tha[0], frame->arp.arp_tha[1], frame->arp.arp_tha[2], frame->arp.arp_tha[3], frame->arp.arp_tha[4], frame->arp.arp_tha[5]);

	fprintf(fp, "\tarp.arp_spa = %s\n", inet_ntoa(*((const struct in_addr *)frame->arp.arp_spa)));
	fprintf(fp, "\tarp.arp_tpa = %s\n", inet_ntoa(*((const struct in_addr *)frame->arp.arp_tpa)));

end:
	fclose(fp);
err:
	*res = ptr;
	return size;
}
