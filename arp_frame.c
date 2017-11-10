
#include <stdio.h>
#include <string.h>
#include "arp_frame.h"

void arp_frame_req(const struct arp_dev *dev, const struct in_addr dest, struct arp_frame *req)
{
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
	memcpy(&req->arp.arp_tpa, &dest, sizeof dest);
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

void arp_frame_dump(const struct arp_frame *frame)
{
	printf("eth.ether_dhost : %02x:%02x:%02x:%02x:%02x:%02x\n", frame->eth.ether_dhost[0], frame->eth.ether_dhost[1], frame->eth.ether_dhost[2], frame->eth.ether_dhost[3], frame->eth.ether_dhost[4], frame->eth.ether_dhost[5]);
	printf("eth.ether_shost : %02x:%02x:%02x:%02x:%02x:%02x\n", frame->eth.ether_shost[0], frame->eth.ether_shost[1], frame->eth.ether_shost[2], frame->eth.ether_shost[3], frame->eth.ether_shost[4], frame->eth.ether_shost[5]);
	printf("eth.ether_type  : %#06x\n", htons(frame->eth.ether_type));

	if (frame->eth.ether_type != htons(ETH_P_ARP)) {
		printf("Unexpected ether_type (%#06x expected)\n", ETH_P_ARP);
		goto end;
	}

	printf("\tarp.arp_hrd = %#06x\n", htons(frame->arp.arp_hrd));
	if (frame->arp.arp_hrd != htons(ARPHRD_ETHER)) {
		printf("Unexpected arp.arp_hrd (%#06x expected)\n", ARPHRD_ETHER);
		goto end;
	}

	printf("\tarp.arp_pro = %#06x\n", htons(frame->arp.arp_pro));
	if (frame->arp.arp_pro != htons(ETHERTYPE_IP)) {
		printf("Unexpected arp.arp_pro (%#06x expected)\n", ETHERTYPE_IP);
		goto end;
	}

	printf("\tarp.arp_hln = %d\n", frame->arp.arp_hln);
	if (frame->arp.arp_hln != sizeof frame->arp.arp_sha) {
		printf("Unexpected arp.arp_hln (%zd expected)\n", sizeof frame->arp.arp_sha);
		goto end;
	}

	printf("\tarp.arp_pln = %d\n", frame->arp.arp_pln);
	if (frame->arp.arp_pln != sizeof frame->arp.arp_spa) {
		printf("Unexpected arp.arp_pln (%zd expected)\n", sizeof frame->arp.arp_spa);
		goto end;
	}

	printf("\tarp.arp_op  = %#06x\n", frame->arp.arp_op);

	printf("\tarp.arp_sha = %02x:%02x:%02x:%02x:%02x:%02x\n", frame->arp.arp_sha[0], frame->arp.arp_sha[1], frame->arp.arp_sha[2], frame->arp.arp_sha[3], frame->arp.arp_sha[4], frame->arp.arp_sha[5]);
	printf("\tarp.arp_tha = %02x:%02x:%02x:%02x:%02x:%02x\n", frame->arp.arp_tha[0], frame->arp.arp_tha[1], frame->arp.arp_tha[2], frame->arp.arp_tha[3], frame->arp.arp_tha[4], frame->arp.arp_tha[5]);

	printf("\tarp.arp_spa = %s\n", inet_ntoa(*((const struct in_addr *)frame->arp.arp_spa)));
	printf("\tarp.arp_tpa = %s\n", inet_ntoa(*((const struct in_addr *)frame->arp.arp_tpa)));

end:
	return;
}
