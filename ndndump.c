#include "headers.h"
#include <ccn/ccn.h>
#include <ccn/ccnd.h>
#include <ccn/coding.h>
#include <ccn/uri.h>

#define MAX_SNAPLEN 65535
#define CCN_MIN_PACKET_SIZE 5

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int dissect_ccn(const char *payload, int size_payload);
int dissect_ccn_interest();
int dissect_ccn_content();

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* declare pointers to packet headers */
	const struct ether_header *ether_hdr;
	const struct ip *ip_hdr;
	const struct udphdr *udp_hdr;
	const char *payload;

	int size_ip;
	int size_udp;
	int size_payload;

	ether_hdr = (struct ether_header *) (packet);
	ip_hdr = (struct ip *) (packet + ETHER_HDRLEN);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		fprintf(stderr, "invalid IP header len %u bytes\n", size_ip);
		return;
	}
	printf("From: %s\t\tTo:%s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

	switch(ip->ip_p) {
		case IPPROTO_UDP:
			break;
		default:
			return;
	}

	udp_hdr = (struct udphdr *)(packet + ETHER_HDRLEN + size_ip);
	size_udp = UDP_HEADER_LEN;
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
	payload = (const char *)(packet + ETHER_HDRLEN + size_ip + size_udp);
	dissect_ccn(payload, size_payload);
}

int dissect_ccn(const char *payload, int size_payload) {
	struct ccn_skeleton_decoder skel_decoder;
	struct ccn_skeleton_decoder *sd;
	struct ccn_charbuf *c;
	int packet_type = 0;
	int packet_type_len = 0;
	const unsigned char *ccnb;

	if (size_payload < CCN_MIN_PACKET_SIZE)
		return 0;
	
	sd = &skel_decoder;
	memset(sd, 0, sizeof(*sd));
	/* set CCN_DSTATE_PAUSE so that the decoder returns
	 * just after recognizing each token. use CCN_GET_TT
	 * _FROM_DSTATE() to extract the token type
	 */
	sd->state |= CCN_DSTATE_PAUSE;
	ccnb = (const unsigned char *)malloc(size_payload);
	memcpy(ccnb, payload, size_payload);
	ccn_skeleton_decode(sd, ccnb, size_payload);
	if (sd->state < 0)
		return 0;
	if (CCN_DTAG == CCN_GET_TT_FROM_DSTATE(sd->state)) {
		packet_type = sd->numval;
		packet_type_len = sd->index;
	} else {
		return 0;
	}
	memset(sd, 0, sizeof(*sd));
	ccn_skeleton_decode(sd, ccnb, size_payload);
	/* test the end of decoding */
	if (!CCN_FINAL_DSTATE(sd->state)) {
		return -1;
	}
	
	/* CCN URI in c */
	c = ccn_charbuf_create();
	ccn_uri_append(c, ccnb, size_payload, 1);
	
	switch (packet_type) {
		case CCN_DTAG_ContentObject:
			if (0 > dissect_ccn_content(ccnb, sd->index))
				return 0;
			break;
		case CCN_DTAG_Interest:
			if (0 > dissect_ccn_interest(ccnb, sd->index))
				return 0;
			break;
		default:
			break;
	}

	return (sd->index);

}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;						/* Session handle */
	struct bpf_program fp;				/* Compiled filter expression */
	char filter_exp[] = "ip";			
	bpf_u_int32 mask;					/* Netmask of the sniffing device */
	bpf_u_int32 net;					/* IP of the sniffing device */
	struct pcap_pkthdr header;			/* Header that pcap gives us */
	const u_char *packet;				/* Actual packet */

	dev = pcap_lookupdev(errbuf);
	if (NULL == dev) {
		fprintf(stderr, "couldn't find default device %s\n", errbuf);
		return 2;
	}
	printf("Device: %s\n", dev);

	if (-1 == pcap_lookupnet(dev, &net, &mask, errbuf)) {
		fprintf(stderr, "couldn't get netmask for device %s\n", dev);
	}
	
	handle = pcap_open_live(dev, MAX_SNAPLEN, 0, 1000, errbuf);
	if (NULL == handle) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	if (-1 == pcap_compile(handle, &fp, filter_exp, 0, net)) {
		fprintf(stderr, "couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	if (-1 == pcap_setfilter(handle, &fp)) {
		fprintf(stderr, "couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	pcap_loop(handle, -1, got_packet, NULL);
	
	pcap_freecode(&fp);
	pcap_close(handle);
	
	return 0;
}
