/* ndndump.c 
 * adapted from ccn plugin for wireshark
 */
#include "headers.h"
#include <ccn/ccn.h>
#include <ccn/ccnd.h>
#include <ccn/coding.h>
#include <ccn/uri.h>
#include <sys/time.h>

#define MAX_SNAPLEN 65535
#define CCN_MIN_PACKET_SIZE 5


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int dissect_ccn(const char *payload, int size_payload);
int dissect_ccn_interest(const unsigned char *ccnb, int ccnb_size);
int dissect_ccn_content(const unsigned char *ccnb, int ccnb_size);
void print_intercept_time();

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* declare pointers to packet headers */
	const struct ether_header *ether_hdr;
	const struct ip *ip_hdr;
	const struct udphdr *udp_hdr;
	const struct tcphdr *tcp_hdr;
	const char *payload;

	int size_ip;
	int size_udp;
	int size_tcp;
	int size_payload;

	ether_hdr = (struct ether_header *) (packet);
	ip_hdr = (struct ip *) (packet + ETHER_HDRLEN);
	size_ip = IP_HL(ip_hdr) * 4;
	if (size_ip < 20) {
		fprintf(stderr, "invalid IP header len %u bytes\n", size_ip);
		return;
	}

	printf("From: %s\t\tTo:%s\n", inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst));

	switch(ip_hdr->ip_p) {
		case IPPROTO_UDP:
			udp_hdr = (struct udphdr *)(packet + ETHER_HDRLEN + size_ip);
			size_udp = UDP_HEADER_LEN;
			size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_udp);
			payload = (const char *)(packet + ETHER_HDRLEN + size_ip + size_udp);
			dissect_ccn(payload, size_payload);
			break;
		case IPPROTO_TCP:
			tcp_hdr = (struct tcphdr *)(packet + ETHER_HDRLEN + size_ip);
			size_tcp = TH_OFF(tcp_hdr) * 4;
			if (size_tcp < 20) {
				fprintf(stderr, "Invalid TCP Header len: %u bytes\n", size_tcp);
				return;
			}
			payload = (const char *)(packet + ETHER_HDRLEN + size_ip + size_tcp);
			size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_tcp);
			dissect_ccn(payload, size_payload);
			break;
		default:
			return;
	}


}

int dissect_ccn(const char *payload, int size_payload) {
	struct ccn_skeleton_decoder skel_decoder;
	struct ccn_skeleton_decoder *sd;
	struct ccn_charbuf *c;
	int packet_type = 0;
	int packet_type_len = 0;
	unsigned char *ccnb;

	if (size_payload < CCN_MIN_PACKET_SIZE)
		return 0;
	
	sd = &skel_decoder;
	memset(sd, 0, sizeof(*sd));
	/* set CCN_DSTATE_PAUSE so that the decoder returns
	 * just after recognizing each token. use CCN_GET_TT
	 * _FROM_DSTATE() to extract the token type
	 */
	sd->state |= CCN_DSTATE_PAUSE;
	ccnb = (unsigned char *)malloc(size_payload);
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
int dissect_ccn_interest(const unsigned char *ccnb, int ccnb_size) {
	printf("dissecting ccn interest");
	struct ccn_parsed_interest interest;
	struct ccn_parsed_interest *pi = &interest;
	struct ccn_charbuf *c;
	struct ccn_indexbuf *comps;
	const unsigned char *comp;
	size_t comp_size;
	const unsigned char *blob;
	size_t blob_size;
	ssize_t len;
	double lifetime;
	int res;
	int i;

	comps = ccn_indexbuf_create();
	res = ccn_parse_interest(ccnb, ccnb_size, pi, comps);
	if (res < 0) 
		return res;

	/* Name */
	len = pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name];
	c = ccn_charbuf_create();
	ccn_uri_append(c, ccnb, ccnb_size, 1);
	printf("Interest Name is %s\n", ccn_charbuf_as_string(c));
	for (i = 0; i < comps->n - 1; i++) {
		res = ccn_name_comp_get(ccnb, comps, i, &comp, &comp_size);
		/* TODO: do something */
	}

	/* MinSuffixComponents */
	len = pi->offset[CCN_PI_E_MinSuffixComponents] - pi->offset[CCN_PI_B_MinSuffixComponents];
	if (len > 0) {
		int min_sc = pi->min_suffix_comps;
		/* TODO: do something */
	}

	/* MaxSuffixComponents */
	len = pi->offset[CCN_PI_E_MaxSuffixComponents] - pi->offset[CCN_PI_B_MaxSuffixComponents];
	if (len > 0) {
		int max_sc = pi->max_suffix_comps;
		/* TODO: do something */
	}

	/* PublisherPublicKeyDigest */
	/* Exclude */

	/* ChildSelector */
	len = pi->offset[CCN_PI_E_ChildSelector] - pi->offset[CCN_PI_B_ChildSelector];
	if (len > 0) {
		int order = pi->orderpref;
		printf("ChildSelector: ");
		switch (order) {
		case 0: printf("leftmost/least\n");
				break;
		case 1: printf("rightmost/greatest\n");
				break;
		default: printf("invalid\n");
		}
	}

	/* AnswerOriginKind */
	len = pi->offset[CCN_PI_E_AnswerOriginKind] - pi->offset[CCN_PI_B_AnswerOriginKind];
	if (len > 0) {
		int origin = pi->answerfrom;
		/* TODO: do something */
	}

	/* Scope */
	len = pi->offset[CCN_PI_E_Scope] - pi->offset[CCN_PI_B_Scope];
	if (len > 0) {
		int scope = pi->scope;
		/* TODO: do something */
	}

	/* InterestLifeTime */
	len = pi->offset[CCN_PI_E_InterestLifetime] - pi->offset[CCN_PI_B_InterestLifetime];
	if (len > 0) {
		ccn_ref_tagged_BLOB(CCN_DTAG_InterestLifetime, ccnb, pi->offset[CCN_PI_B_InterestLifetime], pi->offset[CCN_PI_E_InterestLifetime], &blob, &blob_size);
		lifetime = 0.0;
		for (i = 0; i < blob_size; i++)
			lifetime = lifetime *256.0 + (double)blob[i];
		lifetime /= 4096.0;
		/* TODO: do something */
	}

	/* Nonce */
	len = pi->offset[CCN_PI_E_Nonce] - pi->offset[CCN_PI_B_Nonce];
	if (len > 0) {
		ccn_ref_tagged_BLOB(CCN_DTAG_Nonce, ccnb, pi->offset[CCN_PI_B_Nonce], pi->offset[CCN_PI_E_Nonce], &blob, &blob_size);
		/* TODO: do something */
	}

	return 1;

}

int dissect_ccn_content(const unsigned char *ccnb, int ccnb_size) {
	printf("dissecting ccn content");
	struct ccn_parsed_ContentObject co;
	struct ccn_parsed_ContentObject *pco = &co;
	struct ccn_charbuf *c;
	struct ccn_indexbuf *comps;
	const unsigned char *comp;
	size_t comp_size;
	size_t blob_size;
	const unsigned char *blob;
	int len;
	int i;
	double dt;
	int res;

	comps = ccn_indexbuf_create();
	res = ccn_parse_ContentObject(ccnb, ccnb_size, pco, comps);
	if (res <0) 
		return res;
	
	/* Signature */
	len = pco->offset[CCN_PCO_E_Signature] - pco->offset[CCN_PCO_B_Signature];
	/* TODO: do something with signature */

	/* DigestAlogorith */
	/* Witness */
	/* Signature bits */
	
	/* Name */
	len = pco->offset[CCN_PCO_E_Name] - pco->offset[CCN_PCO_B_Name];
	c = ccn_charbuf_create();
	ccn_uri_append(c, ccnb, ccnb_size, 1);
	printf("ContentObject name is %s\n", ccn_charbuf_as_string(c));

	/* Name Components */
	for (i = 0; i < comps->n - 1; i ++) {
		res = ccn_name_comp_get(ccnb, comps, i, &comp, &comp_size);
		/* TODO: do something */
	}

	/* SignedInfo */
	/* PublisherPublicKeyDigest */

    /* Timestamp */

	/* Type */
	len = pco->offset[CCN_PCO_E_Type] - pco->offset[CCN_PCO_B_Type];
	if (len > 0) {
		res = ccn_ref_tagged_BLOB(CCN_DTAG_Type, ccnb, pco->offset[CCN_PCO_B_Type], pco->offset[CCN_PCO_E_Type], &blob, &blob_size);
		int type = pco->type;
		printf("Content Type is: ");
		switch (type) {
		case CCN_CONTENT_DATA:  printf("Data\n");
								break;
		case CCN_CONTENT_ENCR:	printf("Encrypted\n");
								break;
		case CCN_CONTENT_GONE:  printf("Gone\n");
								break;
		case CCN_CONTENT_KEY:	printf("Key\n");
								break;
		case CCN_CONTENT_LINK:	printf("Link\n");
								break;
		case CCN_CONTENT_NACK:	printf("Nack\n");
								break;
		default:
			break;
		}

	}
	/* FreshSeconds */
    len = pco->offset[CCN_PCO_E_FreshnessSeconds] - pco->offset[CCN_PCO_B_FreshnessSeconds];
    if (len > 0) {
        res = ccn_ref_tagged_BLOB(CCN_DTAG_FreshnessSeconds, ccnb,
                                  pco->offset[CCN_PCO_B_FreshnessSeconds],
                                  pco->offset[CCN_PCO_E_FreshnessSeconds],
                                  &blob, &blob_size);
        i = ccn_fetch_tagged_nonNegativeInteger(CCN_DTAG_FreshnessSeconds, ccnb,
                                                pco->offset[CCN_PCO_B_FreshnessSeconds],
                                                pco->offset[CCN_PCO_E_FreshnessSeconds]);
        
		/* TODO: do something */
    }

	/* FinalBlockID */
    len = pco->offset[CCN_PCO_E_FinalBlockID] - pco->offset[CCN_PCO_B_FinalBlockID];
    if (len > 0) {
        res = ccn_ref_tagged_BLOB(CCN_DTAG_FinalBlockID, ccnb,
                                  pco->offset[CCN_PCO_B_FinalBlockID],
                                  pco->offset[CCN_PCO_E_FinalBlockID],
                                  &blob, &blob_size);
        
		/* TODO: do something */
    }
	/* KeyLocator */

	/* Content */
	len = pco->offset[CCN_PCO_E_Content] - pco->offset[CCN_PCO_B_Content];
	res = ccn_ref_tagged_BLOB(CCN_DTAG_Content, ccnb, pco->offset[CCN_PCO_B_Content], pco->offset[CCN_PCO_E_Content], &blob, &blob_size);
	/* TODO: do something */

	return (ccnb_size);

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

	if (argc > 0) {
		dev = argv[1];
	} else 
		dev = pcap_lookupdev(errbuf);
	if (NULL == dev) {
		fprintf(stderr, "couldn't find default device %s\n", errbuf);
		return 2;
	}
	printf("Device: %s\n", dev);

	if (-1 == pcap_lookupnet(dev, &net, &mask, errbuf)) {
		fprintf(stderr, "couldn't get netmask for device %s: %s\n", dev, errbuf);
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

void print_intercept_time() {
	struct timeval tv;
	struct timezone tz;
	struct tm *tm;
	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);
	printf(" %d: %02d: %02d %d ", tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
}
