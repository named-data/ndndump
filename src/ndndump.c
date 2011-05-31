/* ndndump.c 
 * adapted from ccn plugin for wireshark
 */
#include "headers.h"
#include <ccn/ccn.h>
#include <ccn/ccnd.h>
#include <ccn/coding.h>
#include <ccn/uri.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>


#define MAX_SNAPLEN 65535
#define CCN_MIN_PACKET_SIZE 5
#define PBUF_SIZE 200

struct flags_t {
	int verbose;
	int succinct;
	int udp;
	int tcp;
};

struct flags_t flags = {0, 0, 1, 1};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int dissect_ccn(const char *payload, int size_payload, char *pbuf);
int dissect_ccn_interest(const unsigned char *ccnb, int ccnb_size);
int dissect_ccn_content(const unsigned char *ccnb, int ccnb_size);
void print_intercept_time();
void usage();
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

	char pbuf[PBUF_SIZE];

	ether_hdr = (struct ether_header *) (packet);
	ip_hdr = (struct ip *) (packet + ETHER_HDRLEN);
	size_ip = IP_HL(ip_hdr) * 4;
	if (size_ip < 20) {
		fprintf(stderr, "invalid IP header len %u bytes\n", size_ip);
		return;
	}

	int printed;
	switch(ip_hdr->ip_p) {
		case IPPROTO_UDP:
			if (!flags.udp)
				return;
			udp_hdr = (struct udphdr *)(packet + ETHER_HDRLEN + size_ip);
			size_udp = UDP_HEADER_LEN;
			size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_udp);
			payload = (const char *)(packet + ETHER_HDRLEN + size_ip + size_udp);
			printed = sprintf(pbuf, "From: %s, ", inet_ntoa(ip_hdr->ip_src));
			sprintf(pbuf + printed, "To:%s, Tunnel Type: UDP\n",  inet_ntoa(ip_hdr->ip_dst));
			dissect_ccn(payload, size_payload, pbuf);
			break;
		case IPPROTO_TCP:
			if (!flags.tcp)
				return;
			tcp_hdr = (struct tcphdr *)(packet + ETHER_HDRLEN + size_ip);
			size_tcp = TH_OFF(tcp_hdr) * 4;
			if (size_tcp < 20) {
				fprintf(stderr, "Invalid TCP Header len: %u bytes\n", size_tcp);
				return;
			}
			payload = (const char *)(packet + ETHER_HDRLEN + size_ip + size_tcp);
			size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_tcp);
			printed = sprintf(pbuf, "From: %s, ", inet_ntoa(ip_hdr->ip_src));
			sprintf(pbuf + printed, "To:%s, Tunnel Type: TCP\n",  inet_ntoa(ip_hdr->ip_dst));
			dissect_ccn(payload, size_payload, pbuf);
			break;
		default:
			return;
	}

}

int dissect_ccn(const char *payload, int size_payload, char *pbuf) {
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
			print_intercept_time();
			if (!flags.succinct) {
				printf("%s", pbuf);
			}
			if (0 > dissect_ccn_content(ccnb, sd->index))
				return 0;
			break;
		case CCN_DTAG_Interest:
			print_intercept_time();
			if (!flags.succinct) {
				printf("%s", pbuf);
			}
			if (0 > dissect_ccn_interest(ccnb, sd->index))
				return 0;
			break;
		default:
			break;
	}

	return (sd->index);

}
int dissect_ccn_interest(const unsigned char *ccnb, int ccnb_size) {
	struct ccn_parsed_interest interest;
	struct ccn_parsed_interest *pi = &interest;
	struct ccn_charbuf *c;
	struct ccn_indexbuf *comps;
	//const unsigned char *comp;
	//size_t comp_size;
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
	printf("Packet Type: Interest, Name: %s, ", ccn_charbuf_as_string(c));
	/*
	for (i = 0; i < comps->n - 1; i++) {
		res = ccn_name_comp_get(ccnb, comps, i, &comp, &comp_size);
		// TODO: do something 
	}
	*/

	/* Nonce */
	len = pi->offset[CCN_PI_E_Nonce] - pi->offset[CCN_PI_B_Nonce];
	if (len > 0) {
		ccn_ref_tagged_BLOB(CCN_DTAG_Nonce, ccnb, pi->offset[CCN_PI_B_Nonce], pi->offset[CCN_PI_E_Nonce], &blob, &blob_size);
		printf("<");
		for (i = 0; i < blob_size; i++) {
			printf("%02x", *blob);
			blob++;
		}
		printf(">\n");
	}

	if (flags.verbose) {
		/* MinSuffixComponents */
		len = pi->offset[CCN_PI_E_MinSuffixComponents] - pi->offset[CCN_PI_B_MinSuffixComponents];
		if (len > 0) {
			int min_sc = pi->min_suffix_comps;
			printf("MinSC: %d, ", min_sc);
		}

		/* MaxSuffixComponents */
		len = pi->offset[CCN_PI_E_MaxSuffixComponents] - pi->offset[CCN_PI_B_MaxSuffixComponents];
		if (len > 0) {
			int max_sc = pi->max_suffix_comps;
			printf("MaxSC: %d, ", max_sc);
		}

		/* PublisherPublicKeyDigest */
		/* Exclude */

		/* ChildSelector */
		len = pi->offset[CCN_PI_E_ChildSelector] - pi->offset[CCN_PI_B_ChildSelector];
		if (len > 0) {
			int order = pi->orderpref;
			printf("ChildSelector: ");
			switch (order) {
			case 0: printf("leftmost/least, ");
					break;
			case 1: printf("rightmost/greatest, ");
					break;
			default: printf("invalid, ");
			}
		}

		/* AnswerOriginKind */
		len = pi->offset[CCN_PI_E_AnswerOriginKind] - pi->offset[CCN_PI_B_AnswerOriginKind];
		if (len > 0) {
			int origin = pi->answerfrom;
			printf("AnswerOriginKind: %d, ", origin);	
		}

		/* Scope */
		len = pi->offset[CCN_PI_E_Scope] - pi->offset[CCN_PI_B_Scope];
		if (len > 0) {
			int scope = pi->scope;
			printf("Scope: %d, ", scope);
		}

		/* InterestLifeTime */
		len = pi->offset[CCN_PI_E_InterestLifetime] - pi->offset[CCN_PI_B_InterestLifetime];
		if (len > 0) {
			ccn_ref_tagged_BLOB(CCN_DTAG_InterestLifetime, ccnb, pi->offset[CCN_PI_B_InterestLifetime], pi->offset[CCN_PI_E_InterestLifetime], &blob, &blob_size);
			lifetime = 0.0;
			for (i = 0; i < blob_size; i++)
				lifetime = lifetime *256.0 + (double)blob[i];
			lifetime /= 4096.0;
			printf("InterestLifetime: %f\n", lifetime);
		}
	}

	return 1;

}

int dissect_ccn_content(const unsigned char *ccnb, int ccnb_size) {
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

	/* Content */
	len = pco->offset[CCN_PCO_E_Content] - pco->offset[CCN_PCO_B_Content];
	res = ccn_ref_tagged_BLOB(CCN_DTAG_Content, ccnb, pco->offset[CCN_PCO_B_Content], pco->offset[CCN_PCO_E_Content], &blob, &blob_size);
	/* TODO: do something with content*/

	printf("Packet Type: ContentObject, Name: %s, Content Size: %d\n", ccn_charbuf_as_string(c), len);

	/* Name Components */
	for (i = 0; i < comps->n - 1; i ++) {
		res = ccn_name_comp_get(ccnb, comps, i, &comp, &comp_size);
		/* TODO: do something */
	}

	/* SignedInfo */
	/* PublisherPublicKeyDigest */

    /* Timestamp */

	if (flags.verbose)  {
		/* Type */
		len = pco->offset[CCN_PCO_E_Type] - pco->offset[CCN_PCO_B_Type];
		if (len > 0) {
			res = ccn_ref_tagged_BLOB(CCN_DTAG_Type, ccnb, pco->offset[CCN_PCO_B_Type], pco->offset[CCN_PCO_E_Type], &blob, &blob_size);
			int type = pco->type;
			printf("Content Type: ");
			switch (type) {
			case CCN_CONTENT_DATA:  printf("Data, ");
									break;
			case CCN_CONTENT_ENCR:	printf("Encrypted, ");
									break;
			case CCN_CONTENT_GONE:  printf("Gone, ");
									break;
			case CCN_CONTENT_KEY:	printf("Key, ");
									break;
			case CCN_CONTENT_LINK:	printf("Link, ");
									break;
			case CCN_CONTENT_NACK:	printf("Nack, ");
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
			
			printf("FressSeconds: %d, ", i);
		}

		/* FinalBlockID */
		len = pco->offset[CCN_PCO_E_FinalBlockID] - pco->offset[CCN_PCO_B_FinalBlockID];
		if (len > 0) {
			res = ccn_ref_tagged_BLOB(CCN_DTAG_FinalBlockID, ccnb,
									  pco->offset[CCN_PCO_B_FinalBlockID],
									  pco->offset[CCN_PCO_E_FinalBlockID],
									  &blob, &blob_size);
			
			/* TODO: do something */
			if (res == 0) 
				printf("FinalBlockID: Yes\n");
			else
				printf("FinalBlockID: No\n");
		}
		/* KeyLocator */
	}

	return (ccnb_size);

}

int main(int argc, char *argv[])
{
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;						/* Session handle */
	struct bpf_program fp;				/* Compiled filter expression */
	char filter_exp[] = "ip";			
	bpf_u_int32 mask;					/* Netmask of the sniffing device */
	bpf_u_int32 net;					/* IP of the sniffing device */

	int vflag = -1;
	int sflag = -1;
	int uflag = -1;
	int tflag = -1;
	int nflag = -1;

	int c;

	while ((c = getopt(argc, argv, "vsuti:")) != -1) {
		switch (c) {
		case 'v':
			vflag = 1;
			break;
		case 's':
			sflag = 1;
			break;
		case 'u':
			uflag = 1;	
			break;
		case 't':
			tflag = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		case 'i':
			dev = optarg;
			break;
		case 'h':
			usage();
		case '?':
			if (optopt == 'i')
				fprintf(stderr, "Option -i requires an argument.\n");
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);

			usage();
			return 1;
		default:
			usage();
			return 1;

		}
	}

	if (nflag == -1) {
		if (vflag == 1 && sflag == 1) {
			fprintf(stderr, "Conflicting options -v and -s\n");
			return 1;
		}

		if (1 == vflag)
			flags.verbose = 1;
		if (1 == sflag)
			flags.succinct = 1;
	}
	if (1 == uflag && -1 == tflag) {
		flags.udp = 1;
		flags.tcp = 0;
	}
	if (-1 == uflag && 1 == tflag) {
		flags.udp = 0;
		flags.tcp = 1;
	}
	
	if (NULL == dev)
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
	printf("%d:%02d:%02d.%d, ", tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
}

void usage() {
	printf("usage: ndndump [-nstuv] [-i interface]\n");
	printf("\t\t-i: specify interface\n");
	printf("\t\t-n: normal mode (default)\n");
	printf("\t\t-s: sinccinct mode, will only print minimal info about Interest or Content Object\n");
	printf("\t\t-t: track only tcp tunnel\n");
	printf("\t\t-u: track only udp tunnel\n");
	printf("\t\t-v: verbose mode, will print detail info about Interest or Content Object\n");
}
