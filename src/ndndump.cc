/* ndndump.c
 * Adapted from ccn plugin for wireshark in the ccnx package
 *
 * Copyright (C) 2011 IRL, CS, UCLA.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "config.h"
#include "headers.h"

extern "C"
{
#include <ccn/ccn.h>
#include <ccn/ccnd.h>
#include <ccn/coding.h>
#include <ccn/uri.h>
}

#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>

#include <boost/iostreams/stream.hpp>
#include <boost/exception/all.hpp>

#ifdef HAVE_BOOST_REGEX
#include <boost/regex.hpp>
using namespace boost;
#endif

#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;

#include "print-helper.h"
#include "ccnb-print-xml.h"
#include "ccnb-print-plain.h"
#include "ns3/ccnb-parser-block.h"
#include "ns3/ccnb-parser-dtag.h"

#define MAX_SNAPLEN 65535
#define INTEREST_BYTE0 0x01
#define INTEREST_BYTE1 0xD2

#define CONTENT_OBJECT_BYTE0 0x04
#define CONTENT_OBJECT_BYTE1 0x82

struct flags_t {
	int ccnb;
	int verbose;
	int signature;
	int succinct;
	int unit_time;
	int udp;
	int tcp;
	int invert_match;
	int print_xml;
};

static struct flags_t flags = {0, 0, 0, 0, 0, 1, 1, 0, 0};
#ifndef HAVE_BOOST_REGEX
static char **prefixes = NULL;
static int prefix_num = 0;
#else
static regex prefix_selector;
#endif
static CcnbXmlPrinter *ccnbDecoder = NULL; ///< will be initialized before loop starts
static CcnbPlainPrinter plainPrinter;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
// int dissect_ccn(const char *payload, int size_payload, char *pbuf, char *tbuf);
// int dissect_ccn_interest(const unsigned char *ccnb, int ccnb_size, char *pbuf, char *tbuf);
// int dissect_ccn_content(const unsigned char *ccnb, int ccnb_size, char *pbuf, char *tbuf);
void print_intercept_time(ostream &, const struct pcap_pkthdr *header);
void usage();

#ifndef HAVE_BOOST_REGEX
int match_name (struct ccn_charbuf *c);

#define MATCH(c)								\
	if (prefix_num > 0)							\
	{											\
		int match = match_name(c);				\
		if (!flags.invert_match)				\
		{										\
			if( !match ) return 0;				\
		}										\
		else									\
			if( match ) return 0;				\
	}
#else
#define MATCH(c) \
	if (!prefix_selector.empty())										\
	{																	\
		int match = (int)regex_match (ccn_charbuf_as_string(c), prefix_selector); \
		if (!flags.invert_match)										\
		{																\
			if( !match ) return 0;										\
		}																\
		else															\
			if( match ) return 0;										\
	}
#endif


/* WARNING: THIS IS A HACK
 * I don't know why ndndump does not work with pipe anymore. It seems
 * that the printing to stdout was delayed until pcap_loop returns
 * (which never returns). I changed the packet count to 10 to test my
 * theory, and it confirmed my hypothesis.  To fix this, I think it is
 * fair to add a signal handler just to fflush(stdout) every time a
 * packet is processed.
 */
void sig_handler(int signum) {
	fflush(stdout);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	ostringstream os;
  	print_intercept_time (os, header);

	const ether_header *ether_hdr = reinterpret_cast<const ether_header *> (packet);

	int payload_size = header->len - ETHER_HDRLEN;
	const u_char *payload = packet + ETHER_HDRLEN;
	if (payload_size<0)
		{
			cerr << "Invalid pcap Ethernet frame" << endl;
			return;
		}

	switch (ntohs(ether_hdr->ether_type))
		{
		case /*ETHERTYPE_IP*/0x0800:
		{
			const ip *ip_hdr = reinterpret_cast<const ip *>(payload);
			size_t size_ip = IP_HL(ip_hdr) * 4;
			if (size_ip < 20) {
				cerr << "invalid IP header len "<< size_ip <<" bytes" << endl;
				return;
			}
			os << "From: " << inet_ntoa(ip_hdr->ip_src) << ", "
			   << "To: "   << inet_ntoa(ip_hdr->ip_dst);

			payload_size -= size_ip;
			payload += size_ip;
			if (payload_size<0)
				{
					cerr << "Invalid pcap IP packet" << endl;
					return;
				}

			switch(ip_hdr->ip_p)
				{
				case IPPROTO_UDP:
				{
					if (!flags.udp)
						return;
					const udphdr *udp_hdr = reinterpret_cast<const udphdr *>(payload);
					size_t size_udp = UDP_HEADER_LEN;
					payload_size -= size_udp;
					payload += size_udp;
					if (payload_size<0)
						{
							cerr << "Invalid pcap UDP/IP packet" << endl;
							return;
						}
					// size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_udp);
					// payload = (const char *)(packet + ETHER_HDRLEN + size_ip + size_udp);

					os << ", Tunnel Type: UDP";
					break;
				}
				case IPPROTO_TCP:
				{
					if (!flags.tcp)
						return;
					const tcphdr *tcp_hdr = reinterpret_cast<const tcphdr *>(payload);
					size_t size_tcp = TH_OFF(tcp_hdr) * 4;
					if (size_tcp < 20) {
						cout << "Invalid TCP Header len: "<< size_tcp <<" bytes\n";
						return;
					}
					payload_size -= size_tcp;
					payload += size_tcp;
					if (payload_size<0)
						{
							cerr << "Invalid pcap TCP/IP packet" << endl;
							return;
						}
					os << ", Tunnel Type: TCP";
					break;
				}
				default:
					return;
				}

			break;
		}
		case /*ETHERTYPE_NDN*/0x7777:
			os << ", Tunnel Type: EthernetFrame";
			break;
		default:
			return;
			break; // do nothing if it is not an IP packet
		}

    if (payload_size<5)
	    return;

	if (!((payload[0] == INTEREST_BYTE0 && payload[1] == INTEREST_BYTE1) ||
		  (payload[0] == CONTENT_OBJECT_BYTE0 && payload[1] == CONTENT_OBJECT_BYTE1)))
    {
		return; //definitely not CCNx packet
    }

    boost::iostreams::stream<boost::iostreams::array_source> in (
		(const char*)payload,
		(size_t)payload_size);

	try
		{
			Ptr<CcnbParser::Dtag> root = DynamicCast<CcnbParser::Dtag>(
				CcnbParser::Block::ParseBlock (
					reinterpret_cast<Buffer::Iterator&> (in)));

			if (root && (root->m_dtag==CCN_DTAG_Interest ||
						 root->m_dtag==CCN_DTAG_ContentObject))
				{
					cout << os.str();
					root->accept (plainPrinter, string(""));
					cout << endl; // flushing?
				}
		}
	catch (::boost::exception &e )
		{
			cerr << diagnostic_information(e) << endl;
		}
	catch (...)
		{
			cerr << "exception" << endl;
			// packet parsing error
		}

	kill(getpid(), SIGUSR1);
}

int dissect_ccn_interest(const unsigned char *ccnb, int ccnb_size, char *pbuf, char *tbuf) {
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

	MATCH (c);

	printf("%s", tbuf);
	if (!flags.succinct) {
		printf("%s", pbuf);
	}
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
		// TODO: use ccn_skeleton_parser to deal with this thing

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


	if (flags.ccnb) {
		printf("Interest: \n");
		PrintHelper::print_payload(ccnb, ccnb_size);
		printf("\n");
	}

	if (flags.print_xml)
		ccnbDecoder->DecodeAndPrint ((const char*)ccnb, ccnb_size);

	return 1;
}

int dissect_ccn_content(const unsigned char *ccnb, int ccnb_size, char *pbuf, char *tbuf) {
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

	/* Name */
	len = pco->offset[CCN_PCO_E_Name] - pco->offset[CCN_PCO_B_Name];
	c = ccn_charbuf_create();
	ccn_uri_append(c, ccnb, ccnb_size, 1);

	MATCH (c);

	printf("%s", tbuf);
	if (!flags.succinct) {
		printf("%s", pbuf);
	}

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


	if (flags.signature) {
		/* Signature */
		len = pco->offset[CCN_PCO_E_Signature] - pco->offset[CCN_PCO_B_Signature];
		if (len > 0) {
		printf("Signature: \n\t");

			/* DigestAlgorithm */
			len = pco->offset[CCN_PCO_E_DigestAlgorithm] - pco->offset[CCN_PCO_B_DigestAlgorithm];
			if (len > 0) {
				blob_size = 0;
				res = ccn_ref_tagged_BLOB(CCN_DTAG_DigestAlgorithm, ccnb,
										  pco->offset[CCN_PCO_B_DigestAlgorithm],
										  pco->offset[CCN_PCO_E_DigestAlgorithm],
										  &blob, &blob_size);
				printf("DigestAlogrithm: \n\t");
				PrintHelper::print_payload(blob, blob_size);
				/*
				for (i = 0; i < blob_size; i++) {
					printf("%02x", *blob);
					blob++;
				}
				*/
				printf("\n\t");
			}
			/* Witness */
			/* Signature bits */
			len = pco->offset[CCN_PCO_E_SignatureBits] - pco->offset[CCN_PCO_B_SignatureBits];
			if (len > 0) {
				blob_size = 0;
				res = ccn_ref_tagged_BLOB(CCN_DTAG_SignatureBits, ccnb,
										  pco->offset[CCN_PCO_B_SignatureBits],
										  pco->offset[CCN_PCO_E_SignatureBits],
										  &blob, &blob_size);

				printf("SignatureBits: \n\t");
				PrintHelper::print_payload(blob, blob_size);
				/*
				for (i = 0; i < blob_size; i++) {
					printf("%02x", *blob);
					blob++;
				}
				*/
				printf("\n");
			}
		}
	}

	if (flags.verbose)  {

		/* SignedInfo */
		printf("Signed Info:\n\t");
		/* PublisherPublicKeyDigest */
		len = pco->offset[CCN_PCO_E_PublisherPublicKeyDigest] - pco->offset[CCN_PCO_B_PublisherPublicKeyDigest];
		if (len > 0) {
			blob_size = 0;
			res = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest, ccnb,
									  pco->offset[CCN_PCO_B_PublisherPublicKeyDigest],
									  pco->offset[CCN_PCO_E_PublisherPublicKeyDigest],
									  &blob, &blob_size);
			printf("PublisherPublicKeyDigest: \n\t");
			PrintHelper::print_payload(blob, blob_size);
			/*
			for (i = 0; i < blob_size; i++) {
				printf("%02x", *blob);
				blob++;
			}
			*/
			printf("\n\t");

		}

		/* Timestamp */
		len = pco->offset[CCN_PCO_E_Timestamp] - pco->offset[CCN_PCO_B_Timestamp];
		if (len > 0) {
			res = ccn_ref_tagged_BLOB(CCN_DTAG_Timestamp, ccnb,
									  pco->offset[CCN_PCO_B_Timestamp],
									  pco->offset[CCN_PCO_E_Timestamp],
									  &blob, &blob_size);
			double dt = 0.0;
			for (i = 0; i < blob_size; i++)
				dt = dt * 256.0 + (double)blob[i];
			dt /= 4096.0;
			printf("TimeStamp: %f, ", dt);
		}

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
				printf("FinalBlockID: Yes");
			else
				printf("FinalBlockID: No");
		}
		/* KeyLocator */
		printf("\n");
	}


	if (flags.ccnb) {
		printf("ContentObject:\n");
		PrintHelper::print_payload(ccnb, ccnb_size);
		printf("\n");
	}

	if (flags.print_xml)
		ccnbDecoder->DecodeAndPrint ((const char*)ccnb, ccnb_size);

	return (ccnb_size);

}

int main(int argc, char *argv[])
{
	signal(SIGUSR1, sig_handler);
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
	int gflag = -1;
	int cflag = -1;
	int Iflag = -1;
	int xflag = -1;

	int c;

	while ((c = getopt(argc, argv, "cgvsuthni:Ix")) != -1) {
		switch (c) {
		case 'c':
			cflag = 1;
			break;
		case 'x':
			xflag = 1;
			break;
		case 'g':
			gflag = 1;
			break;
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
		case 'I':
			Iflag = 1;
			break;		
		case 'h':
			usage();
			return 0;
		case '?':
			if ('i' == optopt )
				fprintf(stderr, "Option `-%c' requires an argument.\n", optopt);
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

#ifndef HAVE_BOOST_REGEX
	prefix_num = argc - optind;
	if (prefix_num > 0) {
		prefixes = (char **)malloc(prefix_num * sizeof (char *));
		int index;
		for (index = 0; index < prefix_num; index ++) {
			prefixes[index] = argv[index + optind];
		}
		
		if (Iflag == 1)
		{
			fprintf (stderr, "%s\n", "To invert condition, at least one prefix should be specified");
			return 2;
		}
	}
#else
	if (argc - optind > 0)
	{
		if (argc - optind > 1)
		{
			printf( "%d %d %d\n", argc, optind, argc - optind );
			fprintf (stderr, "Only one prefix selector is allowed. Use advanced regular expression to select more\n");
			return 2;
		}

		try
		{
			prefix_selector = regex (argv[optind]);
		}
		catch (regex_error error)
		{
			fprintf (stderr, "%s\n", error.what());
			return 2;
		}
	}

	if (prefix_selector.empty() && Iflag == 1)
	{
		fprintf (stderr, "%s\n", "Cannot invert empty prefix selector" );
		return 2;
	}
#endif

	if (1 == cflag)
		flags.ccnb = 1;
	if (1 == gflag)
		flags.signature = 1;
	if (1 == nflag)
		flags.unit_time = 1;

	if (1 == vflag && 1 == sflag) {
		fprintf(stderr, "Conflicting options -v and -s\n");
		return 1;
	}

	if (1 == vflag)
		flags.verbose = 1;
	if (1 == sflag)
		flags.succinct = 1;

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

	if (1 == Iflag)
		flags.invert_match = 1;

	if (1 == xflag)
		flags.print_xml = 1;

	printf("Device: %s\n", dev);

#ifndef HAVE_BOOST_REGEX	
	if (prefixes != NULL) {
		int i;
		for (i = 0; i < prefix_num; i++)
			printf("Name Prefix %d: %s\n", i + 1, prefixes[i]);
	}
#else
	if (!prefix_selector.empty())
	{
		printf("Prefix selector: %s\n", prefix_selector.str().c_str() );
	}
#endif

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

	struct ccn_dict *dtags = (struct ccn_dict *)&ccn_dtag_dict;
	ccnbDecoder = new CcnbXmlPrinter( VERBOSE_DECODE, dtags );
	
	pcap_loop(handle, -1, got_packet, NULL);

	delete ccnbDecoder;
	
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}

void print_intercept_time(ostream& os, const struct pcap_pkthdr *header)
{
	struct tm *tm;
	if (flags.unit_time) {
		os << (int) header->ts.tv_sec
		   << "."
		   << setfill('0') << setw(6) << (int)header->ts.tv_usec;
	} else {
		tm = localtime(&(header->ts.tv_sec));
		os << (int)tm->tm_hour << ":"
		   << setfill('0') << setw(2) << (int)tm->tm_min<< ":"
		   << setfill('0') << setw(2) << (int)tm->tm_sec<< "."
		   << setfill('0') << setw(2) << (int)header->ts.tv_usec;
	}
	os << " ";
}

void usage() {
	printf("usage: ndndump [-cghnstuvI] [-i interface] "
#ifndef HAVE_BOOST_REGEX
		   "[prefix1] [prefix2] ... [prefixN]"
#else
		   "[prefix selector]"
#endif
		   "\n");
	printf("  -h: show usage\n");
	printf("  -I: invert prefix selection condition\n");
	printf("  -c: print the whole ccnb\n");
	printf("  -x: print decoded XML of the whole packet\n");
	printf("  -g: print signature of Content Object\n");
	printf("  -i: specify interface\n");
	printf("  -n: use unit_time timestamp in seconds\n");
	printf("  -s: sinccinct mode, no TCP/IP info and  minimal info about Interest or Content Object\n");
	printf("  -t: track only tcp tunnel\n");
	printf("  -u: track only udp tunnel\n");
	printf("  -v: verbose mode, will also print filters of Interest and SignedInfo of Content Object\n");
#ifndef HAVE_BOOST_REGEX
	printf("  [prefix]: dump packets whose name begins with prefix\n");
#else
	printf("  [prefix selector]: dump packets whose name satisfies this regular expression\n\n");
#endif
	printf("\ndefault: \n");
	printf("  select the default interface\n");
	printf("  print timestamp and TCP/IP info of the ccn tunnel\n");
	printf("  print names of Interest and ContentObject\n");
}



#ifndef HAVE_BOOST_REGEX
int match_name(struct ccn_charbuf *c) {
	char *namestr = ccn_charbuf_as_string(c);
	int match = 0;
	int i;
	for (i = 0; i < prefix_num; i++) {
		if (prefixes[i] != NULL) {
			// prefix starts with ccnx:
			if (strlen(prefixes[i]) > 5 && strncmp(prefixes[i], "ccnx:", 5) == 0) {
				if (strncmp(prefixes[i], namestr, strlen(prefixes[i])) != 0)
					continue;
				// check if the last comp of prefix match
				if (strlen(namestr) > strlen(prefixes[i])) {
					if (*(namestr + strlen(prefixes[i])) != '/')
						continue;
				}
			}
			// prefix starts with /
			else {
				if(strncmp(prefixes[i], namestr + 5, strlen(prefixes[i])) != 0)
					continue;
				// check if the last comp of prefix match
				if (strlen(namestr) > strlen(prefixes[i]) + 5) {
					if (*(namestr + strlen(prefixes[i]) + 5) != '/')
						continue;
				}
			}
			match = 1;
			break;
		}
	}
	return match;
}
#endif
