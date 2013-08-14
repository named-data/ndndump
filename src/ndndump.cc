/* ndndump.c
 * Adapted from ndn plugin for wireshark in the ndnx package
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
#include <iostream>
#include "headers.h"

#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>

#include <boost/iostreams/stream.hpp>
#include <boost/exception/all.hpp>
#include <boost/regex.hpp>
#include <boost/utility.hpp>

using namespace boost;

#include <iostream>
#include <fstream>

#include <sstream>
#include <iomanip>
using namespace std;

#include "print-helper.h"
#include "ndnb-print-xml.h"
#include "ndnb-print-plain.h"
#include "ns3/ndnb-parser-block.h"
#include "ns3/ndnb-parser-dtag.h"
#include "ns3/ndnb-parser-blob.h"
#include "ns3/ndnb-parser-name-combiner.h"
#include "ns3/ndnb-parser-non-negative-integer-visitor.h"

#define MAX_SNAPLEN 65535
#define INTEREST_BYTE0 0x01
#define INTEREST_BYTE1 0xD2

#define CONTENT_OBJECT_BYTE0 0x04
#define CONTENT_OBJECT_BYTE1 0x82

#define NDNLP_BYTE0 'N'
#define NDNLP_BYTE1 'd'

struct flags_t {
  int ndnb;
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

static regex prefix_selector;

static NdnbXmlPrinter *ndnbDecoder = NULL; ///< will be initialized before loop starts
static NdnbPlainPrinter plainPrinter;
static NdnbParser::NameCombiner nameCombiner; ///< to work with name filters

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_intercept_time(ostream &, const struct pcap_pkthdr *header);
void usage();

inline bool match_prefix(const string &prefix)
{
  if (!prefix_selector.empty())
    {
      int match = (int)regex_match (prefix, prefix_selector);
      if (!flags.invert_match)
        {
          if( !match ) return false;
        }
      else
        if( match ) return false;
    }

  return true;
}

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

  int payload_size = header->len;
  const u_char *payload = packet;

  int type = *(reinterpret_cast<int*> (args));

  int frame_type = 0; // unknown

  switch (type)
    {
    case DLT_EN10MB:
      {
        const ether_header *ether_hdr = reinterpret_cast<const ether_header *> (packet);

        payload_size -= ETHER_HDRLEN;
        payload += ETHER_HDRLEN;
        if (payload_size<0)
          {
            cerr << "Invalid pcap Ethernet frame" << endl;
            return;
          }

        frame_type = ntohs(ether_hdr->ether_type);
        break;
      }
    case DLT_PPP:
      {
        frame_type = *payload;
        payload_size --;
        payload ++;

        if (!(frame_type & 1))
          {
            frame_type = (frame_type << 8) | *payload;
            payload_size --;
            payload ++;
          }
        break;
      }
    }

  switch (frame_type)
    {
    case /*ETHERTYPE_IP*/0x0800:
    case DLT_EN10MB: // pcap encapsulation
      {
        const ip *ip_hdr = reinterpret_cast<const ip *>(payload);
        size_t size_ip = IP_HL(ip_hdr) * 4;
        if (size_ip < 20) {
          cerr << "invalid IP header len "<< size_ip <<" bytes" << endl;
          return;
        }
        os << "From: " << inet_ntoa(ip_hdr->ip_src) << ", ";
        os << "To: "   << inet_ntoa(ip_hdr->ip_dst);

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
      os << "Tunnel Type: EthernetFrame";
      break;
    case /*ETHERTYPE_NDNLP*/0x8624:
      os << "Tunnel Type: EthernetFrame";
      break;
    case 0x0077: // pcap
      os << "Tunnel Type: PPP";
      payload_size -= 2;
      payload += 2;
      break;
    default:
      return;
      break; // do nothing if it is not an IP packet
    }

  if (payload_size<5)
    return;

  if (!((payload[0] == INTEREST_BYTE0 && payload[1] == INTEREST_BYTE1) ||
        (payload[0] == CONTENT_OBJECT_BYTE0 && payload[1] == CONTENT_OBJECT_BYTE1) ||
        (payload[0] == NDNLP_BYTE0 && payload[1] == NDNLP_BYTE1)))
    {
      return; //definitely not NDNx packet
    }

  boost::iostreams::stream
    <boost::iostreams::array_source> in ((const char*)payload, (size_t)payload_size);

  try
    {
      Ptr<NdnbParser::Dtag> root = DynamicCast<NdnbParser::Dtag> (NdnbParser::Block::ParseBlock (reinterpret_cast<Buffer::Iterator&> (in)));

      if (payload[0] == NDNLP_BYTE0 && payload[1] == NDNLP_BYTE1)
        {
          if (root && root->m_dtag != NdnbParser::NdnlpData)
            {
              return;
            }

          os << ", NdnlpData";

          // if (flags.print_xml)
          //   {
          //     root->accept (*ndnbDecoder, string(""));
          //     cout << "\n";
          //   }

          Ptr<NdnbParser::Dtag> payload;
          for (std::list<Ptr<NdnbParser::Block> >::iterator i = root->m_nestedTags.begin (); i != root->m_nestedTags.end (); i++)
            {
              Ptr<NdnbParser::Dtag> tag = DynamicCast<NdnbParser::Dtag> (*i);
              if (!tag)
                return;

              if (tag->m_dtag == NdnbParser::NdnlpSequence)
                {
                  Ptr<NdnbParser::Blob> blob = DynamicCast<NdnbParser::Blob> (tag->m_nestedTags.front ());
                  os << ", NdnlpSequence: ";
                  PrintHelper::print_percent_escaped (os, (unsigned char*)blob->m_blob.get (), blob->m_blobSize);
                }

              if (tag->m_dtag == NdnbParser::NdnlpPayload)
                {
                  payload = tag;
                  break;
                }
            }
          if (payload == 0 || payload->m_nestedTags.empty ())
            return;

          Ptr<NdnbParser::Blob> blob = DynamicCast<NdnbParser::Blob> (*payload->m_nestedTags.begin ());
          if (blob == 0)
            return;

          boost::iostreams::stream
            <boost::iostreams::array_source> in2 (blob->m_blob.get (), blob->m_blobSize);

          root = DynamicCast<NdnbParser::Dtag> (NdnbParser::Block::ParseBlock (reinterpret_cast<Buffer::Iterator&> (in2)));
        }

      if (root && (root->m_dtag==NDN_DTAG_Interest ||
                   root->m_dtag==NDN_DTAG_Data))
        {
          ostringstream prefix;
          root->accept (nameCombiner, boost::any(static_cast<ostream*>(&prefix)));

          if (!match_prefix(prefix.str())) return; // ignore unmatched prefixes

          if (!flags.succinct)
            cout << os.str() << ", ";

          root->accept (plainPrinter, string(""));

          if (flags.print_xml)
            {
              cout << "\n";
              root->accept (*ndnbDecoder, string(""));
            }

          if (flags.ndnb)
            {
              cout << "\n";
              PrintHelper::print_payload(cout, payload, payload_size);
            }
          cout << endl; // flushing?
        }
    }
  catch (::boost::exception &e )
    {
      cerr << diagnostic_information(e) << endl;
    }
  catch (...)
    {
      // cerr << "exception" << endl;
      // packet parsing error
    }
}

int main(int argc, char *argv[])
{
  signal(SIGUSR1, sig_handler);
  char *dev = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  std::string pcapfilename;
  pcap_t *handle;						/* Session handle */
  struct bpf_program fp;				/* Compiled filter expression */
  //char filter_exp[] = "ip";
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
  int oFlag = -1;
  int c;

  while ((c = getopt(argc, argv, "cgvsuthni:Ixo:")) != -1) {
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
    case 'o':
      oFlag = 1;
      pcapfilename = optarg;
      break;
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

  if (1 == cflag)
    flags.ndnb = 1;
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

  if (oFlag == -1 && NULL == dev)
    dev = pcap_lookupdev(errbuf);

  if (oFlag == -1 && NULL == dev) {
    fprintf(stderr, "couldn't find default device %s\n", errbuf);
    return 2;
  }

  if (1 == Iflag)
    flags.invert_match = 1;

  if (1 == xflag)
    flags.print_xml = 1;

  if(oFlag == -1)
    printf("Device: %s\n", dev);
  else
    std::cout << "Reading from file " << pcapfilename << "\n";

  if (!prefix_selector.empty())
    {
      printf("Prefix selector: %s\n", prefix_selector.str().c_str() );
    }

  if ((oFlag == -1) &&  (-1 == pcap_lookupnet(dev, &net, &mask, errbuf))) {
    fprintf(stderr, "couldn't get netmask for device %s: %s\n", dev, errbuf);
  }

  if(oFlag == -1)
    {
      handle = pcap_open_live(dev, MAX_SNAPLEN, 0, 1000, errbuf);
    }
  else
    {
      handle = pcap_open_offline(pcapfilename.c_str(), errbuf);
    }

  if(oFlag == 1 && handle == NULL)
    {
      cerr << "couldn't open offline file " << pcapfilename << "\n";
      return 2;
    }

  if (oFlag == -1 && handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return 2;
  }
  //	if (-1 == pcap_compile(handle, &fp, filter_exp, 0, net)) {
  //		fprintf(stderr, "couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
  //		return 2;
  //	}
  //	if (-1 == pcap_setfilter(handle, &fp)) {
  //		fprintf(stderr, "couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
  //		return 2;
  //	}

  struct ndn_dict *dtags = (struct ndn_dict *)&ndn_dtag_dict2;
  ndnbDecoder = new NdnbXmlPrinter( VERBOSE_DECODE, dtags );
  plainPrinter.SetOptions (flags.verbose, flags.signature, flags.succinct);

  int type = pcap_datalink (handle);
  if (type != DLT_EN10MB && type != DLT_PPP)
    {
      cerr << "Unsupported pcap format\n";
      return 2;
    }
  pcap_loop(handle, -1, got_packet, reinterpret_cast<u_char*> (&type));

  delete ndnbDecoder;

  //pcap_freecode(&fp);
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
       << setfill('0') << setw(6) << (int)header->ts.tv_usec;
  }
  os << " ";
}

void usage() {
  printf("usage: ndndump [-cghnstuvI] [-i interface] "
         "[prefix selector]"
         "\n");
  printf("  -h: show usage\n");
  printf("  -I: invert prefix selection condition\n");
  printf("  -c: print the whole ndnb\n");
  printf("  -x: print decoded XML of the whole packet\n");
  // for now only in XML format
  // printf("  -g: print signature of Content Object\n");
  printf("  -i: specify interface\n");
  printf("  -n: use unit_time timestamp in seconds\n");
  printf("  -o: use offline file for pcap data\n");
  printf("  -s: sinccinct mode, no TCP/IP info and  minimal info about Interest or Content Object\n");
  printf("  -t: track only tcp tunnel\n");
  printf("  -u: track only udp tunnel\n");
  printf("  -v: verbose mode, will also print filters of Interest and SignedInfo of Content Object\n");
  printf("  [prefix selector]: dump packets whose name satisfies this regular expression\n\n");
  printf("\ndefault: \n");
  printf("  select the default interface\n");
  printf("  print timestamp and TCP/IP info of the ndn tunnel\n");
  printf("  print names of Interest and Data\n");
}
