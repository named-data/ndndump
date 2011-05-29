#ifndef HEADERS_H
#define HEADES_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define	ETHERMTU	1500

/* The number of bytes in an ethernet (MAC) address. */
#define	ETHER_ADDR_LEN		6

/* Length of an Ethernet header */
#define ETHER_HDRLEN		14

/* Structure of an Ethernet header. */
struct	ether_header {
	u_int8_t	ether_dhost[ETHER_ADDR_LEN];
	u_int8_t	ether_shost[ETHER_ADDR_LEN];
	u_int16_t	ether_type;
};

#define	IPVERSION	4
#define	IP_MAXPACKET	65535		/* maximum packet size */

/* Structure of an internet header, naked of options. */
struct ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* Udp protocol header. */
struct udphdr {
	u_int16_t	uh_sport;		/* source port */
	u_int16_t	uh_dport;		/* destination port */
	u_int16_t	uh_ulen;		/* udp length */
	u_int16_t	uh_sum;			/* udp checksum */
};

#define UDP_HEADER_LEN 8

#endif
