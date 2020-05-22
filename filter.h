#include <pcap.h>
#include <net/ethernet.h>

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

/*
 * Structure of an internet header, naked of options.
 *
 * Stolen from tcpdump source (thanks tcpdump people)
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct ip_pkt {
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


int16_t
get_eth_type (const struct pcap_pkthdr* pkthdr,
              const u_char* packet);
