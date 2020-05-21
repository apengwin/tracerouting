/*
 *   This is largely based on Martin Casado's intro to PCAP.
 *   Large amounts of this code were taken from tcpdump source
 *
 *   print-ether.c
 *   print-ip.c
 *   ip.h
 *
 * Compile with:
 * gcc -Wall -pedantic filter.c -lpcap (-o foo_err_something)
 *
 */

#include "filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


void
packet_callback (u_char *args,
           const struct pcap_pkthdr* pkthdr,
           const u_char* packet) {

    /* looking at ethernet headers */
    int16_t type = get_eth_type(args, pkthdr, packet);
    if(type != ETHERTYPE_IP) {
        fprintf(stderr,
                "Bad ethernet header type %d. Problem with filter\n",
                type);
        return;
    }

    const struct ip_pkt* ip;
    u_int length = pkthdr->len;
    u_int hlen;
    u_int off;
    u_int version;

    int len;

    /* jump pass the ethernet header */
    ip = (struct ip_pkt*) (packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct ip_pkt))
    {
        printf("truncated ip %d",length);
        return;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4) {
        fprintf(stdout,"Unknown version %d\n",version);
        return;
    }

    /* check header length */
    if(hlen < 5 ) {
        fprintf(stdout,"bad-hlen %d \n",hlen);
        return;
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    // aka no 1's in first 13 bits
    if((off & 0x1fff) == 0 )  {
        fprintf(stdout,"IP: %s\n", inet_ntoa(ip->ip_dst));
    }

    return;
}

/*
 * This function should be unnecessary if we get the filters right.
 * handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
int16_t
get_eth_type (u_char *args,
              const struct pcap_pkthdr* pkthdr,
              const u_char* packet) {

    if (pkthdr->caplen < ETHER_HDRLEN) {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    // Cast packet to ehter_header.
    struct ether_header *eptr = (struct ether_header *) packet;
    return ntohs(eptr->ether_type);
}


int
main(int argc,char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    // Hold compiled program
    struct bpf_program filter_program;
    // subnet mask
    bpf_u_int32 maskp;
    // ip
    bpf_u_int32 netp;

    // No options.
    if(argc > 1) {
        fprintf(stdout,"Usage: %s\n",argv[0]);
        return 0;
    }

    // grab a device to peak into...
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        printf("%s\n",errbuf);
        exit(1);
    }
    char *dev = alldevs[0].name;

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,
                   &netp,
                   &maskp,
                   errbuf);

    // open device for reading.
    descr = pcap_open_live(dev,
                           BUFSIZ,
                           0,
                           0,
                           errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    char *FILTER_STRING =
      "ip && !(dst net 10.0.0.0/8) && !(dst net 172.16.0.0/12) && !(dst net 192.168.0.0/16)";

    // Lets try and compile the program.. non-optimized
    if(pcap_compile(descr,
                    &filter_program,
                    FILTER_STRING,
                    0,
                    netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }

    // set the compiled program as the filter
    if(pcap_setfilter(descr,&filter_program) == -1) {
        fprintf(stderr,"Error setting filter\n");
        exit(1);
    }

    int loop_forever = -1;
    pcap_loop(descr,
              loop_forever,
              packet_callback,
              NULL);

    fprintf(stdout,"\nfinished\n");
    return 0;
}

