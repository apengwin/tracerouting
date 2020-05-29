/*
 * This is largely based on Martin Casado's intro to PCAP. Thanks Martin!
 * Large amounts of this code were taken from tcpdump source
 *
 * print-ether.c
 * print-ip.c
 * ip.h
 *
 * Compile with:
 * gcc -Wall -pedantic filter.c -lpcap
 *
 */

#include "filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include "json.hpp"

using json = nlohmann::json;


void
handle_packet (int conn_fd,
               const struct pcap_pkthdr* pkthdr,
               const u_char* packet) {

    /* looking at ethernet headers */
    int16_t type = get_eth_type(pkthdr, packet);
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
    if (length < sizeof(struct ip_pkt)) {
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
        fprintf(stderr,"bad-hlen %d \n",hlen);
        return;
    }

    /* see if we have as much packet as we should */
    if(length < len) {
        printf("\ntruncated IP - %d bytes missing\n",len - length);
    }

    // Check to see if we have the first fragment
    // aka no 1's in first 13 bits
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 ) {
        char *msg = inet_ntoa(ip->ip_dst);
        char buf[strlen(msg) + 1];
        strncpy(buf, msg, strlen(msg));
        buf[strlen(msg)] = '\n';
        if(send(conn_fd , buf , strlen(msg) + 1 , 0) < 0) {
            perror("Ignoring: ");
        }
    }

    return;
}

/*
 * This function should be unnecessary if we get the filters right.
 * handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
int16_t
get_eth_type (const struct pcap_pkthdr* pkthdr,
              const u_char* packet) {

    if (pkthdr->caplen < ETHER_HDRLEN) {
        fprintf(stderr,"Packet length less than ethernet header length\n");
        return -1;
    }

    // Cast packet to ehter_header.
    struct ether_header *eptr = (struct ether_header *) packet;
    return ntohs(eptr->ether_type);
}


int
main(int argc,char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    // Hold compiled program
    struct bpf_program filter_program;
    // subnet mask
    bpf_u_int32 maskp;
    // ip
    bpf_u_int32 netp;

    // No options.
    if(argc != 2) {
        fprintf(stderr,"Usage: %s <sock_path>\n", argv[0]);
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

    // Do not open in promiscuous mode.
    int promisc = 0;
    // Set no timeout.
    int to_ms = 0;

    const int MAX_ETHER_SIZE = 1522;
    // open device for reading.
    pcap_t* descr = pcap_open_live(dev,
                           MAX_ETHER_SIZE,
                           promisc,
                           to_ms,
                           errbuf);

    if(descr == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    // Filter only ipv4 packets
    // that aren't being sent to an internal address.
    // TODO: ipv6.
    char const *FILTER_STRING = "ip "
                                "&& !(dst net 10.0.0.0/8) "
                                "&& !(dst net 172.16.0.0/12) "
                                "&& !(dst net 192.168.0.0/16)";

    // Lets try and compile the program.. non-optimized
    if(pcap_compile(descr,
                    &filter_program,
                    FILTER_STRING,
                    0,
                    netp) == PCAP_ERROR) {

        pcap_perror(descr, "Error calling pcap_compile: ");
        exit(1);
    }

    // set the compiled program as the filter
    if(pcap_setfilter(descr,&filter_program) == -1) {
        pcap_perror(descr, "Error calling pcap_setfilter: ");
        exit(1);
    }
    int sockfd;

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("Error opening socket: ");
        exit(1);
    }

    if (access(argv[1], F_OK) != -1) {
        if (unlink(argv[1]) != 0) {
            perror("Error with unlinking existing socket");
            exit(1);
        }
    }

    struct sockaddr_un server;
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, argv[1]);
    if (bind(sockfd, (const struct sockaddr *) &server, sizeof(struct sockaddr_un)) != 0) {
        perror("Binding stream socket");
        exit(1);
    }

    umask(0);
    if (listen(sockfd, 1) != 0) {
        perror("problem with listening...");
        exit(1);
    }
    fprintf(stderr, "Listening on socket....\n");
    int conn_fd = accept(sockfd, 0, 0);
    fprintf(stderr, "Successfully connected.\n");

    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    while (pcap_next_ex(descr, &pkt_header, &pkt_data) == 1) {
        handle_packet(conn_fd, pkt_header, pkt_data);
    }

    pcap_perror(descr, "Error: ");

    return 1;
}

