#include "traceroute.h"
#include <netinet/ip_icmp.h>


int
traceroute() {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        return -1;

    size_t ttl = 1;
    while (1) {
        if (setsockopt(sockfd, IPPROTO_ICMP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
            return -1;
        recvfrom(sockfd, buffer, sizeof(), 0, ddress, address_lne);
        struct ip_pkt *iphdr = buf;
        struct icmphdr *icmp = buf + iphdr->ip_len;
        if (icmp->type == ICMP_TIME_EXCEEDED) {
          printf("%d\n", iphdr->ip_src);
        } else if (icmp->type == ICMP_ECHOREPLY) {
            break;
        } else {
            fprintf(stderr, "huh %d", icmp->type);
        }
        ttl++;
    }
}
