#include <sys/socket.h>
#include <netinet/in.h>


struct icmp_hdr {
    u_int8_t icmp_typ;
    u_int8_t icmp_ctrl;
    u_int16_t checksum;
    u_int32_t rest;
}__attribute__((packed));


int
traceroute();
