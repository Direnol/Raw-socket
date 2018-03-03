#ifndef RAW_SOCKET_RAW_H
#define RAW_SOCKET_RAW_H

#include <stdint.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>


typedef struct udphdr udphdr_t;

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

void set_transport_level(udphdr_t *header, uint16_t src_p, uint16_t dst_p, uint16_t len);

int send_raw(int fd, udphdr_t *header, const struct sockaddr_in *serv, char *pl);

// return new fd of socket and init sock_addr of server; -1 is error, other is successful
int init_addr(struct sockaddr_in *serv, sa_family_t family, char *ip, uint16_t port);

void print_header(udphdr_t *h);

#endif //RAW_SOCKET_RAW_H