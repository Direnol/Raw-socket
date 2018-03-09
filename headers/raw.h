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
#include <time.h>


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

int set_ip_level(int fd, struct iphdr *header, uint16_t pl_size, struct sockaddr_in to, in_addr_t from);

int send_raw_udp(int fd, udphdr_t *header, const struct sockaddr_in *serv, char *pl);

int send_raw_ip(int fd, struct iphdr *ip, udphdr_t *transport, struct sockaddr_in *to, char *pl);

// retun count byte of recv; < 0 is error
int recv_raw(int fd, struct sockaddr_in *get, char *buf, udphdr_t *serv);

// return new fd of socket and init sock_addr of server; -1 is error, other is successful
int init_addr(struct sockaddr_in *serv, sa_family_t family, char *ip, uint16_t port, int protocol);

void print_header_udp(udphdr_t *h);

void print_header_ip(struct iphdr *h);

#endif //RAW_SOCKET_RAW_H
