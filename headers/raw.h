#ifndef RAW_SOCKET_RAW_H
#define RAW_SOCKET_RAW_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include "crc16.h"

#define DEFAULT_INT "wlp3s0"

typedef struct udphdr udphdr_t;

struct pseudo_header
{
    in_addr_t source_address;
    in_addr_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

void set_transport_level(udphdr_t *header, uint16_t src_p, uint16_t dst_p, uint16_t len);

int set_ip_level(int fd, struct iphdr *header, uint16_t pl_size, in_addr_t to, in_addr_t from);

int send_raw_udp(int fd, udphdr_t *header, const struct sockaddr_in *serv, char *pl);

int send_raw_ip(int fd, struct iphdr *ip, udphdr_t *transport, struct sockaddr_in *to, char *pl);

// retun count byte of recv; < 0 is error
int recv_raw(int fd, struct sockaddr_in *get, char *buf, uint16_t dport);

// return new fd of socket and init sock_addr of server; -1 is error, other is successful
int init_addr(struct sockaddr_in *serv, sa_family_t family, char *ip, uint16_t port, int protocol);

void print_header_udp(udphdr_t *h);

void print_header_ip(struct iphdr *h);

void print_header_eth(struct ether_header *eth);

int send_eth_pack(int fd, void *data, uint16_t len, char *sip, char *dip, uint16_t sport, uint16_t dport);

int set_eth_level(struct ether_header *pHeader, char *data, unsigned char *addr, uint16_t type);

void bin_print(char byte, int8_t dlm);

void print_packet(uint8_t *packet, uint16_t len);

void udp_csum(struct udphdr *header, struct iphdr *);

#endif //RAW_SOCKET_RAW_H
