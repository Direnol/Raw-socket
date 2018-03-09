#include "../headers/raw.h"


void set_transport_level(udphdr_t *header, uint16_t src_p, uint16_t dst_p, uint16_t len)
{
    if (!header) return;
    header->check = 0;
    header->dest = htons(dst_p);
    header->source = htons(src_p);
    header->len = htons((uint16_t) (sizeof(*header) + len));
}

int send_raw_udp(int fd, udphdr_t *header, const struct sockaddr_in *serv, char *pl)
{
    static char buf[UINT16_MAX];
    memcpy(buf, (const char *) header, sizeof(*header));
    strncpy(buf + sizeof(*header), pl, ntohs(header->len) - sizeof(*header));
    if (sendto(fd, buf, ntohs(header->len), 0, (const struct sockaddr *) serv, sizeof(*serv)) < 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int init_addr(struct sockaddr_in *serv, sa_family_t family, char *ip, uint16_t port, int protocol)
{
    serv->sin_port = htons(port);
    serv->sin_family = family;
    memset(serv->sin_zero, 0, sizeof(serv->sin_zero));
    if (inet_aton(ip, &serv->sin_addr) == 0) return -1;
    return socket(family, SOCK_RAW, IPPROTO_UDP);
}
void print_header_udp(udphdr_t *h)
{
    puts("TRANSPORT UDP:");
    uint16_t len_msg = ntohs(h->len) - sizeof(*h);
    printf("Len : %d [%d]; Msg %hu, struct %hu\n", ntohs(h->len), h->len, len_msg, htons(h->len) - len_msg);
    printf("src %hu dst %hu check %hu\n", ntohs(h->source), ntohs(h->dest), ntohs(h->check));
}

int recv_raw(int fd, struct sockaddr_in *get, char *buf, udphdr_t *serv)
{
    socklen_t socklen = sizeof(*get);
    ssize_t ret = recvfrom(fd, buf, UINT16_MAX, 0, (struct sockaddr *) get, &socklen);
    struct iphdr *net = (struct iphdr *) buf;
    struct udphdr *uh = (struct udphdr *) (buf + sizeof(*net));
    if (serv->dest == uh->source) {
        return (int) ret;
    }
    if (ret < 0) return -1;
    return 0;
}

int set_ip_level(int fd, struct iphdr *header, uint16_t pl_size, struct sockaddr_in to, in_addr_t from)
{
    int ip_on = 1;
    if (setsockopt(fd, SOL_IP, IP_HDRINCL, &ip_on, sizeof(ip_on))) {
        return EXIT_FAILURE;
    }
    header->ihl = sizeof(*header) / 4; // count of 4-bytes words
    header->version = IPVERSION; // version 4 or 6
    header->tos = 0;
    header->tot_len = htons(pl_size + sizeof(*header));
    header->id = htons((uint16_t) fd);
    header->frag_off = 0x00;
    header->ttl = 0xff;
    header->protocol = IPPROTO_UDP;
    header->check = 0;
    header->saddr = from;
    header->daddr = to.sin_addr.s_addr;
    //chsum
    return EXIT_SUCCESS;
}

int send_raw_ip(int fd, struct iphdr *ip, udphdr_t *transport, struct sockaddr_in *to, char *pl)
{
    static char buf[UINT16_MAX];
    memcpy(buf, (const char *) ip, sizeof(*ip));
    memcpy(buf + sizeof(*ip), transport, sizeof(*transport));
    strncpy(buf + sizeof(*ip) + sizeof(*transport), pl, ntohs(transport->len) - sizeof(*transport));
    if (sendto(fd, buf, ntohs(ip->tot_len), 0, (const struct sockaddr *) to, sizeof(*to)) < 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

void print_header_ip(struct iphdr *h)
{
    struct in_addr _ip[2];
    _ip[0].s_addr = h->saddr;
    _ip[1].s_addr = h->daddr;
    char *src = strdup(inet_ntoa(_ip[0]));
    char *dst = strdup(inet_ntoa(_ip[1]));
    printf("IP : src [%s] dst [%s]\n", src, dst);
    free(src);
    free(dst);
}
