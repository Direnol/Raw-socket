#include "../headers/raw.h"


void set_transport_level(udphdr_t *header, uint16_t src_p, uint16_t dst_p, uint16_t len)
{
    if (!header) return;
    header->check = 0;
    header->dest = htons(dst_p);
    header->source = htons(src_p);
    header->len = htons((uint16_t) (sizeof(*header) + len));
}

int send_raw(int fd, udphdr_t *header, const struct sockaddr_in *serv, char *pl)
{
    static char buf[UINT16_MAX];
    memcpy(buf, (const char *) header, sizeof(*header));
    strncpy(buf + sizeof(*header), pl, ntohs(header->len) - sizeof(*header));
    if (sendto(fd, buf, ntohs(header->len), 0, (const struct sockaddr *) serv, sizeof(*serv)) < 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int init_addr(struct sockaddr_in *serv, sa_family_t family, char *ip, uint16_t port)
{
    serv->sin_port = htons(port);
    serv->sin_family = family;
    memset(serv->sin_zero, 0, sizeof(serv->sin_zero));
    if (inet_aton(ip, &serv->sin_addr) == 0) return -1;
    return socket(family, SOCK_RAW, IPPROTO_UDP);
}
void print_header(udphdr_t *h)
{
    uint16_t len_msg = ntohs(h->len) - sizeof(*h);
    printf("Len : %d [%d]; Msg %hu, struct %hu\n", ntohs(h->len), h->len, len_msg, htons(h->len) - len_msg);
    printf("src %hu dst %hu check %hu\n", ntohs(h->source), ntohs(h->dest), ntohs(h->check));
}

int recv_raw(int fd, struct sockaddr_in *get, char *buf, udphdr_t *serv)
{
    socklen_t socklen = sizeof(*get);
    ssize_t ret = recvfrom(fd, buf, UINT16_MAX, 0, (struct sockaddr *) get, &socklen);
    if (serv->dest == get->sin_port) return (int) ret;
    else if (ret < 0) return -1;
    return 0;
}
