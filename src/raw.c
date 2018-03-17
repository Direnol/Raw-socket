#include <net/if.h>
#include "../headers/raw.h"

//unsigned char DEFAULT_ADDR[6] = {0xc2, 0x06, 0x0c, 0x35, 0x00, 0x00};
unsigned char DEFAULT_ADDR[6] = {0xbc, 0x5f, 0xf4, 0x6d, 0x01, 0x12};

void set_transport_level(udphdr_t *header, uint16_t src_p, uint16_t dst_p, uint16_t len)
{
    if (!header) return;
    header->source = htons(src_p);
    header->dest = htons(dst_p);
    header->len = htons((uint16_t) (sizeof(*header) + len));
    header->check = 0;
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
    return socket(family, SOCK_RAW, protocol);
}

void print_header_udp(udphdr_t *h)
{
    puts("TRANSPORT UDP:");
    uint16_t len_msg = ntohs(h->len) - sizeof(*h);
    printf("Len : %d [%d]; Msg %hu, struct %hu\n", ntohs(h->len), h->len, len_msg, htons(h->len) - len_msg);
    printf("src %hu dst %hu check %hu\n", ntohs(h->source), ntohs(h->dest), ntohs(h->check));
}

int recv_raw(int fd, struct sockaddr_in *get, char *buf, uint16_t dport)
{
    socklen_t socklen = sizeof(*get);
    ssize_t ret = recvfrom(fd, buf, UINT16_MAX, 0, (struct sockaddr *) get, &socklen);
    struct udphdr *uh = (struct udphdr *) (buf + sizeof(struct iphdr));
    if (dport == uh->source) {
        return (int) ret;
    }
    if (ret < 0) return -1;
    return 0;
}

int set_ip_level(int fd, struct iphdr *header, uint16_t pl_size, in_addr_t to, in_addr_t from)
{
    if (fd > 0) {
        int ip_on = 1;
        if (setsockopt(fd, SOL_IP, IP_HDRINCL, &ip_on, sizeof(ip_on))) {
            return EXIT_FAILURE;
        }
    }
    header->ihl = sizeof(*header) >> 2; // count of 4-bytes words
    header->version = IPVERSION; // version 4 or 6

    header->tos = 0;
    header->tot_len = htons(pl_size + sizeof(*header) + sizeof(struct udphdr));

    srand((unsigned int) time(NULL));
    header->id = htons(rand());//(uint16_t) random());
    header->frag_off = 0;
    header->ttl = 65;

    header->protocol = IPPROTO_UDP;
    header->check = 0;

    header->saddr = from;
    header->daddr = to;

    header->check = (csum((const uint16_t *) header, sizeof(*header)));
//    print_header_ip(header);
    return EXIT_SUCCESS;
}

int send_raw_ip(int fd, struct iphdr *ip, udphdr_t *transport, struct sockaddr_in *to, char *pl)
{
    static char buf[UINT16_MAX];
    memcpy(buf, (const char *) ip, sizeof(*ip));
    memcpy(buf + sizeof(*ip), transport, sizeof(*transport));
    strncpy(buf + sizeof(*ip) + sizeof(*transport), pl, ntohs(transport->len) - sizeof(*transport));
    if (sendto(fd, buf, ntohs(ip->tot_len), 0, (const struct sockaddr *) to, sizeof(*to)) <= 0) {
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
    printf("Csum: 0x%04X[%d]\n", ntohs(h->check), h->check);
    printf("total len: %d[%d]\n", h->tot_len, ntohs(h->tot_len));
    printf("ttl: %d\n", h->ttl);
    printf("protocol: %d\n", h->protocol);
    printf("id: %d[%d]\n", h->id, ntohs(h->id));
    printf("tos: %d\n", h->tos);
    char *bin = (char *) h;
    char buf[9];
    for (int i = 0; i < sizeof(*h); ++i) {
        for (int j = 0; j < 2; ++j, ++i) {
            bin_print(bin[i], 1);
        }
        puts("");
    }
    free(src);
    free(dst);
}

int send_eth_pack(int fd, void *_data, uint16_t len, char *sip, char *dip, uint16_t sport, uint16_t dport)
{
    uint16_t all_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + len;
    void *buf = calloc(all_len, sizeof(char));
    if (!buf) return EXIT_FAILURE;
    struct ether_header *eth = buf;
    struct iphdr *ip = buf + sizeof(struct ether_header);
    udphdr_t *udp = (struct udphdr *) ((char *)ip + sizeof(struct iphdr));
    char *data = ((char *)udp + sizeof(struct udphdr));
    memcpy(data, _data, len);
    set_transport_level(udp, sport, dport, len);
    set_ip_level(0, ip, len, inet_addr(dip), inet_addr(sip));
    udp_csum(udp, ip);

#define IOCERR(f) if ((f) < 0) exit(1)

    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strcpy(if_idx.ifr_name, DEFAULT_INT);
    IOCERR(ioctl(fd, SIOCGIFINDEX, &if_idx));

    struct ifreq if_mac;
    memset(&if_mac, 0, sizeof(struct ifreq));
    strcpy(if_mac.ifr_name, DEFAULT_INT);
    IOCERR(ioctl(fd, SIOCGIFHWADDR, &if_mac));

    struct sockaddr_ll serv;
    socklen_t slen = sizeof(serv);
    memset(&serv, 0, slen);

    serv.sll_family = AF_PACKET;
    serv.sll_protocol = htons(ETH_P_IP);
    serv.sll_ifindex = if_idx.ifr_ifindex;
    serv.sll_halen = ETH_ALEN;
    memcpy(serv.sll_addr, DEFAULT_ADDR, 6);

    set_eth_level(eth, if_mac.ifr_ifru.ifru_hwaddr.sa_data, DEFAULT_ADDR, (ETH_P_IP));

    //print_packet(buf, all_len);
    int ret = (int) sendto(fd, buf, all_len, 0, (const struct sockaddr *) &serv, slen);
    free(buf);
    printf("ret %d\n", ret);
    if (ret < 0) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

int set_eth_level(struct ether_header *pHeader, char *data, unsigned char *addr, uint16_t type)
{
    memcpy(pHeader->ether_shost, data, ETH_ALEN);
    memcpy(pHeader->ether_dhost, addr, ETH_ALEN);
    pHeader->ether_type = htons(type);
}

void bin_print(char byte, int8_t dlm)
{
    char buf[9];
    for (int k = 7; k >= 0; --k) {
        buf[7 - k] = (char) (((byte >> k) & 0x1) + '0');
    }
    buf[8] = '\0';
    for (int _i = 0; _i < 4; ++_i) putc(buf[_i], stdout);
    if (dlm)
        putc(' ', stdout);
    for (int _i = 4; _i < 9; ++_i) putc(buf[_i], stdout);
    if (dlm)
        putc(' ', stdout);
}

void print_header_eth(struct ether_header *eth)
{
    printf("Src mac: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02X%c", eth->ether_shost[i], (i == ETH_ALEN - 1 ? '\n' : ':'));
    }
    printf("Dst mac: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02X%c", eth->ether_dhost[i], (i == ETH_ALEN - 1 ? '\n' : ':'));
    }
    printf("Type %04X\n", eth->ether_type);
}

void print_packet(uint8_t *packet, uint16_t n)
{
    for (int cur = 0 ; cur < n; ++cur) {
        int tmp = cur;
        for (int i = 0; i < 16; ++i, ++cur) {
            if (cur < n) printf("%02X|", packet[cur]);
            else printf("   ");
        }
        printf("\t");
        for (int i = 0; i < 16; ++i, ++tmp) {
            const int c = (isprint(packet[tmp]) ? packet[tmp] : '.');
            if (tmp < n) printf("%c", c);
            else printf("   ");
        }
        puts("");
    }
    puts("_______________________________________");

}

void udp_csum(struct udphdr *udph, struct iphdr *iph)
{
    unsigned short  udpplen = 0;
    unsigned char* block = NULL;
    struct pseudo_header* ph = NULL;

    udpplen = ntohs(udph->len);

    ph = malloc(sizeof(struct pseudo_header));
    if (ph == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    ph->source_address = iph->saddr;
    ph->dest_address= iph->daddr;
    ph->placeholder= 0;
    ph->protocol = iph->protocol;
    ph->udp_length= udph->len;

    block = malloc(sizeof(struct pseudo_header) + udpplen);
    if (block == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    udph->check = 0;

    memcpy(block, ph, sizeof(struct pseudo_header));
    memcpy(block + sizeof(struct pseudo_header), udph, udpplen);

    udph->check = csum((unsigned short*)block, sizeof(struct pseudo_header) + udpplen);
}
