#include <stdio.h>
#include <net/if.h>
#include "../headers/raw.h"

int main(int argc, char **argv)
{
    uint16_t dport = 6970;
    uint16_t sport = 7777; //55005;
    char dip[INET_ADDRSTRLEN] = "192.168.1.9";
    char sip[INET_ADDRSTRLEN] = "192.168.1.55";
    char msg[UINT16_MAX] = "lel";

    if (argc >= 2) strcpy(msg, argv[1]);
    if (argc >= 3) dport = (uint16_t) atoi(argv[2]);
    if (argc >= 4) sport = (uint16_t) atoi(argv[3]);
    if (argc >= 5) strcpy(dip, argv[4]);
    int fd;
    struct sockaddr_in serv;
    printf("ip [%s]; msg [%s]\n", dip, msg);
    if ((fd = init_addr(&serv, AF_INET, dip, dport, IPPROTO_UDP)) < 0) {
        perror("Init");
        return EXIT_FAILURE;
    }
    udphdr_t udph;
    struct iphdr iph;
    set_transport_level(&udph, sport, dport, (uint16_t) (strlen(msg) + 1));
    set_ip_level(fd, &iph, (uint16_t) (strlen(msg) + sizeof(udph) + 1), serv.sin_addr.s_addr, inet_addr(sip));
//    print_header_udp(&udph);
//    if (send_raw_udp(fd, &udph, &serv, msg)) {
//        perror("Send raw");
//    }
//    print_header_ip(&iph);
//    if (send_raw_ip(fd, &iph, &udph, &serv, msg)){
//        perror("send raw");
//        goto end;
//    }
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (send_eth_pack(fd, msg, (uint16_t) (strlen(msg) + 1), sip, dip, sport, dport)) {
        perror("Bad send");
    }
    struct sockaddr_in get;
    int ret = 0;
    while ((ret = recv_raw(fd, &get, msg, htons(dport))) <= 0) {
        if (ret < 0) {
            perror("Get msg");
            break;
        }
    }
    if (ret > 0) {
        puts("Get:");
        print_header_ip((struct iphdr *) msg);
        print_header_udp((udphdr_t *) (msg + sizeof(struct iphdr)));
        printf("Msg [%s]\n", msg + sizeof(struct iphdr) + sizeof(udphdr_t));
    }
    end:
    close(fd);

    return EXIT_SUCCESS;
}
