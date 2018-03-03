#include <stdio.h>
#include "../headers/raw.h"


int main(int argc, char **argv)
{
    uint16_t dport = 7777;
    uint16_t sport = 55005;
    char ip[INET_ADDRSTRLEN] = "127.0.0.1";
    char msg[UINT16_MAX] = "lel";
    if (argc >= 2) strcpy(msg, argv[1]);
    if (argc >= 3) dport = (uint16_t) atoi(argv[2]);
    if (argc >= 4) sport = (uint16_t) atoi(argv[3]);
    if (argc >= 5) strcpy(ip, argv[4]);
    int fd;
    struct sockaddr_in serv;
    printf("ip [%s]; msg [%s]\n", ip, msg);
    if ((fd = init_addr(&serv, AF_INET, ip, dport)) < 0) {
        perror("Init");
        return EXIT_FAILURE;
    }
    udphdr_t head;
    set_transport_level(&head, sport, dport, (uint16_t) (strlen(msg) + 1));
    print_header(&head);
    if (send_raw(fd, &head, &serv, msg)) {
        perror("Send raw");
    }
    struct sockaddr_in get;
    int ret = 0;
    while ((ret = recv_raw(fd, &get, msg, &head)) <= 0) {
        if (ret < 0) {
            perror("Get msg");
            break;
        }
    }
    if (ret > 0) {
        printf("Get msg [%s]\n", msg);
    }
    close(fd);
    return EXIT_SUCCESS;
}