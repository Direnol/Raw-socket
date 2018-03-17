#include <stdint.h>
#include "../headers/crc16.h"

uint16_t csum(const uint16_t *ptr, uint16_t nbytes)
{
    register long sum;
    unsigned short oddbyte;
    unsigned short answer;
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (unsigned short) ~sum;
    return (answer);
}

