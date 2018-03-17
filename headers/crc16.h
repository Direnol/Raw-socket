#ifndef RAW_SOCKET_CRC16_H
#define RAW_SOCKET_CRC16_H

#include <glob.h>
#include <zconf.h>
#include <stdint.h>
#include <netinet/in.h>
#include <string.h>


uint16_t csum(const uint16_t *ptr, uint16_t nbytes);


#endif //RAW_SOCKET_CRC16_H
