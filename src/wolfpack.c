#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>

#include "wolfpack.h"

void print_packet_sf(const unsigned char *packet) {
}

unsigned int packetize_sf(const char *message, unsigned char *packets[], unsigned int packets_len, unsigned int max_payload,
    unsigned long src_addr, unsigned long dest_addr, unsigned short flags) {
    return 0;
}

unsigned int checksum_sf(const unsigned char *packet) {
    return 0;
}

unsigned int reconstruct_sf(unsigned char *packets[], unsigned int packets_len, char *message, unsigned int message_len) {
    return 0;
}

