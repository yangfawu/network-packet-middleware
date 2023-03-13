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
    // print [source address - 5 bytes]
    for (int j=0; j<5; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    // print [destination address - 5 bytes]
    for (int j=0; j<5; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    // print [source port - 1 byte]
    printf("%02x\n", *packet);
    packet++;

    // print [destination port - 1 byte]
    printf("%02x\n", *packet);
    packet++;

    // print [fragment offset - 3 bytes]
    for (int j=0; j<3; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    // print [flags - 2 bytes]
    for (int j=0; j<2; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    // print [total length - 3 bytes]
    unsigned int total_byte_length = 0;
    for (int j=0; j<3; j++) {
        printf("%02x", *packet);
        
        // add new byte to compute byte length
        total_byte_length<<= 8;
        total_byte_length|= *packet;
        
        packet++;
    }
    printf("\n");

    // print [checksum - 4 bytes]
    for (int j=0; j<4; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    unsigned int payload_byte_length = total_byte_length - 24;
    // print [payload]
    for (int j=0; j<payload_byte_length; j++) {
        printf("%c", *packet);
        packet++;
    }
    printf("\n");
}

unsigned int packetize_sf(const char *message, unsigned char *packets[], unsigned int packets_len, unsigned int max_payload,
    unsigned long src_addr, unsigned long dest_addr, unsigned short flags) {
    return 0;
}

unsigned int checksum_sf(const unsigned char *packet) {
    unsigned int out = 0;

    unsigned int temp = 0;
    // add [source address - 5 bytes]
    for (int j=0; j<5; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // add [destination address - 5 bytes]
    temp = 0;
    for (int j=0; j<5; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // add [source port - 1 byte]
    out+= *packet;
    packet++;

    // add [destination port - 1 byte]
    out+= *packet;
    packet++;

    // add [fragment offset - 3 bytes]
    temp = 0;
    for (int j=0; j<3; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // add [flags - 2 bytes]
    temp = 0;
    for (int j=0; j<2; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // add [total length - 3 bytes]
    temp = 0;
    for (int j=0; j<3; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // ignore checksum and payload

    return out;
}

unsigned int reconstruct_sf(unsigned char *packets[], unsigned int packets_len, char *message, unsigned int message_len) {
    unsigned char *packet;

    unsigned int CAP = message_len - 1;
    unsigned int actual_message_len = 0;
    unsigned int payloads_written = 0;
    for (int i=0; i<packets_len; i++) {
        packet = packets[i];

        // compute actual checksum
        unsigned int actual_check_sum = checksum_sf(packet);
        
        // skip 12 bytes to [fragment offset]
        packet+= 12;
        unsigned int fragment_offset = 0;
        for (int j=0; j<3; j++) {
            fragment_offset<<= 8;
            fragment_offset|= *packet;
            packet++;
        }

        // skip 2 bytes to total length
        packet+= 2;
        unsigned int total_byte_length = 0;
        for (int j=0; j<3; j++) {
            total_byte_length<<= 8;
            total_byte_length|= *packet;
            packet++;
        }
        unsigned int payload_byte_length = total_byte_length - 24;

        unsigned int checksum = 0;
        for (int j=0; j<4; j++) {
            checksum<<= 8;
            checksum+= *packet;
            packet++;
        }

        if (checksum != actual_check_sum) {
            // printf("NO MATCH got=%x actual=%x\n", checksum, actual_check_sum);
            continue;
        }

        unsigned int wrote_payload = 0;
        for (unsigned int j=0; j<payload_byte_length; j++) {
            if (actual_message_len >= CAP)
                break;
            if (j + fragment_offset >= CAP)
                break;
            
            message[j + fragment_offset] = *packet;
            wrote_payload = 1;

            j++;
            packet++;
            actual_message_len++;
        }

        if (wrote_payload)
            payloads_written++;
    }

    if (payloads_written < 1)
        return 0;
    printf("\n");
    message[actual_message_len] = 0;
    return payloads_written;
}

// int main() {
//     unsigned char packet[] = "\x00\x00\x00\x30\x39\x00\x00\x01\x09\x3b\x20\x40\x00\x00\x00\x10\x00\x00\x00\x1d\x00\x01\x49\xf1\x41\x42\x43\x44\x45RANDOM GARBAGE YOU SHOULD NOT SEE THIS";
//     printf("%x\n", checksum_sf(packet));
//     return EXIT_SUCCESS;
// }
