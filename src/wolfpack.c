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
    for (unsigned int j=0; j<5; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    // print [destination address - 5 bytes]
    for (unsigned int j=0; j<5; j++) {
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
    for (unsigned int j=0; j<3; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    // print [flags - 2 bytes]
    for (unsigned int j=0; j<2; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    // print [total length - 3 bytes]
    unsigned int total_byte_length = 0;
    for (unsigned int j=0; j<3; j++) {
        printf("%02x", *packet);
        
        // add new byte to compute byte length
        total_byte_length<<= 8;
        total_byte_length|= *packet;
        
        packet++;
    }
    printf("\n");

    // print [checksum - 4 bytes]
    for (unsigned int j=0; j<4; j++) {
        printf("%02x", *packet);
        packet++;
    }
    printf("\n");

    unsigned int payload_byte_length = total_byte_length - 24;
    // print [payload]
    for (unsigned int j=0; j<payload_byte_length; j++) {
        printf("%c", *packet);
        packet++;
    }
    printf("\n");
}

#define SOURCE_PORT 32
#define DEST_PORT 64

unsigned int packetize_sf(const char *message, unsigned char *packets[], unsigned int packets_len, unsigned int max_payload, unsigned long src_addr, unsigned long dest_addr, unsigned short flags) {
    unsigned int message_len = strlen(message);
    unsigned int packets_needed = message_len / max_payload;
    if (message_len % max_payload)
        packets_needed++;
    if (packets_needed > packets_len)
        packets_needed = packets_len;

    if (packets_needed < 1)
        return 0;

    unsigned int packets_made = 0;
    unsigned int remaining_message_len = message_len;
    
    // we first make any many max payload packets as possibl
    for (unsigned int i=0; i<packets_needed; i++) {
        unsigned int payload_size = remaining_message_len < max_payload ? remaining_message_len : max_payload;
        remaining_message_len-= payload_size;

        unsigned int packet_size = 24 + payload_size;

        packets[i] = malloc(packet_size);
        unsigned char* packet = packets[i];

        // store addresses
        for (unsigned int j=0; j<5; j++)
            packet[j] = src_addr >> (8 * (4 - j)) & 0xff;
        for (unsigned int j=0; j<5; j++)
            packet[5 + j] = dest_addr >> (8 * (4 - j)) & 0xff;

        // store ports
        packet[10] = SOURCE_PORT;
        packet[11] = DEST_PORT;

        // add offset
        unsigned int fragment_offset = packets_made * max_payload;
        for (unsigned int j=0; j<3; j++)
            packet[12 + j] = fragment_offset >> (8 * (2 - j)) & 0xff;

        // store flags
        for (unsigned int j=0; j<2; j++)
            packet[15 + j] = flags >> (8 * (1 - j)) & 0xff;

        for (unsigned int j=0; j<3; j++)
            packet[17 + j] = packet_size >> (8 * (2 - j)) & 0xff;

        // add checksum
        unsigned int checksum = checksum_sf(packet);
        for (unsigned int j=0; j<4; j++)
            packet[20 + j] = checksum >> (8 * (3 - j)) & 0xff;

        // add payload
        for (unsigned int j=0; j<payload_size; j++) {
            packet[24 + j] = *message;
            message++;
        }

        packets_made++;
    }

    return packets_made;
}

unsigned int checksum_sf(const unsigned char *packet) {
    unsigned long out = 0;

    unsigned long temp = 0;
    // add [source address - 5 bytes]
    for (unsigned int j=0; j<5; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // add [destination address - 5 bytes]
    temp = 0;
    for (unsigned int j=0; j<5; j++) {
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
    for (unsigned int j=0; j<3; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // add [flags - 2 bytes]
    temp = 0;
    for (unsigned int j=0; j<2; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // add [total length - 3 bytes]
    temp = 0;
    for (unsigned int j=0; j<3; j++) {
        temp<<= 8;
        temp|= *packet;
        packet++;
    }
    out+= temp;

    // ignore checksum and payload

    return out % ((1ul << 32) - 1);
}

unsigned int reconstruct_sf(unsigned char *packets[], unsigned int packets_len, char *message, unsigned int message_len) {
    unsigned char *packet;

    for (unsigned int i=0; i<message_len; i++)
        message[i] = '@';

    unsigned int CAP = message_len - 1;
    unsigned int actual_message_len = 0;
    unsigned int payloads_written = 0;
    for (unsigned int i=0; i<packets_len; i++) {
        packet = packets[i];

        // compute actual checksum
        unsigned int actual_check_sum = checksum_sf(packet);
        
        // skip 12 bytes to [fragment offset]
        packet+= 12;
        unsigned int fragment_offset = 0;
        for (unsigned int j=0; j<3; j++) {
            fragment_offset<<= 8;
            fragment_offset|= *packet;
            packet++;
        }

        // skip 2 bytes to total length
        packet+= 2;
        unsigned int total_byte_length = 0;
        for (unsigned int j=0; j<3; j++) {
            total_byte_length<<= 8;
            total_byte_length|= *packet;
            packet++;
        }
        unsigned int payload_byte_length = total_byte_length - 24;

        unsigned int checksum = 0;
        for (unsigned int j=0; j<4; j++) {
            checksum<<= 8;
            checksum|= *packet;
            packet++;
        }

        if (checksum != actual_check_sum)
            continue;

        // printf("\npayload [i=%d]=\"", i);
        // for (unsigned int k=0; k<payload_byte_length; k++) {
        //     printf("%c", packet[k]);
        // }
        // printf("\"\n");

        unsigned int wrote_payload = 0;
        unsigned int message_i = fragment_offset;
        for (unsigned int j=0; j<payload_byte_length; j++) {
            if (message_i >= CAP)
                break;
            message[message_i] = *packet;
            wrote_payload = 1;
            packet++;
            message_i++;
        }

        if (!payload_byte_length || wrote_payload) {
            // printf("\nwrote it\n");
            payloads_written++;
            if (message_i > actual_message_len)
                actual_message_len = message_i;
        }

        // SELF NOTE: actual_message_len can be at CAP, 
        // but there can still be packets that will cover the front parts of the message
    }

    if (payloads_written < 1)
        return 0;

    message[actual_message_len] = 0;
    
    return payloads_written;
}
