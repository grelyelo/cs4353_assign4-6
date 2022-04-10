#include "common.h"
#include "util.h"

struct addr orig_victim_ip_addr;
struct addr orig_victim_eth_addr;
int orig_victim_port; 

struct addr orig_attacker_ip_addr;
struct addr orig_attacker_eth_addr;
int orig_attacker_port;

struct addr replay_victim_ip_addr;
struct addr replay_victim_eth_addr;
int replay_victim_port; 

struct addr replay_attacker_ip_addr;
struct addr replay_attacker_eth_addr;
int replay_attacker_port;

char PCAP_FILENAME[CONFIG_FILE_MAX_LINE]; 

int main(int argc, char ** argv) 
{
    int pcap_fd;
    int config_fd;
    char * pcap_fname, * config_fname;
    unsigned int first_sec; // First packet timestamp, seconds
    int first_usec; // First packet timestamp, microseconds. 

    unsigned int elapsed_sec; // Time delta from first packet, seconds
    int elapsed_usec;         // Time delta from first packet, microseconds. 

    struct pcap_file_header pcap_header;
    struct my_pkthdr pkthdr;
    char * packet; // Some memory which is <snaplen> in size to hold our frames. 

    if (argc == 2) {
        config_fname = argv[1];
        if((config_fd = open(config_fname, O_RDONLY)) == -1) {
            fprintf(stderr, "error while opening %s: %d\n", config_fname, errno);
            return 1;
        };
        
        if(parse_config(config_fd) != 0) {
            fprintf(stderr, "error while parsing config %s\n", config_fname);
            return 1;
        }
        return 0;
    } else if (argc != 3) {
        printf("Usage: %s <pcap file>\n", argv[0]);
        return 1;
    } 
    pcap_fname = argv[1];
    config_fname = argv[2];
    if((pcap_fd = open(pcap_fname, O_RDONLY)) == -1) {
        fprintf(stderr, "error while opening %s: %d\n", pcap_fname, errno);
        return 1;
    };

    if((config_fd = open(config_fname, O_RDONLY)) == -1) {
        fprintf(stderr, "error while opening %s: %d\n", config_fname, errno);
        return 1;
    };
    
    if(parse_config(config_fd) != 0) {
        fprintf(stderr, "error while parsing config %s\n", config_fname);
        return 1;
    }


    if( read_pcap_header(pcap_fd, &pcap_header) != 0 ) {
        close(pcap_fd);
        return 1;
    }
    if(pcap_header.magic != PCAP_MAGIC) {
        fprintf(stderr, "bad magic: %x", pcap_header.magic);
        close(pcap_fd);
        return 1;
    }
    printf("PCAP_MAGIC\n"); /* magic file header */
    printf("Version major number = %d\n", pcap_header.version_major); /* major number */
    printf("Version minor number = %d\n", pcap_header.version_minor); /* minor number */
    printf("GMT to local correction = %d\n", pcap_header.thiszone); /* gmt to local correction */
    printf("Timestamp accuracy = %d\n", pcap_header.sigfigs);
    printf("Snaplen = %d\n", pcap_header.snaplen); 
    printf("Linktype = %d\n", pcap_header.linktype);
    printf("\n");

    if((packet = malloc(pcap_header.snaplen)) == NULL) {
        fprintf(stderr, "could not allocate memory for frames\n");
        return 1;
    }

    int i = 0;
    while(read_packet_header(pcap_fd, &pkthdr) == 0) {
        printf("Packet %d\n", i);

        if(i == 0) {
            first_sec = pkthdr.ts.tv_sec;
            first_usec = pkthdr.ts.tv_usec;
        }
        elapsed_sec = pkthdr.ts.tv_sec - first_sec;
        elapsed_usec = pkthdr.ts.tv_usec - first_usec;
        while(elapsed_usec < 0) {
            elapsed_sec--;
            elapsed_usec += 1000000;
        }

        printf("%u.%06u\n", (unsigned)elapsed_sec, (unsigned)elapsed_usec);
        printf("Captured Packet Length = %u\n", pkthdr.caplen);
        printf("Actual Packet Length = %u\n", pkthdr.len);

        // Read packet
        read_packet(pcap_fd, packet, pkthdr.len);
        // Parse the packet
        parse_packet(packet);
        printf("Packet %d MODIFIED\n", i);

        // Eth replacement
        // attacker
        // replace_eth(packet, &orig_attacker_eth_addr, &replay_attacker_eth_addr, SRC );
        // replace_eth(packet, &orig_attacker_eth_addr, &replay_attacker_eth_addr, DST );

        // // victim
        // replace_eth(packet, &orig_victim_eth_addr, &replay_victim_eth_addr, SRC );
        // replace_eth(packet, &orig_victim_eth_addr, &replay_victim_eth_addr, DST );

        // IP replacement
        // attacker
        replace_ip(packet, &orig_attacker_ip_addr, &replay_attacker_ip_addr, SRC); 
        replace_ip(packet, &orig_attacker_ip_addr, &replay_attacker_ip_addr, DST); 

        // victim
        replace_ip(packet, &orig_victim_ip_addr, &replay_victim_ip_addr, SRC); 
        replace_ip(packet, &orig_victim_ip_addr, &replay_victim_ip_addr, DST); 


        parse_packet(packet);

        i++;
    }
    free(packet);
    if(close(pcap_fd) != 0) {
        fprintf(stderr, "error while closing %s: %d\n", pcap_fname, errno);
        return 1;
    }
    return 0;
}