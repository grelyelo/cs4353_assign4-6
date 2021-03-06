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
char IFACE_NAME[CONFIG_FILE_MAX_LINE];
char TIMING[CONFIG_FILE_MAX_LINE];
char ERRBUF[PCAP_ERRBUF_SIZE];

eth_t * ethfd; 
pcap_t * pcap_dev_fd;

int main(int argc, char ** argv) 
{
	int send_enabled = 0;
    struct addr ad;
    int pcap_fd;
    int config_fd;
    char * pcap_fname, * config_fname;
    unsigned int first_sec; // First packet timestamp, seconds
    int first_usec; // First packet timestamp, microseconds. 
    int timing_mode;
    unsigned int elapsed_sec; // Time delta from first packet, seconds
    int elapsed_usec;         // Time delta from first packet, microseconds. 
    int teardown = 0;

    struct pcap_file_header pcap_header;
    struct my_pkthdr pkthdr;
    unsigned char * packet; // Some memory which is <snaplen> in size to hold our frames. 
    struct ip_hdr * ip_header; 
    struct tcp_hdr * tcp_header; 
	uint32_t init_ack; // holds ack number to put in the tcp header of packets we send. 
    uint32_t ack;
    uint32_t data_recvd; // amount of payload received from server

    if (argc == 2) {
		config_fname = argv[1];
    } else if (argc == 3) {
		if (strcmp(argv[1], "-s") == 0) 
			send_enabled = 1;
		config_fname = argv[2];
    } 

    if((config_fd = open(config_fname, O_RDONLY)) == -1) {
        fprintf(stderr, "error while opening %s: %d\n", config_fname, errno);
        return 1;
    };
    
    if(parse_config(config_fd) != 0) {
        fprintf(stderr, "error while parsing config %s\n", config_fname);
        return 1;
    }

	pcap_fname = PCAP_FILENAME;
    if((pcap_fd = open(pcap_fname, O_RDONLY)) == -1) {
        fprintf(stderr, "error while opening %s: %d\n", pcap_fname, errno);
        return 1;
    };


   	// Set timing mode
    if ( strcmp(TIMING, DELAY_TIMING_STR) == 0 ) { 
        timing_mode = DELAY_TIMING;
    } else if ( strcmp(TIMING, REACTIVE_TIMING_STR) == 0) { 
        timing_mode = REACTIVE_TIMING;
    } else if (strcmp(TIMING, EXACT_TIMING_STR) == 0) { 
        timing_mode = EXACT_TIMING;
    } else { 
        timing_mode = CONTINUOUS_TIMING;
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
    // printf("PCAP_MAGIC\n"); /* magic file header */
    // printf("Version major number = %d\n", pcap_header.version_major); /* major number */
    // printf("Version minor number = %d\n", pcap_header.version_minor); /* minor number */
    // printf("GMT to local correction = %d\n", pcap_header.thiszone); /* gmt to local correction */
    // printf("Timestamp accuracy = %d\n", pcap_header.sigfigs);
    // printf("Snaplen = %d\n", pcap_header.snaplen); 
    // printf("Linktype = %d\n", pcap_header.linktype);
    // printf("\n");

    if((packet = malloc(pcap_header.snaplen)) == NULL) {
        fprintf(stderr, "could not allocate memory for frames\n");
        return 1;
    }

	// Open devices
    // 1. Open ethernet device for sending packets
    ethfd = eth_open(IFACE_NAME);
    if ( ethfd == NULL ) {
		perror("eth_open error");
        return 1;
    }

	// 2. Open packet capture device (non-promisc mode) using same ethernet device as before
	pcap_dev_fd = pcap_open_live(IFACE_NAME, 65535, 0, DEFAULT_RECV_TIMEOUT, ERRBUF);
	if ( pcap_dev_fd == NULL ) {
		fprintf(stderr, "pcap_open_live error: %s", ERRBUF);
        return 1;
	}

    int i = 1;
    while(read_packet_header(pcap_fd, &pkthdr) == 0) {

        // Calculate timestamp
        if(i == 1) {
            first_sec = pkthdr.ts.tv_sec;
            first_usec = pkthdr.ts.tv_usec;
        }
        elapsed_sec = pkthdr.ts.tv_sec - first_sec;
        elapsed_usec = pkthdr.ts.tv_usec - first_usec;
        while(elapsed_usec < 0) {
            elapsed_sec--;
            elapsed_usec += 1000000;
        }

        // Read packet from pcap
        read_packet(pcap_fd, packet, pkthdr.len);

		// Display packet metadata & data
        printf("Packet %d\n", i);
        printf("%u.%06u\n", (unsigned)elapsed_sec, (unsigned)elapsed_usec);
        printf("Captured Packet Length = %u\n", pkthdr.caplen);
        printf("Actual Packet Length = %u\n", pkthdr.len);
 
		/* 
            check to see whether this packet is an attacker or a victim packet. 
            if victim, wait until we get a packet then 
                update the ack number for next sent packet, continue
                otherwise, continue (do next iteration, read next packet, etc). 
                if no packet within a timeframe, report error, continue
            if attacker, replace fields, send packet (if enabled).  
        */

		// Display the modified packet
		// Check if src ip matches the new attacker IP, if it does, send it. 
		if(send_enabled) { 
            ip_header = (struct ip_hdr *) (packet + ETH_HDR_LEN);
			addr_pack(&ad, ADDR_TYPE_IP, IP_ADDR_BITS, &(ip_header->ip_src), IP_ADDR_LEN);
			if( addr_cmp(&ad, &orig_attacker_ip_addr) == 0 ) {
                
                tcp_header = (struct tcp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);

				do_replacement(packet, ack);            // Replace values + recompute checksum on packet. 
                printf("Packet #%d\n",i);
				parse_packet(packet);                   // Show the values from the modified packet. 
				eth_send(ethfd, packet, pkthdr.len);    // send the packet 
				switch(timing_mode) { 
					case DELAY_TIMING:
						nanosleep((const struct timespec[]){{0, 500000L}}, NULL);
						break;
				}
			} else { 
				// get a packet from the victim 
				const unsigned char * recv_packet = pcap_next(pcap_dev_fd, (struct pcap_pkthdr *) &pkthdr);
                ip_header = (struct ip_hdr *) (recv_packet + ETH_HDR_LEN);
                addr_pack(&ad, ADDR_TYPE_IP, IP_ADDR_BITS, &(ip_header->ip_src), IP_ADDR_LEN);
                while((recv_packet != NULL) && addr_cmp(&ad, &replay_victim_ip_addr) != 0) {
                    const unsigned char * recv_packet = pcap_next(pcap_dev_fd, (struct pcap_pkthdr *) &pkthdr);                
                    ip_header = (struct ip_hdr *) (recv_packet + ETH_HDR_LEN);
                    addr_pack(&ad, ADDR_TYPE_IP, IP_ADDR_BITS, &(ip_header->ip_src), IP_ADDR_LEN);
                }
				if (recv_packet != NULL) {
                    tcp_header = (struct tcp_hdr *) (recv_packet + ETH_HDR_LEN + IP_HDR_LEN);
                    printf("Packet #%d\n",i);
                    parse_packet(recv_packet);                   // Show the values from the modified packet. 
                    if( (tcp_header->th_flags & (TH_ACK|TH_SYN)) == (TH_ACK|TH_SYN)) { // SYN/ACK
                        data_recvd = 0;
                        init_ack = ntohl(tcp_header->th_seq) + 1; // increment by 1 for ACK in 3way handshake
                        ack = init_ack;
                    } else if  ((tcp_header->th_flags & (TH_FIN))) { // break, close connection
                        data_recvd += (ntohs(ip_header->ip_len) - IP_HDR_LEN - (tcp_header->th_off * 4));
                        ack = init_ack + data_recvd;                        
                        teardown = 1;
                        i++;
                        break;                        
                    } else { 
                        // Add length of packet data to our ack
                        data_recvd += (ntohs(ip_header->ip_len) - IP_HDR_LEN - (tcp_header->th_off * 4));
                        ack = init_ack + data_recvd;
                    }				
				} else { // couldn't get a packet, so use the packet from the capture instead of the recieved packet. 
                    ip_header = (struct ip_hdr *) (packet + ETH_HDR_LEN);
                    tcp_header = (struct tcp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);

                    data_recvd += (ntohs(ip_header->ip_len) - IP_HDR_LEN - (tcp_header->th_off * 4));
                    ack = init_ack + data_recvd;
                }
			}
		}
        i++;
    }
    // TEARDOWN CONNECTION, read packets until we get a FIN/ACK packet sent by the original attacker. 
    while(teardown && read_packet_header(pcap_fd, &pkthdr) == 0 ) { 
        elapsed_sec = pkthdr.ts.tv_sec - first_sec;
        elapsed_usec = pkthdr.ts.tv_usec - first_usec;
        while(elapsed_usec < 0) {
            elapsed_sec--;
            elapsed_usec += 1000000;
        }
        read_packet(pcap_fd, packet, pkthdr.len);
        ip_header = (struct ip_hdr *) (packet + ETH_HDR_LEN);
        tcp_header = (struct tcp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);
        addr_pack(&ad, ADDR_TYPE_IP, IP_ADDR_BITS, &(ip_header->ip_src), IP_ADDR_LEN);
        if((addr_cmp(&ad, &orig_attacker_ip_addr) == 0) && 
           (tcp_header->th_flags & (TH_FIN))) {
            
            printf("Packet %d\n", i);
            printf("%u.%06u\n", (unsigned)elapsed_sec, (unsigned)elapsed_usec);
            printf("Captured Packet Length = %u\n", pkthdr.caplen);
            printf("Actual Packet Length = %u\n", pkthdr.len);
            ack++;
            do_replacement(packet, ack);            // Replace values + recompute checksum on packet. 
            parse_packet(packet);                   // Show the values from the modified packet. 
            eth_send(ethfd, packet, pkthdr.len);    // send the packet 
        }
    }
    
    free(packet);
    if(close(pcap_fd) != 0) {
        fprintf(stderr, "error while closing %s: %d\n", pcap_fname, errno);
        return 1;
    }
    return 0;
}
