#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h> // libpcap
#include <dnet.h> // libdnet

#include "pcap_magic.h"
#include "my_pkthdr.h"

#define CONFIG_FILE_MAX_LINE 256

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

void display_pcap_header(struct pcap_file_header * );
void display_packet_header(struct my_pkthdr *);

int read_pcap_header(int, struct pcap_file_header *);
int read_packet_header(int, struct my_pkthdr * );
int read_packet(int, char *, int); 
int parse_config(int);

int main(int argc, char ** argv) 
{
    int pcap_fd;
    int config_fd;
    int count;
    char * pcap_fname, * config_fname;
    unsigned int first_sec; // First packet timestamp, seconds
    int first_usec; // First packet timestamp, microseconds. 

    unsigned int elapsed_sec; // Time delta from first packet, seconds
    int elapsed_usec;         // Time delta from first packet, microseconds. 

    struct eth_hdr *eth_header;
    struct ip_hdr *ip_header;
    struct tcp_hdr *tcp_header;
    struct udp_hdr *udp_header;
    struct icmp_hdr *icmp_header;
    struct arp_hdr *arp_header;

    struct addr ad;

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
        eth_header = (struct eth_hdr *) packet; // ethernet header comes first, parse it. 
        printf("Ethernet Header\n");
        addr_pack(&ad,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(eth_header->eth_src),ETH_ADDR_LEN);
        printf("\teth_src = %s\n", addr_ntoa(&ad));
        addr_pack(&ad,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(eth_header->eth_dst),ETH_ADDR_LEN);
        printf("\teth_dst = %s\n", addr_ntoa(&ad));

        switch(ntohs(eth_header->eth_type)) {
            case ETH_TYPE_IP:
                printf("\tIP\n");
                ip_header = (struct ip_hdr *) (packet + ETH_HDR_LEN);
                printf("\t\tip_len = %d\n", ntohs(ip_header->ip_len));
                addr_pack(&ad, ADDR_TYPE_IP, IP_ADDR_BITS, &(ip_header->ip_src), IP_ADDR_LEN);
                printf("\t\tip_src = %s\n", addr_ntoa(&ad));
                addr_pack(&ad, ADDR_TYPE_IP, IP_ADDR_BITS, &(ip_header->ip_dst), IP_ADDR_LEN);
                printf("\t\tip_dst = %s\n", addr_ntoa(&ad));

                switch(ip_header->ip_p) {
                    case IP_PROTO_TCP:
                        printf("\t\tTCP\n");
                        tcp_header = (struct tcp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);
                        printf("\t\t\tsrc_port = %d\n", ntohs(tcp_header->th_sport));
                        printf("\t\t\tdst_port = %d\n", ntohs(tcp_header->th_dport));
                        printf("\t\t\tseq = %u\n", ntohl(tcp_header->th_seq) );
                        printf("\t\t\tack = %u\n", ntohl(tcp_header->th_ack) );

                        break;
                    case IP_PROTO_UDP:
                        printf("\t\tUDP\n");
                        udp_header = (struct udp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);
                        printf("\t\t\tsrc_port = %d\n", ntohs(udp_header->uh_sport));
                        printf("\t\t\tdst_port = %d\n", ntohs(udp_header->uh_dport));
                        break;
                    case IP_PROTO_ICMP:
                        printf("\t\tICMP\n");
                        icmp_header = (struct icmp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);
                        switch(icmp_header->icmp_type) {
                            case ICMP_ECHO:
                                printf("\t\t\tEcho Request\n");
                                break;
                            case ICMP_ECHOREPLY:
                                printf("\t\t\tEcho Reply\n");
                                break;
                            case ICMP_UNREACH:
                                printf("\t\t\tDestination Unreachable");
                                break;
                            case ICMP_SRCQUENCH:
                                printf("\t\t\tSource Quench\n");
                                break;
                            case ICMP_REDIRECT:
                                printf("\t\t\tRedirect\n");
                                break;
                            case ICMP_ALTHOSTADDR:
                                printf("\t\t\tAlternate Host Address\n");
                                break;
                            case ICMP_RTRADVERT:
                                printf("\t\t\tRoute Adverstisement\n");
                                break;
                            case ICMP_RTRSOLICIT:
                                printf("\t\t\tRoute Selection\n");
                                break;  
                            case ICMP_TIMEXCEED:
                                printf("\t\t\tTime Exceeded\n");
                                break;
                            case ICMP_PARAMPROB:
                                printf("\t\t\tParameter Problem\n");
                                break;
                            case ICMP_TSTAMP:
                                printf("\t\t\tTimestamp\n");
                                break;
                            case ICMP_TSTAMPREPLY:
                                printf("\t\t\tTimestamp Reply\n");
                                break;
                            case ICMP_INFO:
                                printf("\t\t\tInformation Request\n");
                                break;
                            case ICMP_INFOREPLY:
                                printf("\t\t\tInformation Reply\n");
                                break;
                            case ICMP_MASK:
                                printf("\t\t\tAddress Mask Request\n");
                                break;
                            case ICMP_MASKREPLY:
                                printf("\t\t\tAddress Mask Reply\n");
                                break;
                            case ICMP_TRACEROUTE:
                                printf("\t\t\tTraceroute\n");
                                break;
                            case ICMP_DATACONVERR:
                                printf("\t\t\tDatagram Conversion Error\n");
                                break;
                            case ICMP_MOBILE_REDIRECT:
                                printf("\t\t\tMobile Redirect\n");
                                break;
                            case ICMP_IPV6_WHEREAREYOU:
                                printf("\t\t\tIPv6 Where-Are-You\n");
                                break;
                            case ICMP_IPV6_IAMHERE:
                                printf("\t\t\tIPv6 I-Am-Here\n");
                                break;
                            case ICMP_MOBILE_REG:
                                printf("\t\t\tMobile Registration Request\n");
                                break;
                            case ICMP_MOBILE_REGREPLY:
                                printf("\t\t\tMobile Reigistration Reply\n");
                                break;
                            case ICMP_DNS:
                                printf("\t\t\tDomain Name Request\n");
                                break;
                            case ICMP_DNSREPLY:
                                printf("\t\t\tDomain Name Reply\n");
                                break;
                            case ICMP_SKIP:
                                printf("\t\t\tSKIP\n");
                                break;
                            case ICMP_PHOTURIS:
                                printf("\t\t\tPhoturis\n");
                                break;
                            default:
                                printf("\t\t\tUnknown ICMP Type");
                                break;                        
                        }

                        break;
                    case IP_PROTO_IGMP:
                        printf("\t\tIGMP\n");
                        break;
                    default:
                        printf("\t\tUnknown layer 4 protocol 0x%x\n", ip_header->ip_p);
                        break;
                }

                break;
            case ETH_TYPE_ARP:
                printf("\tARP\n");
                arp_header = (struct arp_hdr *) (packet + ETH_HDR_LEN);
                switch(ntohs(arp_header->ar_op)) {
                    case ARP_OP_REQUEST:
                        printf("\t\tRequest\n");
                        break;
                    case ARP_OP_REPLY:
                        printf("\t\tReply\n");
                        break;
                    case ARP_OP_REVREQUEST:
                        printf("\t\tReverse Request\n");
                        break;
                    case ARP_OP_REVREPLY:
                        printf("\t\tReverse Reply\n");
                        break;
                    default:
                        printf("\t\tUnknown ARP Operation\n");
                        break;
                }
                break;
            default:
                printf("\tUnknown layer 3 protocol 0x%x\n", eth_header->eth_type);
                break;
        }
        i++;
    }
    free(packet);
    if(close(pcap_fd) != 0) {
        fprintf(stderr, "error while closing %s: %d\n", pcap_fname, errno);
        return 1;
    }
    return 0;
}


int read_pcap_header(int fd, struct pcap_file_header * pcap_header)
{
    if((read(fd, pcap_header, sizeof(struct pcap_file_header)) != sizeof(struct pcap_file_header)))
        return 1;
    if(pcap_header->magic != PCAP_MAGIC)
        return 2;
    return 0;
}


int read_packet_header(int fd, struct my_pkthdr * pkthdr) 
{
    if((read(fd, pkthdr, sizeof(struct my_pkthdr)) != sizeof(struct my_pkthdr))) 
        return 1;
    return 0;
}

int read_packet(int fd, char * packet, int pkt_len) 
{
    if((read(fd, packet, pkt_len) != pkt_len))
        return 1;
    return 0;
}


int parse_config(int fd) 
{ 
	FILE * fp;
    char line[256];
    int d; 

	if ( (fp = fdopen(fd, "r")) == NULL ) {
		return 1;
	}

    if (fscanf(fp, "%s\n", PCAP_FILENAME) != 1 ) { 
        return 1;
    }
    
    // Original Victim
    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &orig_victim_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &orig_victim_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) return 1; 
    orig_victim_port = d;

    // Original Attacker
    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &orig_attacker_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &orig_attacker_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) return 1; 
    orig_attacker_port = d;

    // Replay victim
    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &replay_victim_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &replay_victim_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) return 1; 
    replay_victim_port = d;

    // Replay attacker
    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &replay_attacker_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) return 1; 
    addr_pton(line, &replay_attacker_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) return 1; 
    replay_attacker_port = d;


	return 0;
}
