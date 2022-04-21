#include "common.h"
#include "util.h"
//#include <dnet/eth.h>
//#include <dnet/ip.h>


uint32_t get_ack(char * packet, int len) {
	// To update the new global ack 
	struct tcp_hdr * tcp_header; 
	uint32_t ack;


	tcp_header = (struct tcp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN); 
	ack = ntohl(tcp_header->th_seq) + len;
	return ack;
}

uint32_t get_ack_handshake(char * packet);

uint32_t get_ack_discon(char * packet);

void send_packet(char * packet, eth_t * ethfd, int len) 
{ 
    eth_send(ethfd,packet,len);
}


int replace_port(char * packet, u_int16_t orig, u_int16_t repl, direction_t direction) 
{
    struct tcp_hdr *tcp_header;
    tcp_header = (struct tcp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);
    if(direction == SRC) {
        if(ntohs(tcp_header->th_sport) == orig)
            tcp_header->th_sport = htons(repl);
        return 1;
    } else { 
        if(ntohs(tcp_header->th_dport) == orig)
            tcp_header->th_dport = htons(repl);
        return 1;
    }
    return 0;
}

int replace_ip(char * packet, struct addr * orig, struct addr * repl, direction_t direction) 
{
        // direction: 
        // if SRC, replace src ip
        // if DST, replace dst ip
        struct ip_hdr *ip_header;
        
		struct addr ad; 
        ip_addr_t * ip_addr; // pointer to location to write to 
        // Get the IP header...
        ip_header = (struct ip_hdr *) (packet + ETH_HDR_LEN);
        // Pack address into addr struct...
        if (direction == SRC)
            ip_addr = &(ip_header->ip_src);
        else
            ip_addr = &(ip_header->ip_dst);

        // read the address from packet into addr struct
        addr_pack(&ad,ADDR_TYPE_IP,IP_ADDR_BITS,ip_addr,IP_ADDR_LEN);

        // compare address from packet to the specified original address to replace
        if(addr_cmp(&ad, orig) == 0) {
            // if they match, replace it 
            memcpy( ip_addr, &repl->addr_ip, IP_ADDR_LEN);
            // ip_checksum((void *)ip_header, ntohs(ip_header->ip_len));
            return 1;
        }
        return 0;
}


int replace_eth(char * packet, struct addr * orig, struct addr * repl, direction_t direction) 
{
        // direction: 
        // if SRC, replace src ip
        // if DST, replace dst ip
        struct eth_hdr *eth_header;
        struct addr ad; 
        eth_addr_t * eth_addr; // pointer to location to write to 
        // Get the IP header...
        eth_header = (struct eth_hdr *) (packet);
        // Pack address into addr struct...
        if (direction == SRC)
            eth_addr = &(eth_header->eth_src);
        else
            eth_addr = &(eth_header->eth_dst);

        addr_pack(&ad,ADDR_TYPE_ETH,ETH_ADDR_BITS,eth_addr,ETH_ADDR_LEN);
        if(addr_cmp(&ad, orig) == 0) {
            memcpy( eth_addr, &repl->addr_eth, ETH_ADDR_LEN);
            return 1;
        }
        return 0;
}


void parse_packet(char * packet) 
{ 
    struct addr ad;
    struct eth_hdr *eth_header;
    struct ip_hdr *ip_header;
    struct tcp_hdr *tcp_header;
    struct udp_hdr *udp_header;
    struct icmp_hdr *icmp_header;
    struct arp_hdr *arp_header;

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
					printf("\t\t\tdata offset = %hhd\n", tcp_header->th_off);
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

	if ( (fp = fdopen(fd, "r")) == NULL )
		return 1;

    if (fscanf(fp, "%s\n", PCAP_FILENAME) != 1 ) 
        return 1;
    
    // Original Victim
    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &orig_victim_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &orig_victim_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) 
        return 1; 
    orig_victim_port = d;

    // Original Attacker
    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &orig_attacker_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &orig_attacker_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) 
        return 1; 
    orig_attacker_port = d;

    // Replay victim
    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &replay_victim_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &replay_victim_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) 
        return 1; 
    replay_victim_port = d;

    // Replay attacker
    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &replay_attacker_ip_addr);

    if (fscanf(fp, "%s\n", line) != 1) 
        return 1; 
    addr_pton(line, &replay_attacker_eth_addr);

    if (fscanf(fp, "%d\n", &d) != 1) 
        return 1; 
    replay_attacker_port = d;

    // Interface
    if (fscanf(fp, "%s\n", IFACE_NAME) != 1) 
        return 1; 
    // Timing
    if (fscanf(fp, "%s\n", TIMING) != 1)
        return 1; 

    return 0;
}
