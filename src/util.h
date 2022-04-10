#ifndef _UTIL_H_
#define _UTIL_H_

#include "common.h"

void display_pcap_header(struct pcap_file_header * );
void display_packet_header(struct my_pkthdr *);

int read_pcap_header(int, struct pcap_file_header *);
int read_packet_header(int, struct my_pkthdr * );
int read_packet(int, char *, int); 
void parse_packet(char *);

int replace_ip(char *, struct addr *, struct addr *, direction_t);
int replace_eth(char *, struct addr *, struct addr *, direction_t);

int parse_config(int);

#endif