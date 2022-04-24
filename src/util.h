#ifndef _UTIL_H_
#define _UTIL_H_

#include "common.h"

void send_packet(char *, eth_t *, int);

void display_pcap_header(struct pcap_file_header * );
void display_packet_header(struct my_pkthdr *);

int read_pcap_header(int, struct pcap_file_header *);
int read_packet_header(int, struct my_pkthdr * );
int read_packet(int, unsigned char*, int); 
void parse_packet(unsigned char*);

int replace_ip(unsigned char*, struct addr *, struct addr *, direction_t);
int replace_eth(unsigned char*, struct addr *, struct addr *, direction_t);
int replace_port(unsigned char*, u_int16_t, u_int16_t, direction_t direction);

void do_replacement(unsigned char*, uint32_t ack);

int parse_config(int);

uint32_t get_ack(const unsigned char*, int); 

#endif
