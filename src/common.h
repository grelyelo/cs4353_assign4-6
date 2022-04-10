#ifndef _COMMON_H_
#define _COMMON_H_

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
typedef enum {
    SRC,
    DST
} direction_t;


extern struct addr orig_victim_ip_addr;
extern struct addr orig_victim_eth_addr;
extern int orig_victim_port; 

extern struct addr orig_attacker_ip_addr;
extern struct addr orig_attacker_eth_addr;
extern int orig_attacker_port;

extern struct addr replay_victim_ip_addr;
extern struct addr replay_victim_eth_addr;
extern int replay_victim_port; 

extern struct addr replay_attacker_ip_addr;
extern struct addr replay_attacker_eth_addr;
extern int replay_attacker_port;

extern char PCAP_FILENAME[CONFIG_FILE_MAX_LINE]; 

#endif