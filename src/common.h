#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcap.h> // libpcap
#include <dnet.h> // libdnet

#include "pcap_magic.h"
#include "my_pkthdr.h"

#define CONFIG_FILE_MAX_LINE 256
typedef enum {
    SRC,
    DST
} direction_t;

#define DELAY_TIMING_STR "delay"
#define REACTIVE_TIMING_STR "reactive"
#define EXACT_TIMING_STR "exact"
#define CONTINUOUS_TIMING_STR "continuous"

#define CONTINUOUS_TIMING 0
#define DELAY_TIMING 1
#define REACTIVE_TIMING 2
#define EXACT_TIMING 3

#define DEFAULT_RECV_TIMEOUT 1000
#define DEFAULT_DELAY_NS 500000000L

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
extern char IFACE_NAME[CONFIG_FILE_MAX_LINE];
extern char TIMING[CONFIG_FILE_MAX_LINE];
extern char ERRBUF[PCAP_ERRBUF_SIZE];

extern eth_t * ethfd;
extern pcap_t * pcap_dev_fd;


#endif
