struct timev {
    unsigned int tv_sec;
    unsigned int tv_usec;
};
/* data prefixing each packet */
struct my_pkthdr {
    struct timev ts;
    int caplen;
    int len;
};