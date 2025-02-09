#ifndef IPV4OPT_INFO_H
#define IPV4OPT_INFO_H

#include <linux/types.h>

struct info_ipv4opt{
    __u16 ipv4optmask;
    __u8 soft;
    __u8 invert;
};


#define MASK_IP4OPT_EOL     0x0001
#define MASK_IP4OPT_NOP     0x0002
#define MASK_IP4OPT_RR      0x0004
#define MASK_IP4OPT_RA      0x0008 
#define MASK_IP4OPT_TS      0x0010
#define MASK_IP4OPT_SEC     0x0020
#define MASK_IP4OPT_LSRR    0x0040
#define MASK_IP4OPT_SATID   0x0080
#define MASK_IP4OPT_SSRR    0x0100


#endif