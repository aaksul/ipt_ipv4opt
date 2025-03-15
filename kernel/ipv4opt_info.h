#ifndef IPV4OPT_INFO_H
#define IPV4OPT_INFO_H

#include <linux/types.h>

#define MAX_NUM_IP4OPT 40

struct info_ipv4opt{
    __u8 type_list[MAX_NUM_IP4OPT];
    __u8 num_ip4opt;
    __u8 soft;
    __u8 invert;
};

#endif