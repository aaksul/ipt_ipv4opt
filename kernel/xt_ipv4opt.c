#include <linux/netfilter/x_tables.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include "ipv4opt_info.h"
#include <linux/ip.h> // Include the header file for IP header
#include "ipv4opt_info.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alperen Aksu");
MODULE_DESCRIPTION("A simple Linux kernel module.");
MODULE_VERSION("1.0");

struct ip_opt_tlv
{
    uint8_t type;
    uint8_t length;
    // if variable length, then data follows
};

struct numtomask
{
    uint8_t typenum;
    uint16_t mask;
};

static struct ip_opt_tlv *get_next_option(const struct ip_opt_tlv *ipopt_tlv)
{

    // two case in option layout, 1. type 2. type, length and data
    if (ipopt_tlv->type == IPOPT_EOL || ipopt_tlv->type == IPOPT_NOP)
    {
        return (struct ip_opt_tlv *)((char *)ipopt_tlv + sizeof(uint8_t));
    }

    return (struct ip_opt_tlv *)((char *)ipopt_tlv + ipopt_tlv->length);
}

static bool maybe_invert(const __u8 invert, bool result)
{
    return invert ? !result : result;
}

static bool check_ipv4_options_exist(struct ip_opt_tlv *opt_tlv, struct ip_opt_tlv *end_opt_tlv, struct ip_opt_tlv* limit_ip_header, struct info_ipv4opt *info)
{
    int num_of_matched_ipv4opts = 0;
    int num_of_ip4opt = 0;
    while (opt_tlv != end_opt_tlv && num_of_ip4opt != MAX_NUM_IP4OPT)
    {
        if(opt_tlv == end_opt_tlv){
            return maybe_invert(info->invert, NF_DROP);
        }
        num_of_ip4opt++;    
        // check if the option type is in the list
        for(int i=0; i< info->num_ip4opt; i++){
            if ((opt_tlv->type) == info->type_list[i])
            {
                num_of_matched_ipv4opts++;
                printk(KERN_INFO "Soft: Option type: %d\n", opt_tlv->type);
                printk(KERN_INFO "Soft: Option length: %d\n", opt_tlv->length);
                break;
            }
        }
        opt_tlv = get_next_option(opt_tlv);
    }

    if(num_of_matched_ipv4opts == info->num_ip4opt){
        return maybe_invert(info->invert, NF_ACCEPT);
    }    
    return maybe_invert(info->invert, NF_DROP);

}

static bool check_ipv4_options_sequence(struct ip_opt_tlv *opt_tlv, struct ip_opt_tlv *end_opt_tlv, struct info_ipv4opt *info)
{

    for (int i = 0; i < info->num_ip4opt; i++)
    {
        if(opt_tlv == end_opt_tlv){
            return maybe_invert(info->invert, NF_DROP);
        }

        if ((opt_tlv->type) != info->type_list[i])
        {
            return maybe_invert(info->invert, NF_DROP);
        }
        printk(KERN_INFO "Option type: %d\n", opt_tlv->type);
        printk(KERN_INFO "Option length: %d\n", opt_tlv->length);
        opt_tlv = get_next_option(opt_tlv);
    }

    return maybe_invert(info->invert, NF_ACCEPT);
}

static bool ipv4opt_mt(const struct sk_buff *skb, struct xt_action_param *params)
{
    // Dump source and destination IP addresses
    struct iphdr *ip_header = ip_hdr(skb);
    // start of IP options
    struct ip_opt_tlv *opt_tlv = (struct ip_opt_tlv *)((char *)ip_header + sizeof(struct iphdr));
    // end of IP options
    struct ip_opt_tlv *end_opt_tlv = (struct ip_opt_tlv *)((char *)ip_header + (ip_header->ihl * 4));

    struct ip_opt_tlv *limit_ip_header = (struct ip_opt_tlv *)((char *)ip_header + MAX_IPOPTLEN);

    struct info_ipv4opt *info = (struct info_ipv4opt *)params->matchinfo;

    // [TODO] Check if the part of IP options of the packet is valid by validation function

    if(opt_tlv == end_opt_tlv){
        return maybe_invert(info->invert, NF_DROP);
    }

    if(!info->soft){
        return check_ipv4_options_sequence(opt_tlv, end_opt_tlv, info);    
    } else {
        return check_ipv4_options_exist(opt_tlv, end_opt_tlv, limit_ip_header, info);
    }

    return maybe_invert(info->invert, NF_ACCEPT);
}

struct xt_match ipv4opt_mt_reg __read_mostly = {
    .name = "ipv4opt",
    .revision = 0,
    .family = NFPROTO_IPV4,
    .match = ipv4opt_mt,
    .matchsize = sizeof(struct info_ipv4opt),
    .me = THIS_MODULE,
};

static __init int xtables_ipv4opt_init(void)
{
    printk(KERN_INFO "xtables_ipv4opt_init\n");
    xt_register_match(&ipv4opt_mt_reg);
    return 0;
}

static __exit void xtables_ipv4opt_exit(void)
{
    printk(KERN_INFO "xtables_ipv4opt_exit\n");
    xt_unregister_match(&ipv4opt_mt_reg);
}

module_init(xtables_ipv4opt_init);
module_exit(xtables_ipv4opt_exit);
