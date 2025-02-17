#include <linux/netfilter/x_tables.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include "ipv4opt_info.h"
#include <linux/ip.h> // Include the header file for IP header
#include "ipv4opt_info.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple Linux kernel module.");
MODULE_VERSION("1.0");

struct ip_opt_tlv {
    uint8_t type;
    uint8_t length;
    uint8_t *data;
};

struct ip_opt_list {
    struct ip_opt_tlv *opt;
    struct ip_opt_list *next;
};


bool ipv4opt_mt(const struct sk_buff *skb, struct xt_action_param *params)
{
    // Dump source and destination IP addresses
    struct iphdr *ip_header = ip_hdr(skb);


    struct ip_opt_tlv *opt_tlv = (struct ip_opt_tlv*) ((char*) ip_header + sizeof(struct iphdr));

    //Received packets' first IP option type 
    printk(KERN_INFO "ip type: %d\n", opt_tlv->type);

    //params->hotdrop = 1;

    return NF_DROP;
}

const struct xt_match ipv4opt_mt_reg __read_mostly = {
    .name		= "ipv4opt",
    .revision	= 0,
    .family		= NFPROTO_IPV4,
    .match		= ipv4opt_mt,
    .matchsize	= sizeof(struct info_ipv4opt),
    .me		= THIS_MODULE,
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


