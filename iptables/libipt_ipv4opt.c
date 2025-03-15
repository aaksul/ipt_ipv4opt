#include<xtables.h>
#include"../kernel/ipv4opt_info.h"
#include<netinet/ip.h>
#include<stdio.h>
#include<string.h>

enum {
    XTTYPE_IPV4OPT = 0,
    XTTYPE_SOFT,
};

struct ipopt {
    const char* name;
    uint8_t typenum;
};

struct numtomask{
    uint8_t typenum;
    uint16_t mask;
};


//Add the cmd representation of the options, and map it to the corresponding type number
static const struct ipopt ipopts[] = {
    {"0", IPOPT_EOL},
    {"1", IPOPT_NOP},
    {"7", IPOPT_RR},
    {"148", IPOPT_RA},
    {"68", IPOPT_TS},
    {"130", IPOPT_SEC},
    {"131", IPOPT_LSRR},
    {"137", IPOPT_SSRR}
};

const enum { NON_DEFINED_OPT = 0x0100 };

//Convert the cmd representation of the options to the corresponding type number
static u_int16_t gettypenum(const char* name){
    for(int i = 0; i < sizeof(ipopts)/sizeof(ipopts[0]); i++){
        if(strcmp(ipopts[i].name, name) == 0){
            return ipopts[i].typenum;
        }
    }
    return NON_DEFINED_OPT;
}

//parse cmd options
static __u8 get_type_list(__u8* type_list, const char* opttype){
    char* buffer = xtables_strdup(opttype);
    char* token = strtok(buffer, ",");
    
    if (token == NULL){
        xtables_error(PARAMETER_PROBLEM, "No option specified or options in wrong format");
    }

    __u8 num_ip4opt = 0;
    for(; token != NULL; token = strtok(NULL, ",")){
        u_int16_t typenum = gettypenum(token);
        if(typenum == NON_DEFINED_OPT){
            xtables_error(PARAMETER_PROBLEM, "Invalid option specified");
        }
        type_list[num_ip4opt] = (__u8) typenum;
        num_ip4opt++;
    }
    
    return num_ip4opt;
}

static void ipv4opt_help(void)
{
    printf(
        "ipv4opt match options:\n"
        "--opttype opt1,opt2,...    Match the specified IPv4 options\n"
        "--soft                     Match the soft option\n"
    );
}

static void ipv4opt_parse(struct xt_option_call* cb)
{
    struct info_ipv4opt *info = cb->data;

    xtables_option_parse(cb);

    switch(cb->entry->id){
        case XTTYPE_IPV4OPT:
            info->num_ip4opt = get_type_list(info->type_list, cb->arg);
            info->invert = (cb->invert) ? 1 : 0;
            break;
        case XTTYPE_SOFT:
            info->soft = 1;
            break;
    }  
}
static const struct xt_option_entry ipv4opts[] = {
    {
        .name = "opttype",
        .id = XTTYPE_IPV4OPT,
        .type = XTTYPE_STRING,
        .flags = XTOPT_MAND | XTOPT_INVERT},
    {
        .name = "soft",
        .id = XTTYPE_SOFT,
        .type = XTTYPE_NONE},
        XTOPT_TABLEEND,
};

static void ipv4opt_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
    const struct info_ipv4opt *info = (const struct info_ipv4opt *)match->data;
    printf("ipv4opt match options:");
    if(info->invert){
        printf(" ! ");
    }
    if(info->num_ip4opt > 0){
        printf(" --opttype ");
        for(int i = 0; i < info->num_ip4opt; i++){
            printf("%d,", info->type_list[i]);
        }
    }
    if(info->soft){
        printf(" --soft");
    }
}

static struct xtables_match ipv4opt_mt_reg = {
    .name = "ipv4opt",
    .version = XTABLES_VERSION,
    .family = NFPROTO_IPV4,
    .size = XT_ALIGN(sizeof(struct info_ipv4opt)),
    .userspacesize = XT_ALIGN(sizeof(struct info_ipv4opt)),
    .help = ipv4opt_help,
    .x6_parse = ipv4opt_parse,
    .print = ipv4opt_print,
    .x6_options = ipv4opts,
};


void _init(void)
{
    xtables_register_match(&ipv4opt_mt_reg);
}