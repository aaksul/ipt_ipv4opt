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
    {"136", IPOPT_SATID},
    {"137", IPOPT_SSRR}
};

//Map the type number to the corresponding mask
static const struct numtomask numtomask[] = {
    {IPOPT_EOL, MASK_IP4OPT_EOL},
    {IPOPT_NOP, MASK_IP4OPT_NOP},
    {IPOPT_RR, MASK_IP4OPT_RR},
    {IPOPT_RA, MASK_IP4OPT_RA},
    {IPOPT_TS, MASK_IP4OPT_TS},
    {IPOPT_SEC, MASK_IP4OPT_SEC},
    {IPOPT_LSRR, MASK_IP4OPT_LSRR},
    {IPOPT_SATID, MASK_IP4OPT_SATID},
    {IPOPT_SSRR, MASK_IP4OPT_SSRR}
};


//Convert the cmd representation of the options to the corresponding type number
static u_int8_t gettypenum(const char* name){
    for(int i = 0; i < sizeof(ipopts)/sizeof(ipopts[0]); i++){
        if(strcmp(ipopts[i].name, name) == 0){
            return ipopts[i].typenum;
        }
    }

    return 0;
}

//Convert the type number to the corresponding mask
static u_int16_t getmask(u_int8_t typenum){
    for(int i = 0; i < sizeof(numtomask)/sizeof(numtomask[0]); i++){
        if(numtomask[i].typenum == typenum){
            return numtomask[i].mask;
        }
    }
    return 0;
}

//parse cmd options
static u_int16_t parseopt(const char* opttype){
    u_int16_t mask = 0;
    char* buffer = xtables_strdup(opttype);
    char* token = strtok(buffer, ",");
    if (token == NULL){
        xtables_error(PARAMETER_PROBLEM, "No option specified or options in wrong format");
    }
    for(; token != NULL; token = strtok(NULL, ",")){
        u_int8_t typenum = gettypenum(token);
        if(typenum == 0){
            //xtables_error(PARAMETER_PROBLEM, "Invalid option specified");
        }
        mask |= getmask(typenum);
    }
    
    
    
    return mask;
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
            info->ipv4optmask = parseopt(cb->arg);
            info->invert = (cb->invert) ? 1 : 0;
            printf("mask: %d\n", info->ipv4optmask);
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
    if(info->ipv4optmask){
        printf("--opttype ");
        for(int i = 0; i < sizeof(numtomask)/sizeof(numtomask[0]); i++){
            if(info->ipv4optmask & numtomask[i].mask){
                printf("%s,", ipopts[i].name);
            }
        }
    }
    if(info->soft){
        printf("--soft\n");
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