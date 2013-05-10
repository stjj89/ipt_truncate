/* Shared library add-on to iptables to add customized TRUNCATE support.
 *
 * Written by Samuel Tan
 * Adopted from libipt_REJECT.c by: 
 *  (C) 2000 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ipt_TRUNCATE.h>
#include <linux/version.h>


static void TRUNCATE_help(void)
{
    printf(
"TRUNCATE target options:\n"
"--at-byte NUM              Truncate bytes after the NUM-th byte,\n"
"                           counting from the end of the TCP/UDP header\n"
"                           (or end of IP header for non-TCP/UDP protocol)\n"
"--drop-tcp-opts            Drop optional TCP options\n");


    printf("(*) See man page or read the INCOMPATIBILITES file for compatibility issues.\n");
}

static const struct option TRUNCATE_opts[] = {
    { "at-byte", 1, NULL, '1' },
    { "drop-tcp-opts", 0, NULL, '2' },
    { .name = NULL }
};

static void TRUNCATE_init(struct xt_entry_target *t)
{
    struct ipt_truncate_info *truncate = (struct ipt_truncate_info *)t->data;

    /* default */
    truncate->drop_tcp_opts = 1; /* false, i.e. keep TCP options by default */
    truncate->at_byte = 10;
}

// WORK IN PROGRESS
static int TRUNCATE_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
    struct ipt_truncate_info *truncate = (struct ipt_truncate_info *)(*target)->data;
    unsigned int val;
    
    switch(c) {
    case '1':
        if (!xtables_strtoui(optarg, NULL, &val, 0, UINT32_MAX))
            xtables_error(PARAMETER_PROBLEM,
                   "cannot parse --truncate-size `%s'", optarg);
        if (val < 0)
            xtables_error(PARAMETER_PROBLEM,
                   "Argument passed to --at_byte cannot be negative");

        truncate->at_byte = val;
        
    case '2':
        truncate->drop_tcp_opts = 1; /* true, i.e. drop TCP options */
        
        
    default:
        /* Fall through */
        break;
    }
    
    return 0;
}

static void TRUNCATE_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
    const struct ipt_truncate_info *truncate
        = (const struct ipt_truncate_info *)target->data;
    
    printf("at-byte %d ", truncate->at_byte);
    if (truncate->drop_tcp_opts)
        printf("drop-tcp-opts ");
}

static void TRUNCATE_save(const void *ip, const struct xt_entry_target *target)
{
    const struct ipt_truncate_info *truncate
        = (const struct ipt_truncate_info *)target->data;
    

    printf("--at-byte %d ", truncate->at_byte);
    if (truncate->drop_tcp_opts)
        printf("--drop-tcp-opts ");
}

static struct xtables_target truncate_tg_reg = {
    .name               = "TRUNCATE",
    .version            = XTABLES_VERSION,
    .family             = NFPROTO_IPV4,
    .size               = XT_ALIGN(sizeof(struct ipt_truncate_info)),
    .userspacesize      = XT_ALIGN(sizeof(struct ipt_truncate_info)),
    .help               = TRUNCATE_help,
    .init               = TRUNCATE_init,
    .parse              = TRUNCATE_parse,
    .print              = TRUNCATE_print,
    .save               = TRUNCATE_save,
};

void _init(void)
{
    xtables_register_target(&truncate_tg_reg);
}
