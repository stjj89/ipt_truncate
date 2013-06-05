/*
 * Shared library add-on to iptables to add customized TRUNCATE
 * target module support.
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

#define AT_BYTE_SET  (1 << 1)

static void TRUNCATE_help(void)
{
    printf(
"TRUNCATE target options:\n"
"--at-byte NUM              Truncate bytes after the NUM-th byte,\n"
"                           counting from the end of the TCP/UDP header,\n"
"                           or end of IP header for non-TCP/UDP protocol.\n"
"                           (Note: for TCP, count starts after first 20 bytes of header)\n"
"--drop-tcp-opts            Drop optional TCP options before truncation\n");


    printf("(*) See man page or read the INCOMPATIBILITES file for compatibility issues.\n");
}

static const struct option TRUNCATE_opts[] = {
    { "at-byte",        1, NULL, '1' },
    { "drop-tcp-opts",  0, NULL, '2' },
    { .name = NULL }
};

static void TRUNCATE_init(struct xt_entry_target *t)
{
    struct ipt_truncate_info *truncate = (struct ipt_truncate_info *)t->data;

    truncate->drop_tcp_opts = 0; /* false, i.e. try to keep TCP options by default */

    // If this value is not set by a user-passed argument, truncate_tg_check()
    // will not allow the rule to be added, so user is forced to provide 
    // at-byte argument. This is a hack since I don't know how else to force
    // user to pass at-byte argument and don't want to use a default value
    truncate->at_byte = -1;      
    
}

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
        *flags |= AT_BYTE_SET;
        return 1;
        
    case '2':
        truncate->drop_tcp_opts = 1; /* true, i.e. drop TCP options */
        return 1;
        
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

static void TRUNCATE_check(unsigned int flags)
{
    if ( !(flags & AT_BYTE_SET) ) {
        xtables_error(PARAMETER_PROBLEM,
            "must set --at-byte option for TRUNCATE target module");
    }
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
    .extra_opts         = TRUNCATE_opts,
    .final_check        = TRUNCATE_check,
};

void _init(void)
{
    xtables_register_target(&truncate_tg_reg);
}
