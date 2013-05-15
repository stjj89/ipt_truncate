/*
 * This is a target module which is used to truncate packets.
 */

/* Written by Samuel Tan
 * Adopted from ipt_TRUNCATE by:
 *  (C) 1999-2001 Paul `Rusty' Russell
 *  (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/checksum.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_TRUNCATE.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#include <linux/netfilter_bridge.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samuel Tan <samueltan@gmail.com>");
MODULE_DESCRIPTION("Xtables: packet \"truncation\" target for IPv4");


static unsigned int truncate_TCP(struct sk_buff *skb,       /* skb to truncate */
                                int hook,                   /* hook number */
                                int num_bytes,              /* # bytes to truncate */
                                int drop_tcp_opts)          /* boolean flag to drop TCP options */
{
    printk("truncate_TCP: Entering...\n");

    struct iphdr *iph;
    struct tcphdr _tcph, *tcph;
    unsigned char* tcp_opts;        /* pointer to TCP options */
    unsigned char* curr_opt;
    unsigned char* last_opt;
    int opt_len;
    int bytes_left;
    int new_len;                    /* new total packet length in bytes */
    int err;
    unsigned char last_char;

    iph = ip_hdr(skb);

    tcph = skb_header_pointer(skb, ip_hdrlen(skb),
                 sizeof(_tcph), &_tcph);
    if (tcph == NULL) {
        printk("ipt_TRUNCATE: TCP header not found\n");
        return NF_DROP;   
    }

    
    /* Drop TCP options, truncate data only */
    // TODO: Fix this (need to keep num_bytes AFTER tcp opts)
    if (drop_tcp_opts)
    {
        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +           /* IP header length */
                    sizeof(struct tcphdr) +     /* TCP header length w/o opts (20) */
                    num_bytes;                  /* new data length */

        tcph->doff = sizeof(struct tcphdr) / 4;
    }
    
    /* More optional TCP opts than bytes we want to keep, so 
     * try to keep as many fully aligned options as we can
     */
    else if ( ((tcph->doff << 2) - sizeof(struct tcphdr)) > num_bytes)
    {
        // Check options for handling alignment
        tcp_opts = (unsigned char *)tcph + sizeof(struct tcphdr);

        curr_opt = tcp_opts;
        last_opt = curr_opt;
        bytes_left = num_bytes;

        // After this loop, last_opt will point to
        // the end of the last option we keep
        while (bytes_left > 0)
        {
            // OPT = End of options list
            if ((*curr_opt ^ 0x00) == 0) {
                printk("truncate_TCP: option 0 (END) detected\n");
                break;
            }
            // OPT = NOP
            else if ((*curr_opt ^ 0x01) == 0)
            {
                printk("truncate_TCP: option 1 (NOP) detected\n");
                curr_opt++;
                bytes_left--;
            }
            // OPT = Other option
            else if ( ((*curr_opt ^ 0x02) == 0) ||      /* Maximum segment size */
                        ((*curr_opt ^ 0x03) == 0) ||    /* Windows scale */
                        ((*curr_opt ^ 0x04) == 0) ||    /* Selective ACK ok */
                        ((*curr_opt ^ 0x08) == 0) )     /* Timestamp */
            {
                printk("truncate_TCP: other option (0x%x, len = 0x%x) detected\n", *curr_opt, *(curr_opt + 1));
                curr_opt++;
                bytes_left--;
                opt_len = (uint8_t) *curr_opt; // potential casting problem (CHECK ABOVE TOO)
                
                // Cannot keep this option
                if (bytes_left < (opt_len - 1)) {
                    printk("truncate_TCP: cannot keep last option (0x%x)\n", *(curr_opt - 1));
                    break;
                }
                // Proceed to next option
                else
                {
                    // Length field two octets of option-kind and option-length as
                    // well as the option-data octets, so minus one to account for
                    // option-kind octet we already passed
                    curr_opt += opt_len - 1;
                    last_opt = curr_opt;
                    bytes_left -= opt_len;
                }
            }

            // Unreocnigzed kind (should not happen)
            else
            {
                printk("truncate_TCP: Invalid TCP Option detected\n");
                return NF_DROP;
            }

        }

        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +           /* IP header length */
                    sizeof(struct tcphdr) +     /* TCP header length w/o options (20) */
                    (last_opt - tcp_opts);      /* Length of options kept */


        tcph->doff = (sizeof(struct tcphdr) + (last_opt - tcp_opts)) / 4;

    }

    /* Keep all TCP Options, truncating data after */
    else
    {
        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +            /* IP header length */
                    sizeof(struct tcphdr) +     /* TCP header length w/o opts (20) */
                    num_bytes;                  /* new data length */

    }

    last_char = *(skb->data + (skb->len - 1));

    // Paged data in SKB
    if (skb->data_len > 0)
    {
        err = pskb_trim(skb, new_len);
        if (err) {
            printk("truncate_UDP: ERROR pskb_trim failed!\n");
            return NF_DROP;
        }
    }

    // Linear data in SKB
    // TODO: Error check for skb_trim
    else
    {
        skb_trim(skb, new_len);
        // err = skb_trim(nskb, new_len);
        //if (err) {
        //    printk("truncate_UDP: ERROR skb_trim failed!\n");
        //    return NF_DROP;
        //}
    }

    // If this packet ends in a newline, truncated packet must too
    // TODO: THIS DOESN'T WORK, TCP PROTOCOL KEEPS GOING
    if (last_char == 0x0a)
        *(skb->data + (skb->len - 1)) = 0x0a;

    //printk("Last data character: 0x%x, skb->len = %d\n", *(skb->data + (skb->len - 1)), skb->len );

    /* Modify IP header and compute checksum */
    iph->tot_len   = htons(new_len);     
    ip_send_check(iph);

    int datalen = skb->len - (iph->ihl << 2);
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                      datalen, iph->protocol,
                      csum_partial((char *)tcph, datalen, 0));

    /* Recompute checksum for TCP header */
    // tcph->check = tcp_v4_check((tcph->doff << 2)/*sizeof(struct tcphdr)*/,
    //                   iph->saddr, iph->daddr,
    //                   csum_partial(tcph,
    //                        (tcph->doff << 2), 0));
    //tcph->check = 0;
    // tcph->check = tcp_v4_check(skb->len, iph->saddr, iph->daddr, 
    //                             csum_partial(tcph,
    //                             (tcph->doff << 2), 
    //                             skb->csum));

    printk("truncate_TCP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int truncate_UDP(struct sk_buff *skb,       /* skb to truncate */
                                int hook,                   /* hook number */
                                int num_bytes)              /* # bytes to truncate */
{
    printk("truncate_UDP: Entering...\n");
    struct iphdr *iph;
    struct udphdr _udph, *udph;
    unsigned int new_len;                    /* new total packet length in bytes */
    int err;

    iph = ip_hdr(skb);

    udph = skb_header_pointer(skb, ip_hdrlen(skb),
                 sizeof(_udph), &_udph);
    if (udph == NULL) {
        printk("ipt_TRUNCATE: UDP header not found\n");
        return NF_DROP;   
    }

    
    // Less data after iphdr and udphdr than we want to keep 
    if ( (skb->len - (iph->ihl * 4) - sizeof(struct udphdr)) < num_bytes )
        new_len = skb->len;
    
    // More data than we want to keep, so truncate from after
    // udp header
    else
        new_len = (iph->ihl * 4) + sizeof(struct udphdr) + num_bytes;


    // Paged data in SKB
    if (skb->data_len > 0)
    {
        err = pskb_trim(skb, new_len);
        if (err) {
            printk("truncate_UDP: ERROR pskb_trim failed!\n");
            return NF_DROP;
        }
    }

    // Linear data in SKB
    // TODO: Error check for skb_trim 
    else
    {
        skb_trim(skb, new_len);
        // err = skb_trim(nskb, new_len);
        //if (err) {
        //    printk("truncate_UDP: ERROR skb_trim failed!\n");
        //    return NF_DROP;
        //}
    }

    // Modify IP header 
    iph->tot_len   = htons(new_len);     
    ip_send_check(iph);

    // Modify UDP header
    udph->check = 0; // UDP Checksum optional for IPv4
    udph->len = htons(new_len - (iph->ihl * 4));

    printk("truncate_UDP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int truncate_other(struct sk_buff *skb,         /* skb to truncate */
                                    int hook,                   /* hook number */
                                    int num_bytes)              /* # bytes to truncate */
{
    printk("truncate_other: Entering...\n");
    struct iphdr *iph;
    unsigned int new_len;                    /* new total packet length in bytes */
    int err;

    iph = ip_hdr(skb);

    // Less data after iphdr than we want to keep 
    if ( (skb->len - (iph->ihl * 4)) < num_bytes )
        new_len = skb->len;
    
    // More data than we want to keep, so truncate from after
    // ip header
    else
        new_len = (iph->ihl * 4) + num_bytes;


    // Paged data in SKB
    if (skb->data_len > 0)
    {
        err = pskb_trim(skb, new_len);
        if (err) {
            printk("truncate_other: ERROR pskb_trim failed!\n");
            return NF_DROP;
        }

    }

    // Linear data in SKB
    // TODO: Error check for skb_trim
    else
    {
        skb_trim(skb, new_len);
        // err = skb_trim(nskb, new_len);
        //if (err) {
        //    printk("truncate_other: ERROR skb_trim failed!\n");
        //    return NF_DROP;
        //}
    }



    // Modify IP header and compute checksum 
    printk("truncate_other: skb->len = %d\n", skb->len);
    printk("truncate_other: niph->tot_len before reassignment = %d\n", iph->tot_len);
    iph->tot_len   = htons(new_len);     
    ip_send_check(iph);
    printk("truncate_other: iph->tot_len after assignment = %d\n", iph->tot_len);
    printk("truncate_other: iph_check = %08x\n", ip_fast_csum((unsigned char *)iph, iph->ihl));
    
 
    printk("truncate_other: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int
truncate_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
    struct iphdr *iph = ip_hdr(skb);
    printk("truncate_tg: Entering with iph->protocol = %x\n", iph->protocol);
    const struct ipt_truncate_info *truncate = par->targinfo;

    if (iph->protocol == IPPROTO_TCP)
        return truncate_TCP(skb, par->hooknum, truncate->at_byte, truncate->drop_tcp_opts);
    else if (iph->protocol == IPPROTO_UDP)
        return truncate_UDP(skb, par->hooknum, truncate->at_byte);
    else
        return truncate_other(skb, par->hooknum, truncate->at_byte);    
}

/* Kernel-side sanity check on input passed by iptables */
static bool truncate_tg_check(const struct xt_tgchk_param *par)
{
    const struct ipt_truncate_info *truncate_info = par->targinfo;
    //const struct ipt_entry *e = par->entryinfo;

    if (truncate_info->at_byte < 0) {
        printk("ipt_TRUNCATE: at-byte option must be passed!\n");
        return false;
    }
    return true;
}

static struct xt_target truncate_tg_reg __read_mostly = {
    .name       = "TRUNCATE",
    .family     = NFPROTO_IPV4,
    .target     = truncate_tg,
    .targetsize = sizeof(struct ipt_truncate_info),
    .table      = "filter",
    .hooks      =   (1 << NF_INET_FORWARD) |
                    (1 << NF_INET_LOCAL_OUT),
    .checkentry = truncate_tg_check,
    .me     = THIS_MODULE,
};

static int __init truncate_tg_init(void)
{
    return xt_register_target(&truncate_tg_reg);
}

static void __exit truncate_tg_exit(void)
{
    xt_unregister_target(&truncate_tg_reg);
}

module_init(truncate_tg_init);
module_exit(truncate_tg_exit);
