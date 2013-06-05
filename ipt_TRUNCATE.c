/*
 * Target module which is used to duplicate outgoing and
 * forwarded packets.
 */

/* Written by Samuel Tan
 * Adopted from ipt_REJECT by:
 *  (C) 1999-2001 Paul `Rusty' Russell
 *  (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
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


static unsigned int duplicate_TCP(struct sk_buff *skb,       /* skb to duplicate */
                                int hook,                   /* hook number */
                                int num_bytes,              /* # bytes to duplicate */
                                int drop_tcp_opts)          /* boolean flag to drop TCP options */
{
    //printk("duplicate_TCP: Entering...\n");
    struct iphdr *iph;
    struct tcphdr _tcph, *tcph;
    unsigned char* tcp_opts;        /* pointer to TCP options */
    unsigned char* curr_opt;
    unsigned char* last_opt;
    int opt_len;
    int bytes_left;
    int kept_opts_len;
    int new_len;                    /* new total packet length in bytes */
    int old_user_data_len;
    int datalen;

    iph = ip_hdr(skb);

    tcph = skb_header_pointer(skb, ip_hdrlen(skb),
                 sizeof(_tcph), &_tcph);
    if (tcph == NULL) {
        printk("ipt_TRUNCATE: TCP header not found\n");
        return NF_DROP;   
    }

    /* Drop TCP options, duplicate user data only */
    if (drop_tcp_opts)
    {
        // Calculate new total packet length (in bytes) after truncation
        old_user_data_len = skb->len - (iph->ihl << 2) - (tcph->doff << 2);
        if (num_bytes >= old_user_data_len) // User data less than number of bytes we want to keep, so keep it all
            new_len = (iph->ihl << 2) + sizeof(struct tcphdr) + old_user_data_len;
        else {
            new_len =   (iph->ihl << 2) +           /* IP header length */
                        sizeof(struct tcphdr) +     /* TCP header length w/o opts (20) */
                        num_bytes;                  /* # of user data bytes to keep */
        }
        
        /* Move up user data to overwrite optional TCP options */
        skb_copy_bits(skb,
                    (iph->ihl << 2) + (tcph->doff << 2),
                    skb->data + (iph->ihl << 2) + sizeof(struct tcphdr),
                    old_user_data_len);

        /* Truncate SKB */
        __pskb_trim(skb, new_len);

        // TCP header length modified, so adjust metadata accordingly
        tcph->doff = sizeof(struct tcphdr) >> 2;
    }
    
    /* Keep optional TCP options, so keep num_bytes starting from
     * pointer to first optional TCP option.
     */
    else
    {
        /* Number of bytes we want to keep is greater than total length of 
         * optional TCP options and user data combined, so keep them
         * all and send packet on its way */
        if (num_bytes >= (skb->len - (iph->ihl << 2) - sizeof(struct tcphdr)))
        {
            //printk("duplicate_TCP: Less data than num_bytes = %d, so no truncatation performed\n", num_bytes);
            return XT_CONTINUE;
        }

        /* Length of optional TCP opts greater than number of bytes we want 
         * to keep, so try to keep as many fully aligned options as we can
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
                    //printk("duplicate_TCP: option 0 (END) detected\n");
                    break;
                }
                // OPT = NOP
                else if ((*curr_opt ^ 0x01) == 0)
                {
                    //printk("duplicate_TCP: option 1 (NOP) detected\n");
                    curr_opt++;
                    last_opt = curr_opt;
                    bytes_left--;
                }
                // OPT = Other option
                else if ( ((*curr_opt ^ 0x02) == 0) ||      /* Maximum segment size */
                            ((*curr_opt ^ 0x03) == 0) ||    /* Windows scale */
                            ((*curr_opt ^ 0x04) == 0) ||    /* Selective ACK ok */
                            ((*curr_opt ^ 0x08) == 0) )     /* Timestamp */
                {
                    //printk("duplicate_TCP: other option (0x%x, len = 0x%x) detected\n", *curr_opt, *(curr_opt + 1));
                    curr_opt++;
                    bytes_left--;
                    opt_len = (uint8_t) *curr_opt; // potential casting problem (CHECK ABOVE TOO)
                    
                    // Cannot keep this option
                    if (bytes_left < (opt_len - 1)) {
                        //printk("duplicate_TCP: cannot keep last option (0x%x)\n", *(curr_opt - 1));
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
                    //printk("duplicate_TCP: Invalid TCP Option detected\n");
                    return NF_DROP;
                }
            }

            kept_opts_len = (last_opt - tcp_opts);

            // Kept options must be aligned on 32-bit (4-byte) boundary,
            // so drop unaligned bytes we kept from the loop above
            if (kept_opts_len % 4)
                kept_opts_len = kept_opts_len - (kept_opts_len % 4);

            // Calculate new total packet length (in bytes) after truncation
            new_len =   (iph->ihl << 2) +           /* IP header length */
                        sizeof(struct tcphdr) +     /* TCP header length w/o options (20) */
                        kept_opts_len;              /* Length of options kept */

            // TCP header length modified, so adjust metadata accordingly
            tcph->doff = (sizeof(struct tcphdr) + kept_opts_len) >> 2;
        }

        /* The number of bytes we want to keep exceeds the length of the
         * optional TCP options, but is less than the total length of 
         * optional TCP options and user data combined, so we duplicate user data only
         */
        else
        {
            // Calculate new total packet length (in bytes) after truncation
            new_len =   (iph->ihl << 2) +           /* IP header length */
                        sizeof(struct tcphdr) +     /* TCP header length w/o opts (20) */
                        num_bytes;                  /* new data length */
        }

        /* Truncate SKB */
        __pskb_trim(skb, new_len);
    }

    /* Modify IP header and compute checksum */
    iph->tot_len   = htons(new_len);     
    ip_send_check(iph);
    datalen = skb->len - (iph->ihl << 2);

    /* Recompute checksum for TCP header */
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                      datalen, iph->protocol,
                      csum_partial((char *)tcph, datalen, 0));
    
    // // OLD CHECKSUM: does not work
    // tcph->check = tcp_v4_check((tcph->doff << 2)/*sizeof(struct tcphdr)*/,
    //                   iph->saddr, iph->daddr,
    //                   csum_partial(tcph,
    //                        (tcph->doff << 2), 0));
    //tcph->check = 0;
    // tcph->check = tcp_v4_check(skb->len, iph->saddr, iph->daddr, 
    //                             csum_partial(tcph,
    //                             (tcph->doff << 2), 
    //                             skb->csum));

    // TODO:
    // If CHECKSUM_NONE is not set, TCP retransmission packets that
    // have ip_summed = CHECKSUM_PARTIAL will get bad checksum on
    // WireShark. Why?
    skb->ip_summed = CHECKSUM_NONE;
    //printk("skb->ip_summed = 0x%x\n", skb->ip_summed);
    //printk("duplicate_TCP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int duplicate_UDP(struct sk_buff *skb,       /* skb to duplicate */
                                int hook,                   /* hook number */
                                int num_bytes)              /* # bytes to duplicate */
{
    printk("duplicate_UDP: Entering...\n");
    struct iphdr *iph;
    struct udphdr _udph, *udph;
    unsigned int new_len;                    /* new total packet length in bytes */

    iph = ip_hdr(skb);

    udph = skb_header_pointer(skb, ip_hdrlen(skb),
                 sizeof(_udph), &_udph);
    if (udph == NULL) {
        printk("ipt_TRUNCATE: UDP header not found\n");
        return NF_DROP;   
    }

    /* Calculate new skb->len */
    // Less user data than we want to keep, so keep all and send packet on its way
    if ( (skb->len - (iph->ihl << 2) - sizeof(struct udphdr)) <= num_bytes ) {
        //printk("duplicate_UDP: Less data than num_bytes = %d, so no truncatation performed\n", num_bytes);
        return XT_CONTINUE;
    }
    // More data than we want to keep, so duplicate from after
    // udp header
    else
        new_len = (iph->ihl << 2) + sizeof(struct udphdr) + num_bytes;
    
    /* Truncate SKB */
    __pskb_trim(skb, new_len);

    /* Modify IP header and compute checksum */
    iph->tot_len   = htons(new_len);     
    ip_send_check(iph);

    /* Modify UDP header */
    udph->check = 0; // UDP Checksum optional for IPv4
    udph->len = htons(new_len - (iph->ihl << 2));

    printk("duplicate_UDP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int duplicate_other(struct sk_buff *skb,         /* skb to duplicate */
                                    int hook,                   /* hook number */
                                    int num_bytes)              /* # bytes to duplicate */
{
    //printk("duplicate_other: Entering...\n");
    struct iphdr *iph;
    unsigned int new_len;                    /* new total packet length in bytes */

    iph = ip_hdr(skb);

    /* Calculate new skb->len */
    // Less data after iphdr than we want to keep, so keep all and send packet on its way
    if ( (skb->len - (iph->ihl << 2)) < num_bytes ) {
        //printk("duplicate_other: Less data than num_bytes = %d, so no truncatation performed\n", num_bytes);
        return XT_CONTINUE;
    } 
    // More data than we want to keep, so duplicate from after
    // ip header
    else
        new_len = (iph->ihl << 2) + num_bytes;

    /* Truncate SKB */
    __pskb_trim(skb, new_len);

    /* Modify IP header and compute checksum */
    iph->tot_len   = htons(new_len);     
    ip_send_check(iph);
 
    //printk("duplicate_other: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int
duplicate_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
    struct iphdr *iph = ip_hdr(skb);
    //printk("duplicate_tg: Entering with iph->protocol = %x\n", iph->protocol);
    const struct ipt_duplicate_info *duplicate = par->targinfo;

    if (IPPROTO_TCP == iph->protocol)
        return duplicate_TCP(skb, par->hooknum, duplicate->at_byte, duplicate->drop_tcp_opts);
    else if (IPPROTO_UDP == iph->protocol)
        return duplicate_UDP(skb, par->hooknum, duplicate->at_byte);
    else
        return duplicate_other(skb, par->hooknum, duplicate->at_byte);    
}

static struct xt_target duplicate_tg_reg __read_mostly = {
    .name       = "DUPLICATE",
    .family     = NFPROTO_IPV4,
    .target     = duplicate_tg,
    .targetsize = sizeof(struct ipt_duplicate_info),
    .table      = "mangle",
    .hooks      =   (1 << NF_INET_PRE_ROUTING) |
                    (1 << NF_INET_FORWARD) |
                    (1 << NF_INET_LOCAL_OUT) |
                    (1 << NF_INET_POST_ROUTING),
    .me         = THIS_MODULE,
};

static int __init duplicate_tg_init(void)
{
    return xt_register_target(&duplicate_tg_reg);
}

static void __exit duplicate_tg_exit(void)
{
    xt_unregister_target(&duplicate_tg_reg);
}

module_init(duplicate_tg_init);
module_exit(duplicate_tg_exit);
