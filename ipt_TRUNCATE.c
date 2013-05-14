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


static unsigned int truncate_TCP(   struct sk_buff *skb,     /* skb to truncate */
                            int hook,                   /* hook number */
                            int num_bytes,              /* # bytes to truncate */
                            int drop_tcp_opts)          /* boolean flag to drop TCP options */
{
    printk("truncate_TCP: Entering...\n");

    struct iphdr *iph;
    struct tcphdr _tcph, *tcph;
    //unsigned int addr_type;
    unsigned char* tcp_opts;        /* pointer to TCP options */
    unsigned char* curr_opt;
    unsigned char* last_opt;
    int opt_len;
    int bytes_left;
    int new_len;                    /* new total packet length in bytes */
    int tail_room;

    tcph = skb_header_pointer(skb, ip_hdrlen(skb),
                 sizeof(_tcph), &_tcph);
    if (tcph == NULL) {
        printk("ipt_TRUNCATE: TCP header not found\n");
        return NF_DROP;   
    }

    
    /* Drop TCP options, truncate data only */
    if (drop_tcp_opts)
    {
        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +           /* IP header length */
                    sizeof(struct tcphdr) +     /* TCP header length w/o opts (20) */
                    num_bytes;                  /* new data length */

        tcph->doff = sizeof(struct tcphdr) / 4;
    }
    
    /* Keep TCP options that are alinged and not truncated */
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
            // Kind = 0 (end of options list)
            if ((*curr_opt ^ 0x00) == 0)
                break;
            // Kind = 1 (NOP)
            else if ((*curr_opt ^ 0x01) == 0)
            {
                curr_opt++;
                bytes_left--;
            }
            // Kind = 2 (other option)
            else if ((*curr_opt ^ 0x02) == 0)
            {
                curr_opt++;
                bytes_left--;
                opt_len = (uint8_t) curr_opt; // potential casting problem (CHECK ABOVE TOO)
                
                // Cannot keep this option
                if (bytes_left < opt_len)
                    break;
                // Proceed to next option
                else {

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
                printk("ipt_TRUNCATE: Invalid TCP Option detected\n");
                return NF_DROP;
            }

        }

        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +           /* IP header length */
                    sizeof(struct tcphdr) +     /* TCP header length w/o options (20) */
                    (last_opt - tcp_opts);      /* Length of options kept */

        // Set tcp header length
        if (((sizeof(struct tcphdr) + (last_opt - tcp_opts)) % 4) != 0) {
            printk("truncate_TCP: ERROR (sizeof(struct tcphdr) + (last_opt - tcp_opts)) = %d, not divisible by 4\n", 
                (sizeof(struct tcphdr) + (last_opt - tcp_opts)));
            return NF_DROP;
        }
        tcph->doff = (sizeof(struct tcphdr) + (last_opt - tcp_opts)) / 4;

    }

    /* Keep all TCP Options, truncate only data */
    else
    {
        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +            /* IP header length */
                    num_bytes;                  /* new data length */

    }

    // Paged data in SKB
    if (skb->data_len > 0)
    {
        err = pskb_trim(skb, new_len);
        if (err) {
            printk("truncate_UDP: ERROR pskb_trim failed!\n");
            return NF_DROP;
        }

        // printk("truncate_other: Exiting after pskb_trim...\n");
        // kfree_skb(nskb);
        // return NF_DROP;
    }

    // Linear data in SKB
    else
    {
        skb_trim(skb, new_len);
        // err = skb_trim(nskb, new_len);
        //if (err) {
        //    printk("truncate_UDP: ERROR skb_trim failed!\n");
        //    goto free_nskb;
        //}
    }

    /* Modify IP header and compute checksum */
    iph = ip_hdr(skb);
    iph->tot_len   = htons(new_len);     
    iph->check     = ip_fast_csum((unsigned char *)iph, iph->ihl);


    /* Recompute checksum for TCP header */
    tcph->check = tcp_v4_check(sizeof(struct tcphdr),
                       iph->saddr, iph->daddr,
                       csum_partial(tcph,
                            sizeof(struct tcphdr), 0));

    printk("truncate_TCP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int truncate_UDP(struct sk_buff *skb,        /* skb to truncate */
                            int hook,                   /* hook number */
                            int num_bytes)              /* # bytes to truncate */
{
    printk("truncate_UDP: Entering...\n");
    struct iphdr *iph;
    struct udphdr _udph, *udph;
    unsigned int new_len;                    /* new total packet length in bytes */
    int err;

    udph = skb_header_pointer(skb, ip_hdrlen(skb),
                 sizeof(_udph), &_udph);
    if (udph == NULL) {
        printk("ipt_TRUNCATE: UDP header not found\n");
        return NF_DROP;   
    }

    
    // Less data after iphdr and udphdr than we want to keep 
    if ( (skb->len - sizeof(struct iphdr) - sizeof(struct udphdr)) < num_bytes )
        new_len = skb->len;
    
    // More data than we want to keep, so truncate from after
    // udp header
    else
        new_len = sizeof(struct iphdr) + sizeof(struct udphdr) + num_bytes;


    // Paged data in SKB
    if (skb->data_len > 0)
    {
        err = pskb_trim(skb, new_len);
        if (err) {
            printk("truncate_UDP: ERROR pskb_trim failed!\n");
            return NF_DROP;
        }

        // printk("truncate_other: Exiting after pskb_trim...\n");
        // kfree_skb(nskb);
        // return NF_DROP;
    }

    // Linear data in SKB
    else
    {
        skb_trim(skb, new_len);
        // err = skb_trim(nskb, new_len);
        //if (err) {
        //    printk("truncate_UDP: ERROR skb_trim failed!\n");
        //    goto free_nskb;
        //}
    }

    // Modify IP header 
    iph = ip_hdr(skb);
    iph->tot_len   = htons(new_len);     
    ip_send_check(iph);

    // Modify UDP header
    udph->check = 0; // UDP Checksum optional for IPv4
    udph->len = htons(new_len - sizeof(struct iphdr));

    printk("truncate_UDP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int truncate_other(struct sk_buff *skb,        /* skb to truncate */
                            int hook,                   /* hook number */
                            int num_bytes)              /* # bytes to truncate */
{
    printk("truncate_other: Entering...\n");
    struct iphdr *iph;
    //unsigned int addr_type;
    unsigned int new_len;                    /* new total packet length in bytes */
    unsigned int tail_room;
    unsigned int data_len;
    int err;

    /* Check checksum */
    //if (nf_ip_checksum(skb, hook, ip_hdrlen(skb), IPPROTO_TCP)) {
    //    printk("truncate_other: IP checksum failed!\n");
    //    return NF_DROP;     // Is this default behavior, or no truncate?
    //}
    


    // Less data after iphdr than we want to keep 
    if ( (skb->len - sizeof(struct iphdr)) < num_bytes )
        new_len = skb->len;
    
    // More data than we want to keep, so truncate from after
    // ip header
    else
        new_len = sizeof(struct iphdr) + num_bytes;

    // nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) 
    //                 + LL_MAX_HEADER, GFP_ATOMIC);

    // Paged data in SKB
    if (skb->data_len > 0)
    {
        err = pskb_trim(skb, new_len);
        if (err) {
            printk("truncate_other: ERROR pskb_trim failed!\n");
            return NF_DROP;
        }

        // printk("truncate_other: Exiting after pskb_trim...\n");
        // kfree_skb(nskb);
        // return NF_DROP;
    }

    // Linear data in SKB
    else
    {
        skb_trim(skb, new_len);
        // err = skb_trim(nskb, new_len);
        //if (err) {
        //    printk("truncate_other: ERROR skb_trim failed!\n");
        //    goto free_nskb;
        //}
    }



    // Modify IP header and compute checksum 
    iph = ip_hdr(skb);
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
    printk("truncate_tg: Entering...\n");
    const struct ipt_truncate_info *truncate = par->targinfo;

    if (skb->protocol == IPPROTO_TCP)
        return truncate_TCP(skb, par->hooknum, truncate->at_byte, truncate->drop_tcp_opts);
    else if (skb->protocol == IPPROTO_UDP)
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
        printk("ipt_TRUNCATE: at_byte option cannot be passed negative value.\n");
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

// /* Send RST reply */
// static unsigned int truncate_other2( struct sk_buff *oldskb,     /* skb to truncate */
//                             int hook,                   /* hook number */
//                             int num_bytes)              /* # bytes to truncate */
// {
//     printk("truncate_other: Entering...\n");

//     struct sk_buff *nskb;
//     struct iphdr *niph, *oiph;
//     unsigned int addr_type;
//     int err;

    
//     // int headerlen = skb_headroom(oldskb);
//     // unsigned int size = skb_end_offset(oldskb) + oldskb->data_len;
//     unsigned int new_len;

//     // Less data after iphdr than we want to keep 
//     if ( (oldskb->len - sizeof(struct iphdr)) < num_bytes )
//         new_len = oldskb->len;
    
//     // More data than we want to keep, so truncate from after
//     // ip header
//     else
//         new_len = sizeof(struct iphdr) + num_bytes;

//     // nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) 
//     //                 + LL_MAX_HEADER, GFP_ATOMIC);

//     nskb = skb_copy(oldskb, GFP_ATOMIC);
//     if (!nskb) {
//         printk("truncate_other: ERROR skb_copy failed!\n");
//         return NF_DROP;
//     }


//     // Paged data in SKB
//     if (oldskb->data_len > 0)
//     {
//         err = pskb_trim(nskb, new_len);
//         if (err) {
//             printk("truncate_other: ERROR pskb_trim failed!\n");
//             goto free_nskb;
//         }

//         // printk("truncate_other: Exiting after pskb_trim...\n");
//         // kfree_skb(nskb);
//         // return NF_DROP;
//     }

//     // Linear data in SKB
//     else
//     {
//         skb_trim(nskb, new_len);
//         // err = skb_trim(nskb, new_len);
//         //if (err) {
//         //    printk("truncate_other: ERROR skb_trim failed!\n");
//         //    goto free_nskb;
//         //}

//         // printk("truncate_other: Exiting after skb_trim...\n");
//         // kfree_skb(nskb);
//         // return NF_DROP;
//     }



//     // Modify IP header and compute checksum 
//     niph = ip_hdr(nskb);
//     oiph = ip_hdr(oldskb);
//     printk("truncate_other: oldskb->len = %d\n", oldskb->len);
//     printk("truncate_other: oiph->tot_len = %d\n", oiph->tot_len);
//     printk("truncate_other: niph->tot_len before reassignment = %d\n", niph->tot_len);
//     niph->tot_len   = new_len;     
//     niph->check     = ip_fast_csum((unsigned char *)niph, niph->ihl);
//     printk("truncate_other: new_len = %d\n", new_len);
//     printk("truncate_other: iph_check = %08x\n", ip_fast_csum((unsigned char *)niph, niph->ihl));



//     addr_type = RTN_UNSPEC;
//     if (hook != NF_INET_FORWARD
// #ifdef CONFIG_BRIDGE_NETFILTER
//         || (nskb->nf_bridge && nskb->nf_bridge->mask & BRNF_BRIDGED)
// #endif
//        )
//         addr_type = RTN_LOCAL;

//     /* ip_route_me_harder expects skb->dst to be set */
//     skb_dst_set(nskb, dst_clone(skb_dst(oldskb)));

//     if (ip_route_me_harder(nskb, addr_type))
//         goto free_nskb;

//     printk("truncate_other: Finished ip_route_me_harder!\n");

//     niph->ttl   = dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);
//     nskb->ip_summed = CHECKSUM_NONE;

//     nf_ct_attach(nskb, oldskb);

//     ip_local_out(nskb);
//     //ip_output(nskb);

//     printk("truncate_other: Finished ip_local_out!\n");
//     printk("truncate_other: Exiting normally...\n");
//     return NF_DROP;

//  free_nskb:
//     kfree_skb(nskb);
//     printk("truncate_other: Exiting with error...\n");
//     return NF_DROP;
// }

// static void truncate_TCP2( struct sk_buff *oldskb,     /* skb to truncate */
//                           int hook,                   /* hook number */
//                           int num_bytes)              /* # bytes to truncate */
// {

//     struct sk_buff *nskb;
//     const struct iphdr *oiph;
//     struct iphdr *niph;
//     const struct tcphdr *oth;
//     struct tcphdr _otcph, *tcph;
//     unsigned int addr_type;
//     int new_len;                    /* new total packet length in bytes */
//     unsigned char* data;
//     int err;

//     oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
//                  sizeof(_otcph), &_otcph);
//     if (oth == NULL)
//         return;

//     /* No RST for RST. */
//     if (oth->rst)
//         return;

//     /* Check checksum */
//     if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
//         return;
//     oiph = ip_hdr(oldskb);

//     /* Allocate new skb */
//     //nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
//     //         LL_MAX_HEADER, GFP_ATOMIC);
//     nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
//              LL_MAX_HEADER + num_bytes, GFP_ATOMIC);
//     if (!nskb)
//         return;

//     /* Calculate new total packet length (in bytes) after truncation */
//     new_len =   (oiph->ihl * 4) +           /* old ip header length */
//                 sizeof(struct tcphdr) +     /* truncated TCP header length */
//                 num_bytes;                  /* new data length */

//     skb_reserve(nskb, LL_MAX_HEADER);

//     skb_reset_network_header(nskb);
//     niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
//     niph->version   = oiph->version;
//     niph->tot_len   = new_len;
//     niph->ihl       = oiph->ihl/* sizeof(struct iphdr) / 4 */;
//     niph->tos       = oiph->tos;
//     niph->id        = oiph->id;
//     niph->frag_off  = oiph->frag_off /*htons(IP_DF)*/;
//     niph->protocol  = oiph->protocol /*IPPROTO_TCP*/;
//     niph->check     = 0;                // ip_fast_csum() called later in ip_send_check() in ip_local_out
//     niph->saddr     = oiph->daddr;      // ?? Are we sending back or forwarding?
//     niph->daddr     = oiph->saddr;

//     tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
//     memset(tcph, 0, sizeof(*tcph));
//     tcph->source    = oth->dest;        // ?? Switch source and destination?
//     tcph->dest      = oth->source;
//     tcph->doff      = sizeof(struct tcphdr) / 4;
//     tcph->seq       = oth->seq;
//     tcph->ack_seq   = oth->ack_seq;
//     /*
//     // Creating Ack sequence if it is not ack?
//     if (oth->ack)
//         tcph->seq = oth->ack_seq;
//     else {
//         tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
//                       oldskb->len - ip_hdrlen(oldskb) -
//                       (oth->doff << 2));
//         tcph->ack = 1;
//     }
//     */
//     tcph->rst   = oth->rst;
//     tcph->check = tcp_v4_check(sizeof(struct tcphdr),
//                        niph->saddr, niph->daddr,
//                        csum_partial(tcph,
//                             sizeof(struct tcphdr), 0));

//     /* Truncate data */
//     data = skb_put(skb, num_bytes);
//     err = 0;

//     /* Only num_bytes of data from old skb is copied into new SKB */
//     // ?? Did we mean to count starting from TCP Options, if they are there?
//     skb->csum = csum_and_copy_from_user(oldskb->data, data,
//                         num_bytes, 0, &err);
//     if (err)
//         goto free_nskb;

//     // ?? NOT SURE WHAT THIS STUFF DOES
//     addr_type = RTN_UNSPEC;
//     if (hook != NF_INET_FORWARD
// #ifdef CONFIG_BRIDGE_NETFILTER
//         || (nskb->nf_bridge && nskb->nf_bridge->mask & BRNF_BRIDGED)
// #endif
//        )
//         addr_type = RTN_LOCAL;

//     /* ip_route_me_harder expects skb->dst to be set */
//     skb_dst_set(nskb, dst_clone(skb_dst(oldskb)));

//     if (ip_route_me_harder(nskb, addr_type))
//         goto free_nskb;

//     niph->ttl   = dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);
//     nskb->ip_summed = CHECKSUM_NONE;

//     /* "Never happens" */
//     if (nskb->len > dst_mtu(skb_dst(nskb)))
//         goto free_nskb;

//     nf_ct_attach(nskb, oldskb);

//     ip_local_out(nskb);
//     return;

//  free_nskb:
//     kfree_skb(nskb);
// }
