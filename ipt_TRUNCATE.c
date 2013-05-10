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

/* Send RST reply */
// static void send_reset( struct sk_buff *oldskb,     /* skb to truncate */
//                         int hook,                   /* hook number */
//                         int num_bytes)              /* # bytes to truncate */
// {
//     struct sk_buff *nskb;
//     const struct iphdr *oiph;
//     struct iphdr *niph;
//     const struct tcphdr *oth;
//     struct tcphdr _otcph, *tcph;
//     unsigned int addr_type;

//     /* IP header checks: fragment. */
//     if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
//         return;

//     // Check protocol and call appopriate function
//     // to truncate packet
//     if(ip_hdr(oldskb)->protocol == IPPROTO_TCP)
//         truncate_TCP(oldskb, hook, num_bytes);
//     else if (ip_hdr(oldskb)->protocol == IPPROTO_UDP)
//         truncate_UDP(oldskb, hook, num_bytes);
//     else
//         truncate_other(oldskb, hook, num_bytes);


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

//     nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
//              LL_MAX_HEADER, GFP_ATOMIC);
//     if (!nskb)
//         return;

//     skb_reserve(nskb, LL_MAX_HEADER);

//     skb_reset_network_header(nskb);
//     niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
//     niph->version   = 4;
//     niph->ihl   = sizeof(struct iphdr) / 4;
//     niph->tos   = 0;
//     niph->id    = 0;
//     niph->frag_off  = htons(IP_DF);
//     niph->protocol  = IPPROTO_TCP;
//     niph->check = 0;
//     niph->saddr = oiph->daddr;
//     niph->daddr = oiph->saddr;

//     tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
//     memset(tcph, 0, sizeof(*tcph));
//     tcph->source    = oth->dest;
//     tcph->dest  = oth->source;
//     tcph->doff  = sizeof(struct tcphdr) / 4;

//     if (oth->ack)
//         tcph->seq = oth->ack_seq;
//     else {
//         tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
//                       oldskb->len - ip_hdrlen(oldskb) -
//                       (oth->doff << 2));
//         tcph->ack = 1;
//     }

//     tcph->rst   = 1;
//     tcph->check = tcp_v4_check(sizeof(struct tcphdr),
//                        niph->saddr, niph->daddr,
//                        csum_partial(tcph,
//                             sizeof(struct tcphdr), 0));

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

    /* Check checksum */
    if (nf_ip_checksum(skb, hook, ip_hdrlen(skb), IPPROTO_TCP))
        return NF_DROP;
    iph = ip_hdr(skb);

    
    /* Drop TCP options, truncate data only */
    if (drop_tcp_opts)
    {
        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +           /* IP header length */
                    sizeof(struct tcphdr) +     /* TCP header length w/o opts (20) */
                    num_bytes;                  /* new data length */

        // Truncate packet
        tail_room = skb->end - skb->tail;
        skb->tail = skb->data + num_bytes;
        skb->end = skb->tail + tail_room;
    }
    
    /* Keep TCP options that are alinged and not truncated */
    else if ( ((tcph->doff << 2) - sizeof(struct tcphdr)) > num_bytes)
    {
        // Check options for handling alignment

        tcp_opts = tcph + sizeof(struct tcphdr);

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
                opt_len = (int) curr_opt; // potential casting problem (CHECK ABOVE TOO)
                
                // Cannot keep this option
                if (bytes_left < opt_len)
                    break;
                // Proceed to next option
                else {
                    curr_opt += opt_len;
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


        // Set tcph->doff to reflect truncation
        tcph->doff = (sizeof(struct tcphdr) + (last_opt - tcp_opts)) / 4;
    }

    /* Keep all TCP Options, truncate only data */
    else
    {
        // Calculate new total packet length (in bytes) after truncation
        new_len =   (iph->ihl * 4) +            /* IP header length */
                    (tcph->doff << 2) +         /* TCP header length w/o opts (20) */
                    num_bytes;                  /* new data length */

        // Truncate packet
        printk("CHECK THIS OUT\n");
        tail_room = skb->end - skb->tail;
        skb->tail = skb->data + num_bytes;
        skb->end = skb->tail + tail_room;
    }

    /* Modify IP header and compute checksum */    
    iph->tot_len   = new_len;     
    iph->check     = ip_fast_csum((unsigned char *)iph, iph->ihl);

    /* Modify TCP header */

    
    /*
    // Creating Ack sequence if it is not ack?
    if (tcph->ack)
        tcph->seq = tcph->ack_seq;
    else {
        tcph->ack_seq = htonl(ntohl(tcph->seq) + tcph->syn + tcph->fin +
                      skb->len - ip_hdrlen(skb) -
                      (tcph->doff << 2));
        tcph->ack = 1;
    }
    */

    /* Recompute checksum for TCP header */
    iph->check = tcp_v4_check(sizeof(struct tcphdr),
                       iph->saddr, iph->daddr,
                       csum_partial(tcph,
                            sizeof(struct tcphdr), 0));

    printk("truncate_TCP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int truncate_UDP(   struct sk_buff *skb,        /* skb to truncate */
                            int hook,                   /* hook number */
                            int num_bytes)              /* # bytes to truncate */
{
    printk("truncate_UDP: Entering...\n");
    struct iphdr *iph;
    struct udphdr _udph, *udph;
    unsigned int new_len;                    /* new total packet length in bytes */
    unsigned int tail_room;
    unsigned int user_data_len;

    udph = skb_header_pointer(skb, ip_hdrlen(skb),
                 sizeof(_udph), &_udph);
    if (udph == NULL) {
        printk("ipt_TRUNCATE: UDP header not found\n");
        return NF_DROP;   
    }

    /* Check checksum */
    if (nf_ip_checksum(skb, hook, ip_hdrlen(skb), IPPROTO_TCP))
        return NF_DROP;
    iph = ip_hdr(skb);

    
    user_data_len = (unsigned char*) skb->tail - (skb->data + (iph->ihl * 4) + sizeof(struct udphdr));

    /* Truncate data */
    
    // Truncate packet if it has any data
    if (user_data_len > 0)
    {
        tail_room = skb->end - skb->tail;

        // Calculate new total packet length (in bytes) after truncation
        if (user_data_len >= num_bytes) {           
            new_len =   (iph->ihl * 4) +            /* IP header length */
                        sizeof(struct udphdr) +     /* UDP header length (8) */
                        num_bytes;                  /* new data length */

            // Truncate packet
                     
        }

        // Truncate all data if it is less than the num_bytes we intend to truncate
        else
            new_len = (iph->ihl * 4) + sizeof(struct udphdr);

        skb->tail = skb->data + new_len;
        printk("truncate_UDP: skb->tail (%08x) = skb->data (%08x) + new_len (%d)\n", skb->tail, skb->data, new_len);
        skb->end = skb->tail + tail_room;
        printk("truncate_UDP: skb->end (%08x) = skb->tail (%08x) + tail_room (%d)\n", skb->end, skb->tail, tail_room);

        /* Modify IP header and compute checksum */
        printk("truncate_UDP: iph->tot_len before reassignment = %d\n", iph->tot_len);
        iph->tot_len   = new_len;     
        iph->check     = ip_fast_csum((unsigned char *)iph, iph->ihl);

        /* UDP Checksum optional for IPv4 */
        udph->check = 0;
    }
    // /* Recompute checksum for UDP header */
    // /* Code taken directly from udp_send_skb() in /net/ipv4/udp.c */
    // struct sock *sk = skb->sk
    // int is_udplite = IS_UDPLITE(sk);
    // __wsum csum = 0;

    // if (is_udplite)                  /*     UDP-Lite      */
    //     csum = udplite_csum(skb);

    // else if (sk->sk_no_check == UDP_CSUM_NOXMIT) {   /* UDP csum disabled */

    //     skb->ip_summed = CHECKSUM_NONE;
    //     goto send;

    // } else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */

    //     udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
    //     goto send;

    // } else
    //     csum = udp_csum(skb);

    // /* add protocol-dependent pseudo-header */
    // udph->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
    //                   sk->sk_protocol, csum);
    // if (udph->check == 0)
    //     udph->check = CSUM_MANGLED_0;

    printk("truncate_UDP: Exiting...\n");
    return XT_CONTINUE;
}

static unsigned int truncate_other( struct sk_buff *skb,        /* skb to truncate */
                            int hook,                   /* hook number */
                            int num_bytes)              /* # bytes to truncate */
{
    printk("truncate_other: Entering...\n");
    struct iphdr *iph;
    //unsigned int addr_type;
    unsigned int new_len;                    /* new total packet length in bytes */
    unsigned int tail_room;
    unsigned int data_len;

    /* Check checksum */
    //if (nf_ip_checksum(skb, hook, ip_hdrlen(skb), IPPROTO_TCP)) {
    //    printk("truncate_other: IP checksum failed!\n");
    //    return NF_DROP;     // Is this default behavior, or no truncate?
    //}
    iph = ip_hdr(skb);

    
    data_len = ((unsigned char*) skb->tail) - (skb->data + (iph->ihl * 4));

    /* Truncate data */
    

    // Truncate packet if it has any data
    if (data_len > 0)
    {
        printk("truncate_other: skb->data_len = %d\n", skb->data_len);

        tail_room = skb->end - skb->tail;
        printk("truncate_other: tail_room (%d) = skb->end (%08x) - skb->tail (%08x)\n", tail_room, skb->end, skb->tail);

        // Calculate new total packet length (in bytes) after truncation
        if (data_len >= num_bytes) {
            new_len =   (iph->ihl * 4) +            /* IP header length */
                        num_bytes;                  /* new length for rest of packet */
        }

        // Truncate all data if it is less than the num_bytes we intend to truncate
        else
            new_len = (iph->ihl * 4);


        skb->tail = skb->data + new_len;
        printk("truncate_other: skb->tail (%08x) = skb->data (%08x) + new_len (%d)\n", skb->tail, skb->data, new_len);
        skb->end = skb->tail + tail_room;
        printk("truncate_other: skb->end (%08x) = skb->tail (%08x) + tail_room (%d)\n", skb->end, skb->tail, tail_room);

        /* Modify IP header and compute checksum */    
        printk("truncate_other: iph->tot_len before reassignment = %d\n", iph->tot_len);
        iph->tot_len   = new_len;     
        iph->check     = ip_fast_csum((unsigned char *)iph, iph->ihl);
        printk("truncate_other: new_len = %d\n", new_len);
        printk("truncate_other: iph_check = %08x\n", ip_fast_csum((unsigned char *)iph, iph->ihl));
    }
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
