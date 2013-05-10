#ifndef _IPT_TRUNCATE_H
#define _IPT_TRUNCATE_H

struct ipt_truncate_info {
    int at_byte;
    int drop_tcp_opts;  
};

#endif /*_IPT_TRUNCATE_H*/
