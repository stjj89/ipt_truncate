# Simple script to install module for testing

#!/bin/sh
rmmod /lib/modules/2.6.32-5-amd64/kernel/net/netfilter/x_tables.ko
insmod /lib/modules/2.6.32-5-amd64/kernel/net/netfilter/x_tables.ko
cd ./user
make libipt_TRUNCATE.so
rm /lib/xtables/libipt_TRUNCATE.so
cp ./libipt_TRUNCATE.so /lib/xtables/
cd ..
make
rmmod ipt_TRUNCATE.ko
insmod ./ipt_TRUNCATE.ko