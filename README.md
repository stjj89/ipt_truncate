ipt_truncate
============

TRUNCATE target module for iptables

-- To compile and install module --
Type "sudo make" then "sudo make install"

-- To uninstall module --
Type "sudo make uninstall"

-- To run --
Type "iptables -t mangle -A $CHAIN -j TRUNCATE --at-byte=$NUM [--drop-tcp-opts]",
where $CHAIN is OUTPUT, FORWARD, POSTROUTING or PREROUTING, and $NUM is the 
number of bytes to keep. 

The --at-byte argument must be specified, while the --drop-tcp-opts option is 
optional (optional TCP options after the first 20 bytes of the TCP header are
kept by default).

-- To clean --
Type "sudo make clean"
