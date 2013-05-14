ipt_truncate
============

TRUNCATE target module for iptables

-- To compile --
1. Get root shell (sudo su)
2. Type "./install.sh"

-- To run --
1. Type "iptables -A $CHAIN -j TRUNCATE --at-byte=$NUM [--drop-tcp-opts]",
   where $CHAIN is either OUTPUT or FORWARD, and $NUM is the number of bytes
   to keep (compulsary argument)
