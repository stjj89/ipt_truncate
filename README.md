ipt_truncate
============

TRUNCATE target module for iptables

-- To compile --
Type "sudo make" then "sudo make install"
(Note: xtables module must already be loaded)

-- To run --
Type "iptables -A $CHAIN -j TRUNCATE --at-byte=$NUM [--drop-tcp-opts]",
where $CHAIN is either OUTPUT or FORWARD, and $NUM is the number of bytes
to keep (compulsary argument)
