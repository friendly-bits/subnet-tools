# get-subnet
Shell script that trims an ipv4 or ipv6 address to a given length, and outputs resulting subnet: ip with mask bits.

Examples:
- Input: _'192.168.4.112/12' inet_. Output: _'192.160.0.0/12'_
- Input: _'2001:4567:1111:56ff::1/42' inet6_. Output: _'2001:4567:1100::/42'_

This is a modified and improved version of a script found here:
https://github.com/chmduquesne/wg-ip/blob/master/wg-ip

The code should be POSIX-compatible (tested on dash and on bash).
Requires _awk_, _grep_ with ERE support, _sed_ and some additional standard Unix utilities like _tr_ and _cut_.
Only tested with GNU variants, and only on Linux.
Probably should work on other Unixes but may need slight modifications.

The script is not particularly fast because it's doing a lot of validation. One run takes about 0.1s, depending on the CPU.
If you want to put a lot of addresses through it, the validation code can be removed and it'll work much faster.

The second script (_get-subnet-tests.sh_) tests some functions found in the main script. It's not required for the main script.

If you find any bugs or have a suggestion for code improvement, please let me know.
