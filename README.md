# get-subnet
Unix shell script which trims an ipv4 or ipv6 address to a given length (expressed in CIDR mask bits) and outputs the resulting subnet.

Examples:
- Input: '**192.168.4.111/12**'. Output: '**192.160.0.0/12**'
- Input: '**2001:4567:1111:56ff::1/42**'. Output: '**2001:4567:1100::/42**'

This is a modified and (hopefully) improved version of some parts of a script found here:
https://github.com/chmduquesne/wg-ip/blob/master/wg-ip

Requires _awk_, _grep_ with ERE support, _sed_ and some additional standard Unix utilities like _tr_ and _cut_.

The code is supposedly POSIX-compliant (tested on dash and on bash) and even some effort has been made to avoid using non-POSIX options of the abovementioned utilities.
However, only tested with the GNU variants, and only on Linux (works on OpenWRT as well as on desktop Linux distributions).
Probably should work on other Unixes but may need slight modifications.

The script is not particularly fast because it's doing a lot of validation and error checking. One run takes about 0.1s (for ipv6), depending on the CPU.
If you want to put a lot of addresses through it, the validation code can be removed and that should speed it up.

The second script (_get-subnet-tests.sh_) tests some functions found in the main script. It's not required for the main script.

If you find any bugs or have a suggestion for code improvement, please let me know.
