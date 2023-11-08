# subnet-tools

## get-subnet.sh
Unix shell script which trims an ipv4 or ipv6 address to a given length (expressed in CIDR mask bits) and outputs the resulting subnet.

This is a modified and (hopefully) improved version of some parts of a script found here:
https://github.com/chmduquesne/wg-ip/blob/master/wg-ip

Examples:
- Input: **`sh get-subnet.sh 192.168.4.111/12`**. Output: **`192.160.0.0/12`**
- Input: **`sh get-subnet.sh 2001:4567:1111:56ff::1/42`**. Output: **`2001:4567:1100::/42`**

The auxiliary script _get-subnet-tests.sh_ tests some functions found in the main script. It's not required for the main script.

## aggregate-subnets.sh
Unix shell script which calculates merged subnets (where merge is possible). Basically the script attempts to calculate an efficient configuration for subnets given as an input by trimming down each input subnet to its mask bits and removing subnets that encapsulate each other. Designed for automated creation of firewall rules, but perhaps someone has a different application for this functionality. Utilizes the above get-subnet.sh script as a library. Requires to specify family (inet or inet6) as 1st argument, then any number of subnets to aggregate (for ipv6, enclose each one in double quotes).

Examples:
- Input: **`sh aggregate-subnets.sh inet 192.168.1.1/24 192.168.0.0/16 192.169.0.9/8`**.

Output:
**`192.0.0.0/8`**

- Input: **`sh aggregate-subnets.sh inet 192.168.1.1/24 192.168.0.0/16 192.169.0.9/16`**.

Output: **`192.168.0.0/16 192.169.0.0/16`**

(works the same way for ipv6 subnets)

## Dependencies
_awk_, _grep_ with ERE support, _sed_ and some additional standard Unix utilities like _tr_ and _cut_.

The code is POSIX-compliant (tested on dash and on bash) and an effort has been made to avoid using non-POSIX options of the aforementioned utilities.
However, only tested with the GNU variants, and only on Linux (works on OpenWRT as well as on desktop Linux distributions).
Probably should work on other Unixes but may need slight modifications.

## Notes
The scripts are not particularly fast because they're doing a lot of validation and error checking.
If you want to process a lot of addresses, the validation code can be removed and that should speed them up somewhat.

If you find any bugs or have a suggestion for code improvement, please let me know.
