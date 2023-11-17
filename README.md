# subnet-tools

## trim-subnet.sh
Unix shell script which trims an ipv4 or ipv6 address to a given length (expressed in CIDR mask bits) and outputs the resulting subnet.

Examples:
- Input: **`sh trim-subnet.sh 192.168.4.111/12`**. Output: **`192.160.0.0/12`**
- Input: **`sh trim-subnet.sh 2001:4567:1111:56ff::1/42`**. Output: **`2001:4567:1100::/42`**

The auxiliary script _trim-subnet-tests.sh_ tests some functions found in the main script. It's not required for the main script.

## aggregate-subnets.sh
Unix shell script which calculates an efficient configuration for subnets given as an input by trimming down each input subnet to its mask bits and removing subnets that are encapsulated inside other subnets on the list. Intended for easier automated creation of firewall rules. Utilizes the above trim-subnet.sh script as a library.

Options:

`-f <family>`: force processing subnets for specified family (`inet` for ipv4 or `inet6` for ipv6). If not specified, auto-detects families for input subnets and processes each family separately.

Examples:
- Input: **`sh aggregate-subnets.sh 192.168.1.1/24 192.168.0.0/16 192.169.0.9/8`**.

Output:
**`192.0.0.0/8`**

- Input:
**`sh aggregate-subnets.sh 192.168.1.1/24 192.168.0.0/16 192.169.0.9/16 fd16:1234:5678:ab:1:1:1:1/64 fd16:1234:5678:ab:2:2:2:2/64 fd16:1234:5678:ab::1/128 fd16:1234:5678:cd:1:1:1:1/60`**.

Output: **`192.169.0.0/16
192.168.0.0/16
fd16:1234:5678:ab::/64
fd16:1234:5678:c0::/60`**

## detect-local-subnets.sh
Unix shell script which uses standard utilities to detect local area ipv4 and ipv6 subnets, regardless of the device it's running on (router or host).
Some heuristics are employed which are likely to work on Linux but for other Unixes, testing is recommended.
Tested on Debian-based Linux distributions and on OpenWRT.

Requires the aggregate-subnets.sh and the trim-subnet.sh scripts to process found ip addresses.

Options:

`-s`: only output aggregated subnets

`-f <family>`: only check subnets for specified family (`inet` for ipv4 or `inet6` for ipv6)

## detect-local-subnets-AIO.sh
Same as above but as a stand-alone script (does not require aggregate-subnets.sh and trim-subnet.sh).

## Dependencies
**_awk_**, **_grep_** with ERE support, **_sed_** and some additional standard Unix utilities like **_tr_**, **_sort_** and **_cut_**. All these are included with any desktop Linux distribution and probably with most other Unix-like operating systems.

The code is POSIX-compliant (tested on dash and on bash) and an effort has been made to avoid using non-POSIX options of the aforementioned utilities.
However, only tested with the GNU variants, and only on Linux (works on OpenWRT as well as on desktop Linux distributions).
Probably should work on other Unixes but may need slight modifications.

## Notes
- These scripts do not make any changes to the system they're running on, do not gather any user data and do not send it anywhere. `trim-subnet.sh` and `aggregate-subnets.sh` simply take your input, do some calculations and report the results back to your console. `detect-local-subnets.sh` and `detect-local-subnets-AIO.sh` examine the network configuration on the specific machine they're running on (without making any external connections), do some calculation and report the results back to your console. All that provided that you downloaded the scripts from the official source, which is `https://github.com/blunderful-scripts/subnet-tools`.
- If you find any bugs or have a suggestion for code improvement, please let me know.
- If you find this repository useful, please take a second to give it a star.
