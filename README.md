# subnet-tools
POSIX-compliant shell script library for ip addresses processing, detecting LAN ipv4 and ipv6 subnets and for subnets aggregation.

## Included functions:
- ip_to_int()
- int_to_ip()
- hex_to_ipv6()
- aggregate_subnets()
- detect_lan_subnets()
- get_lan_subnets()

Read code comments to find out what each function is doing and how to use it.

## Usage
Source the subnet-tools.sh script: `. ./subnet-tools.sh`

- LAN subnets detection + aggregation:

`get_lan_subnets [ipv4|ipv6]`

- LAN subnets detection (no aggregation):

`detect_lan_subnets [ipv4|ipv6]`

- Subnets/ip's aggregation:

Pipe input subnets (newline-separated) into aggregate_subnets. Example:

`cat subnets_file.txt | aggregate_subnets [ipv4|ipv6]`

## Dependencies
- **ip** utility
- **_grep_**, **_sed_**, **_tr_** and **_sort_**.
- All scripts require the ip-regex.sh script which sets regex variables.

## Notes
- Only use get_lan_subnets() and detect_lan_subnets() on a machine which has no dedicated WAN interfaces (physical or logical). Otherwise WAN subnet may be wrongly detected as LAN subnet.

- The library sets a few variables (`$_nl`, `$subnet_regex_ipv4`, `$subnet_regex_ipv6`) - these are required for some of the functions to work correctly

- The shell code is POSIX-compliant (tested on ash, dash and bash).
- The library avoids using non-POSIX extensions of the aforementioned utilities, except for `grep -o` which technically is not POSIX-compliant but supported by most grep implementations.
- Tested only on Linux. May or may not work on other UNIX-like operating systems.

## Notes
- If you find any bugs or have a suggestion for code improvement, please let me know.
- If you find this repository useful, please take a second to give it a star.
