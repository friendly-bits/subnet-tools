#!/bin/sh

# get-subnet.sh

# trims an ip to given length (expressed in CIDR mask bits) and outputs the resulting subnet

# requires ip with mask bits in 1st arg. auto-detects the ip family.

# this is a modified and (hopefully) improved version of a script found here:
# https://github.com/chmduquesne/wg-ip/blob/master/wg-ip
# also used some input from here:
# https://stackoverflow.com/questions/14697403/expand-ipv6-address-in-shell-script

# the script should be POSIX-compatible
# requires awk, grep with ERE support, sed and some additional standard utilities like tr and cut.
# only tested with GNU variants, and only on Linux.


# convert hex to dec (portable version)
hex2dec() (
	hex="$*"
	[ -z "$hex" ] && { echo "hex2dec(): Error: received an empty value." >&2; return 1; }

	for i in $hex; do
		printf "%d " "$(( 0x$i ))"
	done
)

# converts given ip address into 16 1-byte chunks
ip_to_bytes() (
	ip="$1"
	family="$2"

	[ -z "$addr" ] && { echo "ip_to_bytes(): Error: received an empty ip address." >&2; return 1; }
	[ -z "$family" ] && { echo "ip_to_bytes(): Error: received an empty value for ip family." >&2; return 1; }

	case "$family" in
		inet )	printf "%s" "$ip" | tr '.' ' ' ;;
		inet6 )
			expanded_ip="$(expand_ipv6 "$ip")"
			validate_ip "$expanded_ip" "$family" || \
				{ echo "ip_to_bytes(): Failed to expand ip '$ip'. Resulting address '$expanded_ip' is invalid." >&2; return 1; }
			split_exp_ip="$(printf "%s" "$expanded_ip" | tr -d ':' | sed 's/.\{2\}/& /g')"
			hex2dec "$split_exp_ip" ;;
		* ) echo "ip_to_bytes(): Error: invalid family '$family'" >&2; return 1 ;;
	esac
)

# expands given ipv6 address
expand_ipv6() (
	addr="$1"

	[ -z "$addr" ] && { echo "expand_ipv6(): Error: received an empty ip address." >&2; return 1; }

	# prepend 0 if we start with :
	printf "%s" "$addr" | grep "^:" >/dev/null 2>/dev/null && addr="0${addr}"

	# expand ::
	if printf "%s" "$addr" | grep "::" >/dev/null 2>/dev/null; then
		colons=$(printf "%s" "$addr" | sed 's/[^:]//g')
		missing=$(printf "%s" ":::::::::" | sed "s/$colons//")
		expanded=$(printf "%s" "$missing" | sed 's/:/:0/g')
		addr=$(printf "%s" "$addr" | sed "s/::/$expanded/")
	fi
	blocks=$(printf "%s" "$addr" | tr ':' ' ')
	blocks="$(hex2dec "$blocks")"
	for block in $blocks; do
		blocks_temp="$blocks_temp$(printf "%04x:" "$block")"
	done
	# trim trailing ':'
	blocks="${blocks_temp%?}"
	printf "%s" "$blocks"
)

# returns a compressed ipv6 address under the form recommended by RFC5952
# expects fully expanded ipv6 address as input, otherwise may produce incorrect results
compress_ipv6 () (
	addr="$1"

	[ -z "$addr" ] && { echo "compress_ipv6(): Error: received an empty ip address." >&2; return 1; }

	compress_var="$(printf "%s\n" "$addr" | sed -e 's/::/:0:/g' | tr ':' '\n' | while read -r compress_var_hex; do [ -n "$compress_var_hex" ] && \
		printf ":%x" "$((0x$compress_var_hex))"; done)"
	for zero_chain in :0:0:0:0:0:0:0:0 :0:0:0:0:0:0:0 :0:0:0:0:0:0 :0:0:0:0:0 :0:0:0:0 :0:0:0 :0:0
	do
		case "$compress_var" in
			*$zero_chain* )
				compress_var="$(printf "%s" "$compress_var" | sed -e "s/$zero_chain/::/" -e 's/:::/::/')"
				break
		esac
	done

	case "$compress_var" in
		::*) ;;
		:*) compress_var="${compress_var#:}"
	esac
	printf "%s" "$compress_var"
)

# formats the input bytes as an ipv4 or ipv6 address
format_ip() (
	bytes="$1"
	family="$2"

	[ -z "$bytes" ] && { echo "format_ip(): Error: received empty value instead of bytes." >&2; return 1; }
	[ -z "$family" ] && { echo "format_ip(): Error: received empty value for ip family." >&2; return 1; }

	case "$family" in
		inet )
			# shellcheck disable=SC2086
			printf "%d.%d.%d.%d\n" $bytes
			return 0
		;;
		inet6 )
			# shellcheck disable=SC2086
			addr="$(printf "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n" $bytes)"
			addr_compressed="$(compress_ipv6 "$addr")"
			validate_ip "$addr" "$family" || \
				{ echo "format_ip(): Error: Failed to compress address '$addr', resulting ip '$addr_compressed' is invalid.'" >&2; return 1; }
			printf "%s" "$addr_compressed"
			return 0
		;;
		* ) echo "format_ip(): Error: invalid family '$family'" >&2; return 1
	esac
)

# generates a mask represented as 16 1-byte hex chunks
mask() (
	maskbits="$1"
	[ -z "$maskbits" ] && { echo "mask(): Error: received empty value instead of mask bits." >&2; return 1; }

	res=""
	for i in $(seq 0 15); do
		b=0
		j=$(( maskbits - 8 * i))
		if [ $j -ge 8 ]; then
			b=255
		elif [ $j -gt 0 ]; then
			b=$(( (255 << (8-j)) & 255 ))
		else
			b=0
		fi
		res="$res $b"
	done

	# trim extra spaces
	res="$(printf "%s" "$res" | awk '{$1=$1};1')"
	printf "%s" "$res"
)

# validates an ipv4 or ipv6 address, with or without mask bits
# first performs regex validation, then runs the address through 'ip route get' command
validate_ip () (
	addr="$1"
	family="$2"

	maskbits="$(printf "%s" "$addr" | awk -F/ '{print $2}')"
	# chop off mask bits
	addr="$(printf "%s" "$addr" | awk -F/ '{print $1}')"

	[ -z "$addr" ] && { echo "validate_ip(): Error: received an empty ip address." >&2; return 1; }
	[ -z "$family" ] && { echo "validate_ip(): Error: received empty value for ip family." >&2; return 1; }

	case "$family" in
		inet )
			if [ -n "$maskbits" ]; then
				printf "%s" "$maskbits" | grep -E "${maskbits_regex_ipv4}" > /dev/null || \
					{ echo "validate_ip(): Error: failed to validate $family mask bits '$maskbits' with 'grep -E ${maskbits_regex_ipv4}'." >&2; return 1; }
			fi
			printf "%s" "$addr" | grep -E "${ipv4_regex}" > /dev/null || \
				{ echo "validate_ip(): Error: failed to validate ipv4 address: '$addr' with 'grep -E ${ipv4_regex}'." >&2; return 1; }
		;;

		inet6 )
			if [ -n "$maskbits" ]; then
				printf "%s" "$maskbits" | grep -E "${maskbits_regex_ipv6}" > /dev/null || \
					{ echo "validate_ip(): Error: failed to validate $family mask bits '$maskbits' with 'grep -E ${maskbits_regex_ipv6}'." >&2; return 1; }
			fi
			printf "%s" "$addr" | grep -E "${ipv6_regex}" > /dev/null || \
				{ echo "validate_ip(): Error: failed to validate ipv6 address '$addr' with 'grep -E ${ipv6_regex}'." >&2; return 1; }
		;;
		* ) echo "validate_ip(): Error: invalid family '$family'" >&2; return 1
	esac

	# using the 'ip route get' command to put the address through kernel's validation
	# it normally returns 0 if the ip address is correct and it has a route, 1 if the address is invalid
	# 2 if validation successful but for some reason it doesn't want to check the route ('permission denied')
	ip route get "$addr" >/dev/null 2>/dev/null; rv=$?
	[ $rv -eq 1 ] && { echo "validate_ip(): Error: failed to validate the ip '$addr' with command 'ip route get'." >&2; return 1; }
	return 0
)


# Main
main() (
	# check dependencies

	# test 'grep -E'
	rv=0
	printf "%s" "32" | grep -E "${maskbits_regex_ipv4}" > /dev/null || rv=1
	printf "%s" "0" | grep -E "${maskbits_regex_ipv4}" > /dev/null && rv=$((rv + 1))
	[ "$rv" -ne 0 ] && { echo "get-subnet: Error: 'grep -E' command is not working correctly on this machine." >&2; return 1; }
	rv=0

 	# test 'ip route get'
	ip route get "127.0.0.1" >/dev/null 2>/dev/null; rv_ipv4=$?
	[ $rv_ipv4 -eq 1 ] && echo "get-subnet: Warning: command 'ip addr get' is not working correctly on this machine for ipv4." >&2
	ip route get "::1" >/dev/null 2>/dev/null; rv_ipv6=$?
	[ $rv_ipv6 -eq 1 ] && echo "get-subnet: Warning: command 'ip addr get' is not working correctly on this machine for ipv6." >&2

	if [ "$rv_ipv4" -eq 1 ] && [ "$rv_ipv6" -eq 1 ]; then
		echo "get-subnet: Error: 'ip route get' command is not present or not working as expected on this machine." >&2; return 1
	fi


	addr="$1"

	# get mask bits
	maskbits="$(printf "%s" "$addr" | awk -F/ '{print $2}')"

	[ -z "$maskbits" ] && { echo "get-subnet: Error: input '$addr' has no mask bits." >&2; return 1; }

	# chop off mask bits
	addr="$(printf "%s" "$addr" | awk -F/ '{print $1}')"


	# detect the family
	family=""
	printf "%s" "$addr" | grep -E "${ipv4_regex}" > /dev/null && family="inet"
	printf "%s" "$addr" | grep -E "${ipv6_regex}" > /dev/null && family="inet6"

	[ -z "$family" ] && { echo "get-subnet: Error: failed to detect the family for address '$addr'." >&2; return 1; }

	[ "$family" = "inet" ] && [ "$rv_ipv4" -eq 1 ] && \
		{ echo "get-subnet: Can't process ipv4 addresses." >&2; return 1; }
	[ "$family" = "inet6" ] && [ "$rv_ipv6" -eq 1 ] && \
		{ echo "get-subnet: Can't process ipv6 addresses." >&2; return 1; }
	

	validate_ip "${addr}/${maskbits}" "$family" || { echo "get-subnet: Error: ip '$addr' failed validation.'" >&2; return 1; }

	ip_bytes="$(ip_to_bytes "$addr" "$family")" || { echo "get-subnet: Error converting ip to bytes." >&2; return 1; }
	mask_bytes="$(mask "$maskbits")" || { echo "get-subnet: Error generating mask bytes." >&2; return 1; }

	[ "$family" = "inet6" ] && mask_len=128 || mask_len=32

	# perform bitwise AND on the address and the mask
	bytes=""
	for i in $(seq 1 $(( mask_len/8 )) ); do
		mask_byte="$(printf "%s" "$mask_bytes" | cut -d' ' -f "$i")"
		ip_byte="$(printf "%s" "$ip_bytes" | cut -d' ' -f "$i")"
		b=$(( ip_byte & mask_byte ))
		bytes="$bytes $b"
	done

	# trim extra spaces
	bytes="$(printf "%s" "$bytes" | awk '{$1=$1};1')"

	subnet="$(format_ip "$bytes" "$family")/$maskbits"

	# shellcheck disable=SC2015
	validate_ip "$subnet" "$family" && { printf "%s\n" "$subnet"; return 0; } || \
		{ echo "get-subnet: Error converting '$addr/$maskbits' to subnet. Resulting subnet '$subnet' is invalid." >&2; return 1; }
)

### Constants
# ipv4 regex and cidr regex taken from here and modified for ERE matching:
# https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
# the longer ("alternative") ipv4 regex from the top suggestion performs about 40x faster on a slow CPU with ERE grep than the shorter one
# ipv6 regex taken from the BanIP code and modified for ERE matching
# https://github.com/openwrt/packages/blob/master/net/banip/files/banip-functions.sh
ipv4_regex='^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])$'
ipv6_regex='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}:?$'
maskbits_regex_ipv6='^(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])$'
maskbits_regex_ipv4='^(3[0-2]|([1-2][0-9])|[8-9])$'


# to test functions from external sourcing script, export the $test_get-subnet variable in that script
if [ -z "$test_get_subnet" ]; then
	main "$1" || exit 1
else return 0
fi
