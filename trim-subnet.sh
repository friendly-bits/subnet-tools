#!/bin/sh
# shellcheck disable=SC2181,SC2031,SC2030

# trim-subnet.sh

# trims an ip to given length (expressed in CIDR mask bits) and outputs the resulting subnet

# requires ip with mask bits in 1st arg. optional 2nd arg is ip family (inet or inet6).
# if not specified, auto-detects the ip family.

# this is a modified and (hopefully) improved version of some parts of a script found here:
# https://github.com/chmduquesne/wg-ip/blob/master/wg-ip
# also used some input from here:
# https://stackoverflow.com/questions/14697403/expand-ipv6-address-in-shell-script

# the code is POSIX-compatible
# requires awk, grep with ERE support, sed and some additional standard utilities like tr and cut.
# only tested with GNU variants, and only on Linux.


#### Initial setup
export LC_ALL=C
me=$(basename "$0")


#### Functions

# converts given ip address into hex number
ip_to_hex() (
	ip="$1"
	family="$2"
	[ -z "$ip" ] && { echo "ip_to_hex(): Error: received an empty ip address." >&2; return 1; }
	[ -z "$family" ] && { echo "ip_to_hex(): Error: received an empty value for ip family." >&2; return 1; }

	case "$family" in
		inet )
			split_ip="$(printf "%s" "$ip" | tr '.' ' ')"
			for ip in $split_ip; do
				printf "%02x" "$ip"
			done
		;;
		inet6 )
			expanded_ip="$(expand_ipv6 "$ip")"
			# expanded ipv6 address should be represented in 32 characters
			[ ${#expanded_ip} -ne 32 ] && \
				{ echo "ip_to_hex(): Error: failed to expand ip '$ip'. Resulting address '$expanded_ip' has invalid length." >&2; return 1; }
			printf "%s" "$expanded_ip"
		;;
		* ) echo "ip_to_hex(): Error: invalid family '$family'" >&2; return 1 ;;
	esac
)

# expands given ipv6 address into hex number
expand_ipv6() (
	addr="$1"
	[ -z "$addr" ] && { echo "expand_ipv6(): Error: received an empty ip address." >&2; return 1; }

	# prepend 0 if we start with :
	printf "%s" "$addr" | grep "^:" >/dev/null 2>/dev/null && addr="0${addr}"

	# expand ::
	if printf "%s" "$addr" | grep "::" >/dev/null 2>/dev/null; then
		# count colons
		colons="$(printf "%s" "$addr" | tr -cd ':')"
		# repeat :0 for every missing colon
		expanded_zeroes="$(for i in $(seq $((9-${#colons})) ); do printf "%s" ':0'; done)";
		# replace '::'
		addr=$(printf "%s" "$addr" | sed "s/::/$expanded_zeroes/")
	fi

	# replace colons with whitespaces
	quads=$(printf "%s" "$addr" | tr ':' ' ')

	# pad with 0's and merge
	for quad in $quads; do
		printf "%04x" "0x$quad" || \
					{ echo "expand_ipv6(): Error: failed to convert quad '0x$quad'." >&2; return 1; }
	done
)

# returns a compressed ipv6 address in the format recommended by RFC5952
# expects a fully expanded and merged ipv6 address as input (no colons)
compress_ipv6 () (
	ip=""
	# add leading colon
	quads_merged="${1}"
	[ -z "$quads_merged" ] && { echo "compress_ipv6(): Error: received an empty string." >&2; return 1; }

	# split into whitespace-separated quads
	quads="$(printf "%s" "$quads_merged" | sed 's/.\{4\}/& /g')"
	# remove extra leading 0's in each quad, remove whitespaces, add colons
	for quad in $quads; do
		ip="${ip}$(printf "%x:" "0x$quad")" || \
					{ echo "compress_ipv6(): Error: failed to convert quad '0x$quad'." >&2; return 1; }
	done

	# remove trailing colon, add leading colon
	ip=":${ip%?}"

	# compress 0's across neighbor chunks
	for zero_chain in ":0:0:0:0:0:0:0:0" ":0:0:0:0:0:0:0" ":0:0:0:0:0:0" ":0:0:0:0:0" ":0:0:0:0" ":0:0:0" ":0:0"
	do
		case "$ip" in
			*$zero_chain* )
				ip="$(printf "%s" "$ip" | sed -e "s/$zero_chain/::/" -e 's/:::/::/')"
				break
		esac
	done

	# trim leading colon if it's not a double colon
	case "$ip" in
		::*) ;;
		:*) ip="${ip#:}"
	esac
	printf "%s" "$ip"
)

# formats merged hex number as an ipv4 or ipv6 address
format_ip() (
	ip_hex="$1"
	family="$2"
	[ -z "$ip_hex" ] && { echo "format_ip(): Error: received empty value instead of ip_hex." >&2; return 1; }
	[ -z "$family" ] && { echo "format_ip(): Error: received empty value for ip family." >&2; return 1; }
	case "$family" in
		inet )
			# split into 4 octets
			octets="$(printf "%s" "$ip_hex" | sed 's/.\{2\}/&\ /g')"
			# convert from hex to dec, remove spaces, add delimiting '.'
			ip=""
			for octet in $octets; do
				ip="${ip}$(printf "%d." 0x"$octet")" || { echo "format_ip(): Error: failed to convert octet '0x$octet' to decimal." >&2; return 1; }
			done
			# remove trailing '.'
			ip="${ip%?}"
			printf "%s" "$ip"
			return 0
		;;
		inet6 )
			# convert from expanded and merged number into compressed colon-delimited ip
			ip="$(compress_ipv6 "$ip_hex")" || return 1
			printf "%s" "$ip"
			return 0
		;;
		* ) echo "format_ip(): Error: invalid family '$family'" >&2; return 1
	esac
)

# generates a mask represented as a hex number
generate_mask() (
	maskbits="$1"
	mask_len="$2"
	ip_bytes=$((mask_len/8))

	[ -z "$maskbits" ] && { echo "generate_mask(): Error: received empty value instead of mask bits." >&2; return 1; }

	for i in $(seq 0 $((ip_bytes-1)) ); do
		b=0
		j=$(( maskbits - 8 * i))
		if [ $j -ge 8 ]; then
			b=255
		elif [ $j -gt 0 ]; then
			b=$(( (255 << (8-j)) & 255 ))
		else
			b=0
		fi
		# convert to hex
		printf '%02x' "$b"
	done
)

# validates an ipv4 or ipv6 address
# if 'ip route get' command is working correctly, validates the address through it
# then performs regex validation
validate_ip () (
	addr="$1"; addr_regex="$2"
	[ -z "$addr" ] && { echo "validate_ip(): Error:- received an empty ip address." >&2; return 1; }
	[ -z "$addr_regex" ] && { echo "validate_ip: Error: address regex has not been specified." >&2; return 1; }

	if [ -z "$ip_route_get_disable" ]; then
		# using the 'ip route get' command to put the address through kernel's validation
		# it normally returns 0 if the ip address is correct and it has a route, 1 if the address is invalid
		# 2 if validation successful but for some reason it doesn't want to check the route ('permission denied')
		for address in $addr; do
			ip route get "$address" >/dev/null 2>/dev/null; rv=$?
			[ $rv -eq 1 ] && { echo "validate_ip(): Error: ip address'$address' failed kernel validation." >&2; return 1; }
		done
	fi

	# regex validation
	printf "%s\n" "$addr" | tr ' ' "\n" | grep -E "^$addr_regex$" > /dev/null || \
		{ echo "validate_ip(): Error: failed to validate addresses '$addr' with regex." >&2; return 1; }
	return 0
)

# tests whether 'ip route get' command works for ip validation
test_ip_route_get() {
	family="$1"
	case "$family" in
		inet ) legal_addr="127.0.0.1"; illegal_addr="127.0.0.256" ;;
		inet6 ) legal_addr="::1"; illegal_addr=":a:1" ;;
		* ) echo "test_ip_route_get(): Error: invalid family '$family'" >&2; return 1 ;;
	esac
	legal_exp_addr="2001:4567:1212:00b2:0000:0000:0000:0000"
	illegal_exp_addr="2001:4567:1212:00b2:0T00:0000:0000:0000"
	rv_legal=0; rv_illegal=1; rv_legal_exp=0; rv_illegal_exp=1

	# test with a legal ip
	ip route get "$legal_addr" >/dev/null 2>/dev/null; [ $? -ne 0 ] && rv_legal=1
 	# test with an illegal ip
	ip route get "$illegal_addr" >/dev/null 2>/dev/null; [ $? -ne 1 ] && rv_illegal=0
	# test with a legal expanded ip
	ip route get "$legal_exp_addr" >/dev/null 2>/dev/null; rv=$?; if [ $rv -ne 0 ] && [ $rv -ne 2 ]; then rv_legal_exp=1; fi
	# test with an illegal expanded ip
	ip route get "$illegal_exp_addr" >/dev/null 2>/dev/null; [ $? -ne 1 ] && rv_illegal_exp=0

	# combine the results
	rv=$(( rv_legal || rv_legal_exp || ! rv_illegal || ! rv_illegal_exp ))

	if [ $rv -ne 0 ]; then
		echo "$me: Note: command 'ip route get' is not working as expected (or at all) on this device." >&2
		echo "$me: Disabling validation using the 'ip route get' command. Less reliable regex validation will be used instead." >&2
		echo >&2
		ip_route_get_disable=true
	fi
	unset legal_addr illegal_addr legal_exp_addr illegal_exp_addr rv_legal rv_illegal rv_legal_exp rv_illegal_exp
}

# performs bitwise AND on the ip address and the mask
# after optimizations, mostly just copies bits or generates 0's
bitwise_and() (
	ip_hex="$1"; mask_hex="$2"; maskbits="$3"; mask_len="$4"

	# chunk length in bits
	chunk_len=32

	# characters representing each chunk
	char_num=$((chunk_len / 4))

	bits_processed=0
	for i in $(seq 1 $(( mask_len / chunk_len )) ); do
		chunk_start=$((1 + (i - 1)*char_num))
		chunk_end=$((i*char_num))

		ip_chunk="$(printf "%s" "$ip_hex" | cut -c${chunk_start}-${chunk_end} )"

		bits_processed=$((bits_processed + chunk_len))

		# shellcheck disable=SC2086
		# skip calculation where we can simply copy the bits
		if [ $bits_processed -le $maskbits ]; then
			printf "%s" "$ip_chunk"
		else
			mask_chunk="$(printf "%s" "$mask_hex" | cut -c${chunk_start}-${chunk_end} )"
			ip_chunk=$(printf "%0${char_num}x" $(( 0x$ip_chunk & 0x$mask_chunk )) ) || \
				{ echo "bitwise_and(): Error: failed to calculate '0x$ip_chunk & 0x$mask_chunk'."; exit 1; }
			printf "%s" "$ip_chunk"
		fi


		# shellcheck disable=SC2086
		# if we processed $maskbits bits already, no need to calculate further - just append 0's
		if [ $bits_processed -ge $maskbits ]; then
			bytes_missing=$(( (mask_len - bits_processed)/8 ))
			# shellcheck disable=SC2034
			# repeat 0 for every missing character
			for b in $(seq 1 $bytes_missing); do printf "%s" '00'; done
			break
		fi
	done
)

# Main
trim_subnet() {
	# check dependencies
	! command -v awk >/dev/null || ! command -v sed >/dev/null || ! command -v tr >/dev/null || \
	! command -v grep >/dev/null || ! command -v ip >/dev/null || ! command -v cut >/dev/null && \
		{ echo "trim_subnet(): Error: missing dependencies, can not proceed" >&2; return 1; }

	# test 'grep -E'
	rv=0; rv1=0; rv2=0
	printf "%s" "32" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null; rv1=$?
	printf "%s" "0" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null; rv2=$?
	rv=$((rv1 || ! rv2))
	[ "$rv" -ne 0 ] && { echo "trim_subnet(): Error: 'grep -E' command is not working correctly on this machine." >&2; return 1; }
	unset rv rv1 rv2

	# convert to lower case
	input_ip="$(printf "%s" "$1" | awk '{print tolower($0)}')"
	family="$(printf "%s" "$2" | awk '{print tolower($0)}')"

	# get mask bits
	maskbits="$(printf "%s" "$input_ip" | awk -F/ '{print $2}')"

	[ -z "$maskbits" ] && { echo "trim_subnet(): Error: input '$input_ip' has no mask bits." >&2; return 1; }

	# chop off mask bits
	input_addr="$(printf "%s" "$input_ip" | awk -F/ '{print $1}')"

	# detect the family
	if [ -z "$family" ]; then
		printf "%s" "$input_addr" | grep -E "^${ipv4_regex}$" > /dev/null && family="inet"
		printf "%s" "$input_addr" | grep -E "^${ipv6_regex}$" > /dev/null && family="inet6"
	fi

	[ -z "$family" ] && { echo "trim_subnet(): Error: failed to detect the family for address '$input_addr'." >&2; return 1; }

	case "$family" in
		inet ) mask_len=32; addr_regex="$ipv4_regex" ;;
		inet6 ) mask_len=128; addr_regex="$ipv6_regex" ;;
		* ) echo "trim_subnet(): Error: invalid family '$family'" >&2; return 1 ;;
	esac

	# validate mask bits
	if [ "$maskbits" -lt 8 ] || [ "$maskbits" -gt $mask_len ]; then echo "trim_subnet(): Error: invalid $family mask bits '$maskbits'." >&2; return 1; fi

	test_ip_route_get "$family" || return 1

	validate_ip "${input_addr}" "$addr_regex" || return 1

	# convert ip to hex number
	ip_hex="$(ip_to_hex "$input_addr" "$family")" || return 1
	mask_hex="$(generate_mask "$maskbits" $mask_len)" || return 1

	# perform bitwise AND on the ip address and the mask
	newip_hex="$(bitwise_and "$ip_hex" "$mask_hex" "$maskbits" $mask_len)" || return 1
	new_ip="$(format_ip "$newip_hex" "$family")" || return 1

	subnet="${new_ip}/$maskbits"

	# shellcheck disable=SC2015
	validate_ip "$new_ip" "$addr_regex" && { printf "%s\n" "$subnet"; return 0; } || return 1
}

#### Constants
# ipv4 regex taken from here and modified for ERE matching:
# https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
# the longer ("alternative") ipv4 regex from the top suggestion performs about 40x faster on a slow CPU with ERE grep than the shorter one
# ipv6 regex taken from the BanIP code and modified for ERE matching
# https://github.com/openwrt/packages/blob/master/net/banip/files/banip-functions.sh
ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}:?'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
#maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'


# to test functions from external sourcing script, export the $source_trim_subnet variable in that script
if [ -z "$source_trim_subnet" ]; then
	trim_subnet "$1" "$2" || exit 1
else return 0
fi
