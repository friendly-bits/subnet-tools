#!/bin/sh
# shellcheck disable=SC2181,SC2031,SC2030

# trim-subnet.sh

# trims an ip to given length (expressed in CIDR mask bits) and outputs the resulting subnet

# requires ip with mask bits in 1st arg. optional 2nd arg is ip family (inet or inet6).
# if not specified, auto-detects the ip family.

# the code is POSIX-compliant
# requires awk, grep with ERE support, sed and some additional standard utilities like tr and cut.
# only tested with GNU variants, and only on Linux. should work on other Unixes.


#### Initial setup
export LC_ALL=C
#debugmode=true


#### Functions

# converts given ip address into a hex number
ip_to_hex() {
	ip="$1"
	family="$2"
	[ -z "$ip" ] && { echo "ip_to_hex(): Error: received an empty ip address." >&2; return 1; }
	[ -z "$family" ] && { echo "ip_to_hex(): Error: received an empty value for ip family." >&2; return 1; }

	case "$family" in
		inet )
			split_ip="$(printf "%s" "$ip" | tr '.' ' ')"
			for ip in $split_ip; do
				printf "%02x" "$ip" || { echo "ip_to_hex(): Error: failed to convert ip '$ip' to hex." >&2; return 1; }
			done
		;;
		inet6 )
			expand_ipv6 "$ip" || { echo "ip_to_hex(): Error: failed to expand ip '$ip'." >&2; return 1; }
		;;
		* ) echo "ip_to_hex(): Error: invalid family '$family'" >&2; return 1 ;;
	esac
}

# expands given ipv6 address and converts it into a hex number
expand_ipv6() {
	addr="$1"
	[ -z "$addr" ] && { echo "expand_ipv6(): Error: received an empty string." >&2; return 1; }

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
}

# returns a compressed ipv6 address in the format recommended by RFC5952
# for input, expects a fully expanded ipv6 address represented as a hex number (no colons)
compress_ipv6() {
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
}

# converts an ip address represented as a hex number into a standard ipv4 or ipv6 address
hex_to_ip() {
	ip_hex="$1"
	family="$2"
	[ -z "$ip_hex" ] && { echo "hex_to_ip(): Error: received empty value instead of ip_hex." >&2; return 1; }
	[ -z "$family" ] && { echo "hex_to_ip(): Error: received empty value for ip family." >&2; return 1; }
	case "$family" in
		inet )
			# split into 4 octets
			octets="$(printf "%s" "$ip_hex" | sed 's/.\{2\}/&\ /g')"
			# convert from hex to dec, remove spaces, add delimiting '.'
			ip=""
			for octet in $octets; do
				ip="${ip}$(printf "%d." 0x"$octet")" || { echo "hex_to_ip(): Error: failed to convert octet '0x$octet' to decimal." >&2; return 1; }
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
		* ) echo "hex_to_ip(): Error: invalid family '$family'" >&2; return 1
	esac
}

# generates a mask represented as a hex number
generate_mask()
{
	# CIDR bits
	maskbits="$1"

	# address length (32 bits for ipv4, 128 bits for ipv6)
	addr_len="$2"

	[ -z "$maskbits" ] && { echo "generate_mask(): Error: received empty value instead of mask bits." >&2; return 1; }
	[ -z "$addr_len" ] && { echo "generate_mask(): Error: received empty value instead of mask length." >&2; return 1; }

	mask_bytes=$((addr_len/8))

	mask="" bytes_done=0 i=0 sum=0 cur=128
	octets='' frac=''

	octets=$((maskbits / 8))
	frac=$((maskbits % 8))
	while [ ${octets} -gt 0 ]; do
		mask="${mask}ff"
		octets=$((octets - 1))
		bytes_done=$((bytes_done + 1))
	done

	if [ $bytes_done -lt $mask_bytes ]; then
		while [ $i -lt $frac ]; do
			sum=$((sum + cur))
			cur=$((cur / 2))
			i=$((i + 1))
		done
		mask="$mask$(printf "%02x" $sum)"
		bytes_done=$((bytes_done + 1))

		while [ $bytes_done -lt $mask_bytes ]; do
			mask="${mask}00"
			bytes_done=$((bytes_done + 1))
		done
	fi

	printf "%s\n" "$mask"
}


# validates an ipv4 or ipv6 address
# if 'ip route get' command is working correctly, validates the address through it
# then performs regex validation
validate_ip() {
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
}

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
		echo "test_ip_route_get(): Note: command 'ip route get' is not working as expected (or at all) on this device." >&2
		echo "test_ip_route_get(): Disabling validation using the 'ip route get' command. Less reliable regex validation will be used instead." >&2
		echo >&2
		ip_route_get_disable=true
	fi
	unset legal_addr illegal_addr legal_exp_addr illegal_exp_addr rv_legal rv_illegal rv_legal_exp rv_illegal_exp
}

# calculates bitwise ip & mask, both represented as hex humbers, and outputs the result in the same format
# arguments:
# 1: ip_hex - ip formatted as a hex number, 2: mask_hex - mask formatted as a hex number, 3: maskbits - CIDR value,
# 4: addr_len - address length in bits (32 for ipv4, 128 for ipv6),
# 5: chunk_len - chunk size in bits used for calculation. seems to perform best with 16 bits for ipv4, 32 bits for ipv6
bitwise_and() {
	ip_hex="$1"; mask_hex="$2"; maskbits="$3"; addr_len="$4"; chunk_len="$5"
	[ "$debugmode" ] && echo "ip_hex: '$ip_hex', mask_hex: '$mask_hex', maskbits: '$maskbits', addr_len: '$addr_len', chunk_len: '$chunk_len'" >&2

	# characters representing each chunk
	char_num=$((chunk_len / 4))

	bits_processed=0; char_offset=0
	# shellcheck disable=SC2086
	# copy ~ $maskbits bits
	while [ $((bits_processed + chunk_len)) -le $maskbits ]; do
		chunk_start=$((char_offset + 1))
		chunk_end=$((char_offset + char_num))

		ip_chunk="$(printf "%s" "$ip_hex" | cut -c${chunk_start}-${chunk_end} )"

		printf "%s" "$ip_chunk"
		[ "$debugmode" ] && echo "copied ip chunk: '$ip_chunk'" >&2
		bits_processed=$((bits_processed + chunk_len))
		char_offset=$((char_offset + char_num))
	done

	# shellcheck disable=SC2086
	# calculate the next chunk if needed
	if [ $bits_processed -ne $maskbits ]; then
		chunk_start=$((char_offset + 1))
		chunk_end=$((char_offset + char_num))

		mask_chunk="$(printf "%s" "$mask_hex" | cut -c${chunk_start}-${chunk_end} )"
		ip_chunk="$(printf "%s" "$ip_hex" | cut -c${chunk_start}-${chunk_end} )"
		ip_chunk=$(printf "%0${char_num}x" $(( 0x$ip_chunk & 0x$mask_chunk )) ) || \
			{ echo "bitwise_and(): Error: failed to calculate '0x$ip_chunk & 0x$mask_chunk'."; return 1; }
		printf "%s" "$ip_chunk"
		[ "$debugmode" ] && echo "calculated ip chunk: '$ip_chunk'" >&2
		bits_processed=$((bits_processed + chunk_len))
	fi

	bytes_missing=$(( (addr_len - bits_processed)/8 ))
	# repeat 00 for every missing byte
	[ "$debugmode" ] && echo "bytes missing: '$bytes_missing'" >&2
	# shellcheck disable=SC2086,SC2034
	[ $bytes_missing -gt 0 ] && for b in $(seq 1 $bytes_missing); do printf "%s" '00'; done
	return 0
}

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
		inet ) addr_len=32; chunk_len=16; addr_regex="$ipv4_regex" ;;
		inet6 ) addr_len=128; chunk_len=32; addr_regex="$ipv6_regex" ;;
		* ) echo "trim_subnet(): invalid family '$family'." >&2; return 1 ;;
	esac

	# validate mask bits
	if [ "$maskbits" -lt 8 ] || [ "$maskbits" -gt $addr_len ]; then echo "trim_subnet(): Error: invalid $family mask bits '$maskbits'." >&2; return 1; fi

	test_ip_route_get "$family" || return 1

	validate_ip "${input_addr}" "$addr_regex" || return 1

	# convert ip to hex number
	ip_hex="$(ip_to_hex "$input_addr" "$family")" || return 1
	mask_hex="$(generate_mask "$maskbits" $addr_len)" || return 1

	# perform bitwise AND on the ip address and the mask
	newip_hex="$(bitwise_and "$ip_hex" "$mask_hex" "$maskbits" $addr_len $chunk_len)" || return 1
	new_ip="$(hex_to_ip "$newip_hex" "$family")" || return 1

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


# to use or test functions from external sourcing script, export the $source_trim_subnet variable in that script
if [ -z "$source_trim_subnet" ]; then
	trim_subnet "$1" "$2" || exit 1
else return 0
fi
