#!/bin/sh
# shellcheck disable=SC2181,SC2031,SC2030

# trim-subnet.sh

# trims an ip to given length (expressed in CIDR mask bits) and outputs the resulting subnet

# requires ip with mask bits in 1st arg. optional 2nd arg is ip family (inet or inet6).
# if not specified, auto-detects the ip family.

# the code is POSIX-compliant
# requires the 'ip' utility, awk, grep with ERE support and tr.
# only tested with GNU variants, and only on Linux. should work on other Unixes.


#### Initial setup
export LC_ALL=C
me=$(basename "$0")
#debugmode=true


#### Functions

# 1 - input string
# 2 - start char pos.
# 3 - end char pos.
substring() {
	printf '%.*s' $(($3 - $2 + 1)) "${1#"$(printf '%.*s' $(($2 - 1)) "$1")"}"
}

# 1 - ip
# 2 - family
# 3 - var name for output
ip_to_hex() {
	convert_ip() {
		IFS="$4"
		for chunk in $ip; do
			printf "%0${2}x" "$3$chunk" || { echo "ip_to_hex(): Error: failed to convert chunk '0x$chunk'." >&2; return 1; }
		done
	}

	ip="$1"; family="$2"; out_var="$3"
	case "$ip" in '') echo "ip_to_hex: Error: received an empty ip address." >&2; return 1; esac

	case "$family" in
		'') echo "ip_to_hex: Error: received an empty value for ip family." >&2; return 1 ;;
		inet ) convert_ip "$ip" "2" "" '.' ;;
		inet6 )
			expand_ipv6 "$ip" "ip" || { echo "ip_to_hex(): Error: failed to expand ip '$ip'." >&2; return 1; }
			# remove colons, pad with 0's and merge
			convert_ip "$ip" "4" "0x" ':'
			;;
		* ) echo "ip_to_hex: Error: invalid family '$family'" >&2; return 1 ;;
	esac
}

# 1 - ip
# 2 - var name for output
expand_ipv6() {
	ip="$1"; out_var="$2"
	case "$ip" in '') echo "expand_ipv6: Error: received an empty string." >&2; return 1; esac

	# prepend 0 if we start with :
	case "$ip" in :*) ip="0${ip}"; esac

	# expand ::
	case "$ip" in *::*)
		# count colons
		colons="$(printf "%s" "$ip" | tr -cd ':')"
		# repeat :0 for every missing colon
		i=1; expanded_zeroes=''
		while true; do
			case $((i > 9-${#colons})) in 1) break; esac
			expanded_zeroes="$expanded_zeroes:0"
			i=$((i+1))
		done
		# replace '::'
		ip="${ip%%::*}$expanded_zeroes${ip#*::}"
	esac
	eval "$out_var"='$ip'
}

# expects a fully expanded ipv6 address for input
# 1 - ip
# 2 - var name for output
compress_ipv6() {
	ip="$1"; out_var="$2"
	# add leading colon

	# compress 0's inside each chunk
	ip="$(IFS=":"
		for chunk in $ip; do
			printf '%x:' "0x$chunk"
		done)"
	ip=":${ip%:}"

	# compress 0's across neighbor chunks
	for zero_chain in ":0:0:0:0:0:0:0:0" ":0:0:0:0:0:0:0" ":0:0:0:0:0:0" ":0:0:0:0:0" ":0:0:0:0" ":0:0:0" ":0:0"
	do
		case "$ip" in
			*$zero_chain* )
				ip="${ip%%"$zero_chain"*}::${ip#*"$zero_chain"}"
				case "$ip" in *:::* ) ip="${ip%%:::*}::${ip#*:::}"; esac
				break
		esac
	done

	# trim leading colon if it's not a double colon
	case "$ip" in
		::*) ;;
		:*) ip="${ip#:}"
	esac
	eval "$out_var"='$ip'
}

# 1 - input hex number
# 2 - family
# 3 - var name for output
hex_to_ip() {
	convert_hex() {
		chunks=$(
			while true; do
				case "$hex" in '') break; esac
				printf '%.*s ' "${#3}" "$hex"
				hex="${hex#$3}"
			done
		)
		for chunk in $chunks; do
			printf "%$2" "0x$chunk" ||
				{ echo "hex_to_ip: Error: failed to convert chunk '0x$chunk'." >&2; return 1; }
		done
	}

	hex="$1"; family="$2"; out_var_hex_to_ip="$3"
	case "$hex" in '') echo "hex_to_ip: Error: received empty value instead of ip_hex." >&2; return 1; esac
	case "$family" in
		'') echo "hex_to_ip: Error: received empty value for ip family." >&2; return 1 ;;
		inet )
			ip="$(convert_hex "$hex" "d." "??")"
			ip="${ip%.}"
			;;
		inet6 )
			ip="$(convert_hex "$hex" "x:" "????")"
			compress_ipv6 "${ip%:}" "ip" || return 1
		;;
		* ) echo "hex_to_ip: Error: invalid family '$family'" >&2; return 1
	esac
	eval "$out_var_hex_to_ip"='$ip'
}

# generates a mask represented as a hex number
# 1 - CIDR bits
# 2 - address length in bits
generate_mask() {
	# CIDR bits
	maskbits="$1"

	# address length (32 bits for ipv4, 128 bits for ipv6)
	addr_len="$2"

	mask_bytes=$((addr_len/8))

	bytes_done=0 i=0 sum=0 cur=128

	octets=$((maskbits / 8))
	frac=$((maskbits % 8))
	while true; do
		case "$octets" in 0) break; esac
		printf '%s' "ff"
		octets=$((octets - 1))
		bytes_done=$((bytes_done + 1))
	done

	case "$bytes_done" in "$mask_bytes") ;; *)
		while true; do
			case "$i" in "$frac") break; esac
			sum=$((sum + cur))
			cur=$((cur / 2))
			i=$((i + 1))
		done
		printf "%02x" "$sum" || { echo "generate_mask: Error: failed to convert byte '$sum' to hex." >&2; return 1; }
		bytes_done=$((bytes_done + 1))

		while true; do
			case "$bytes_done" in "$mask_bytes") break; esac
			printf '%s' "00"
			bytes_done=$((bytes_done + 1))
		done
	esac
}


# validates an ipv4 or ipv6 address or multiple addresses
# if 'ip route get' command is working correctly, validates the addresses through it
# then performs regex validation
# 1 - ip addresses
# 2 - regex
validate_ip() {
	addr="$1"; addr_regex="$2"
	case "$addr" in '') echo "validate_ip: Error: received an empty ip address." >&2; return 1; esac
	case "$addr_regex" in '') echo "validate_ip: Error: address regex has not been specified." >&2; return 1; esac

	case "$ip_route_get_disable" in '')
		# using the 'ip route get' command to put the address through kernel's validation
		# it normally returns 0 if the ip address is correct and it has a route, 1 if the address is invalid
		# 2 if validation successful but for some reason it doesn't want to check the route ('permission denied')
		for address in $addr; do
			ip route get "$address" >/dev/null 2>/dev/null
			case $? in 1) echo "validate_ip: Error: ip address'$address' failed kernel validation." >&2; return 1; esac
		done
	esac

	## regex validation
	# -v inverts grep output to get non-matching lines
	printf "%s\n" "$addr" | grep -vE "^$addr_regex$" > /dev/null
	case $? in 1) ;; *) echo "validate_ip: Error: one or more addresses failed regex validation: '$addr'." >&2; return 1; esac
	return 0
}

# tests whether 'ip route get' command works for ip validation
# 1 - family
test_ip_route_get() {
	family="$1"
	case "$family" in
		inet ) legal_addr="127.0.0.1"; illegal_addr="127.0.0.256" ;;
		inet6 ) legal_addr="::1"; illegal_addr=":a:1" ;;
		* ) echo "test_ip_route_get: Error: invalid family '$family'" >&2; return 1
	esac
	rv_legal=0; rv_illegal=1

	# test with a legal ip
	ip route get "$legal_addr" >/dev/null 2>/dev/null; rv_legal=$?
 	# test with an illegal ip
	ip route get "$illegal_addr" >/dev/null 2>/dev/null; case $? in 1) ;; *) rv_illegal=0; esac

	# combine the results
	rv=$(( rv_legal || ! rv_illegal ))

	case $rv in 0) ;; *)
		echo "test_ip_route_get(): Note: command 'ip route get' is not working as expected (or at all)." >&2
		echo "test_ip_route_get(): Disabling validation using the 'ip route get' command. Less reliable regex validation will be used instead." >&2
		echo >&2
		ip_route_get_disable=true
	esac
}

# calculates bitwise ip & mask, both represented as hex humbers, and outputs the result in the same format
# arguments:
# 1: ip_hex - ip formatted as a hex number, 2: mask_hex - mask formatted as a hex number, 3: maskbits - CIDR value,
# 4: addr_len - address length in bits (32 for ipv4, 128 for ipv6),
# 5: chunk_len - chunk size in bits used for calculation. seems to perform best with 16 bits for ipv4, 32 bits for ipv6
bitwise_and() {
	ip="$1"; mask="$2"; maskbits="$3"; addr_len="$4"; chunk_len="$5"

	# characters representing each chunk
	char_num=$((chunk_len / 4))

	bits_processed=0; char_offset=0
	# copy ~ $maskbits bits
	while true; do
		case $((bits_processed + chunk_len > maskbits)) in 1) break; esac
		chunk_start=$((char_offset + 1))
		chunk_end=$((char_offset + char_num))
		substring "$ip" "$chunk_start" "$chunk_end"

		bits_processed=$((bits_processed + chunk_len))
		char_offset=$((char_offset + char_num))
	done
	# calculate the next chunk if needed
	case "$bits_processed" in "$maskbits") ;; *)
		chunk_start=$((char_offset + 1))
		chunk_end=$((char_offset + char_num))

		mask_chunk="$(substring "$mask" "$chunk_start" "$chunk_end")"
		ip_chunk="$(substring "$ip" "$chunk_start" "$chunk_end")"
		printf "%0${char_num}x" $(( 0x$ip_chunk & 0x$mask_chunk )) ||
			{ echo "bitwise_and: Error: failed to calculate '0x$ip_chunk & 0x$mask_chunk'." >&2; return 1; }
		bits_processed=$((bits_processed + chunk_len))
	esac

	bytes_missing=$(( (addr_len - bits_processed)/8 ))
	# repeat 00 for every missing byte
	b=0
	while true; do
		case "$b" in "$bytes_missing") break; esac
		printf '%s' "00"
		b=$((b+1))
	done
}

# Main

trim_subnet() {
	# convert to lower case
	input_ip="$(printf "%s" "$1" | tr 'A-Z' 'a-z')"
	family="$(printf "%s" "$2" | tr 'A-Z' 'a-z')"

	case "$input_ip" in */*) ;; *) echo "trim_subnet: Error: '$input_ip' is not a valid subnet." >&2; return 1; esac
	# get mask bits
	maskbits="${input_ip#*/}"
	case "$maskbits" in ''|*[!0-9]*)
		echo "trim_subnet: Error: input '$subnet' has no mask bits or it's not a number." >&2; return 1
	esac
	# chop off mask bits
	input_addr="${input_ip%%/*}"

	# detect the family
	if [ -z "$family" ]; then
		printf "%s" "$input_addr" | grep -E "^${ipv4_regex}$" > /dev/null && family="inet"
		printf "%s" "$input_addr" | grep -E "^${ipv6_regex}$" > /dev/null && family="inet6"
	fi

	case "$family" in
		'') echo "trim_subnet: Error: failed to detect the family for address '$input_addr'." >&2; return 1 ;;
		inet ) addr_len=32; chunk_len=16; addr_regex="$ipv4_regex" ;;
		inet6 ) addr_len=128; chunk_len=32; addr_regex="$ipv6_regex" ;;
		* ) echo "trim_subnet: invalid family '$family'." >&2; return 1 ;;
	esac

	# validate mask bits
	case $(( (maskbits<8) | (maskbits>addr_len)  )) in 1)
		echo "trim_subnet: Error: invalid $family mask bits '$maskbits'." >&2; return 1
	esac

	test_ip_route_get "$family" || return 1

	validate_ip "${input_addr}" "$addr_regex" || return 1

	# convert ip to hex number
	ip_hex="$(ip_to_hex "$input_addr" "$family")" || return 1
	mask_hex="$(generate_mask "$maskbits" $addr_len)" || return 1

	# perform bitwise AND on the ip address and the mask
	newip_hex="$(bitwise_and "$ip_hex" "$mask_hex" "$maskbits" $addr_len $chunk_len)" || return 1
	hex_to_ip "$newip_hex" "$family" "new_ip" || return 1

	subnet="$new_ip/$maskbits"

	validate_ip "$new_ip" "$addr_regex" && { printf "%s\n" "$subnet"; return 0; } || return 1
}


## Constants
# ipv4 regex taken from here and modified for ERE matching:
# https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
# the longer ("alternative") ipv4 regex from the top suggestion performs about 40x faster on a slow CPU with ERE grep than the shorter one
# ipv6 regex taken from the BanIP code and modified for ERE matching
# https://github.com/openwrt/packages/blob/master/net/banip/files/banip-functions.sh
ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4})(:[0-9a-f]{0,4}){2,7}'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
#maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'


## check dependencies
! command -v awk >/dev/null || ! command -v tr >/dev/null ||
! command -v grep >/dev/null || ! command -v ip >/dev/null &&
	{ echo "$me: Error: missing dependencies, can not proceed" >&2; exit 1; }

# test 'grep -E'
rv=0; rv1=0; rv2=0
printf "%s" "32" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null; rv1=$?
printf "%s" "0" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null; rv2=$?
rv=$((rv1 || ! rv2))
[ "$rv" -ne 0 ] && { echo "$me: Error: 'grep -E' command is not working correctly." >&2; exit 1; }
unset rv rv1 rv2



# to use or test functions from external sourcing script, export the $source_trim_subnet variable in that script
if [ -z "$source_trim_subnet" ]; then
	trim_subnet "$1" "$2" || exit 1
else return 0
fi
