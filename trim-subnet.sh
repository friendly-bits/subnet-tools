#!/bin/sh
# shellcheck disable=SC2154,SC2086,SC2018,SC2019,SC2015

# Copyright: friendly bits
# github.com/friendly-bits

# trim-subnet.sh

# trims an ip to given length (expressed in CIDR mask bits) and outputs the resulting subnet

# requires ip with mask bits in 1st arg. optional 2nd arg is ip family (inet or inet6).
# if not specified, auto-detects the ip family.

# the code is POSIX-compliant
# requires the 'ip' utility, grep with ERE support and tr.
# only tested with GNU variants, and only on Linux. should work on other Unixes.


#### Initial setup
export LC_ALL=C
set -f
me=$(basename "$0")
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
#debugmode=true

. "$script_dir/ip-regex.sh"


#### Functions

# 1 - ip
# 2 - family
# 3 - chunk length in bits
ip_to_hex() {
	ip="$1"; family="$2"; chunk_len_bits="$3"
	chunk_len_chars=$((chunk_len_bits/4))
	case "$family" in
		inet ) chunk_delim='.'; hex_flag='' ;;
		inet6 )
			chunk_delim=':'; hex_flag='0x'
			# expand ::
			case "$ip" in *::*)
				zeroes=":0:0:0:0:0:0:0:0:0"
				ip_tmp="$ip"
				while true; do
					case "$ip_tmp" in *:*) ip_tmp="${ip_tmp#*:}";; *) break; esac
					zeroes="${zeroes#??}"
				done
				# replace '::'
				ip="${ip%::*}$zeroes${ip##*::}"
				# prepend 0 if we start with :
				case "$ip" in :*) ip="0${ip}"; esac
			esac
	esac
	IFS="$chunk_delim"
	for chunk in $ip; do
		printf " 0x%0${chunk_len_chars}x" "$hex_flag$chunk"
	done
}

# 1 - input hex chunks
# 2 - family
# 3 - var name for output
hex_to_ip() {
	convert_failed() {  printf '%s\n' "hex_to_ip(): Error: failed to convert hex '$1' to ip." >&2; }
	family="$2"; out_var="$3"

	case "$family" in
		inet6 )
			_fmt_delim=':'
			ip="$(IFS=' ' printf "%x:" $1)" || { convert_failed "$1"; return 1; }
			## compress ipv6

			case "$ip" in :* ) ;; *) ip=":$ip"; esac
			# compress 0's across neighbor chunks
			for zeroes in ":0:0:0:0:0:0:0:0" ":0:0:0:0:0:0:0" ":0:0:0:0:0:0" ":0:0:0:0:0" ":0:0:0:0" ":0:0:0" ":0:0"; do
				case "$ip" in *$zeroes* )
					ip="${ip%%"$zeroes"*}::${ip#*"$zeroes"}"
					break
				esac
			done

			# trim leading colon if it's not a double colon
			case "$ip" in
				::*) ;;
				:*) ip="${ip#:}"
			esac
			;;
		inet) _fmt_delim='.'; ip="$(IFS=' ' printf "%d." $1)" || { convert_failed "$1"; return 1; }
	esac
	eval "$out_var"='${ip%$_fmt_delim}'
}

# 1 - mask bits
# 2 - ip length in bytes
# 3 - chunk length in bits
generate_mask() {
	maskbits="$1"
	ip_len_bytes="$2"
	chunk_len_bytes="$(($3/8))"

	bytes_done='' i='' sum=0 cur=128

	octets=$((maskbits / 8))
	frac=$((maskbits % 8))
	while true; do
		case ${#bytes_done} in "$octets") break; esac
		case $((${#bytes_done}%chunk_len_bytes==0)) in 1) printf ' 0x'; esac
		printf %s "ff"
		bytes_done="${bytes_done}1"
	done

	case "${#bytes_done}" in "$ip_len_bytes") ;; *)
		while true; do
			case ${#i} in "$frac") break; esac
			sum=$((sum + cur))
			cur=$((cur / 2))
			i="${i}1"
		done
		case "$((${#bytes_done}%chunk_len_bytes))" in 0) printf ' 0x'; esac
		printf "%02x" "$sum" || { printf '%s\n' "generate_mask: Error: failed to convert byte '$sum' to hex." >&2; return 1; }
		bytes_done="${bytes_done}1"

		while true; do
			case ${#bytes_done} in "$ip_len_bytes") break; esac
			case "$((${#bytes_done}%chunk_len_bytes))" in 0) printf ' 0x'; esac
			printf %s "00"
			bytes_done="${bytes_done}1"
		done
	esac
}


# 1 - ip's
# 2 - regex
validate_ip() {
	addr="$1"; ip_regex="$2"
	[ ! "$addr" ] && { echo "validate_ip: Error: received an empty ip address." >&2; return 1; }

	[ -z "$ip_route_get_disable" ] && {
		# using the 'ip route get' command to put the address through kernel's validation
		# it normally returns 0 if the ip address is correct and it has a route, 1 if the address is invalid
		# 2 if validation successful but for some reason it can't check the route
		for address in $addr; do
			ip route get "$address" 1>/dev/null 2>/dev/null
			case $? in 0|2) ;; *)
				{ printf '%s\n' "validate_ip: Error: ip address'$address' failed kernel validation." >&2; return 1; }
			esac
		done
	}

	## regex validation
	printf "%s\n" "$addr" | grep -vE "^$ip_regex$" > /dev/null
	[ $? != 1 ] && { printf '%s\n' "validate_ip: Error: one or more addresses failed regex validation: '$addr'." >&2; return 1; }
	:
}

# tests whether 'ip route get' command works for ip validation
# 1 - family
test_ip_route_get() {
	family="$1"
	case "$family" in
		inet ) legal_addr="127.0.0.1"; illegal_addr="127.0.0.256" ;;
		inet6 ) legal_addr="::1"; illegal_addr=":a:1" ;;
		* ) printf '%s\n' "test_ip_route_get: Error: invalid family '$family'" >&2; return 1
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

# calculates bitwise ip & mask, both represented as hex chunks, and outputs the result in the same format
# arguments:
# 1 - ip formatted as hex chunks
# 2 - mask formatted as hex chunks
# 3 - maskbits
# 4 - ip length in bits (32 for ipv4, 128 for ipv6),
# 5 - chunk size in bits used for calculation
bitwise_and() {
	ip="$1"; mask="$2"; maskbits="$3"; ip_len_bytes="$4"; chunk_len_bits="$5"
	chunk_len_chars=$((chunk_len_bits/4))

	IFS_OLD="$IFS"; IFS=' '; chunks_done=''; bits_done=0
	# copy ~ $maskbits bits
	for ip_chunk in $ip_hex; do
		[ $((bits_done + chunk_len_bits < maskbits)) = 0 ] && break
		printf ' %s' "$ip_chunk"
		bits_done=$((bits_done + chunk_len_bits))
		chunks_done="${chunks_done}1"
	done
	# calculate the next chunk if needed
	[ "$bits_done" != "$maskbits" ] && {
		set -- $mask
		chunks_done="${chunks_done}1"
		eval "mask_chunk=\"\${${#chunks_done}}\""

		printf " 0x%0${chunk_len_chars}x" $(( ip_chunk & mask_chunk ))
		bits_done=$((bits_done + chunk_len_bits))
	}

	# repeat 00 for every missing byte
	while [ "$bits_done" != "$ip_len_bits" ]; do
		[ $((bits_done%chunk_len_bits)) = 0 ] && printf ' 0x'
		printf %s "00"
		bits_done=$((bits_done + 8))
	done
	IFS="$IFS_OLD"
}

set_family_vars() {
	case "$family" in
		'') printf '%s\n' "set_family_vars: Error: failed to detect the family for address '$ip'." >&2; return 1 ;;
		inet ) ip_len_bits=32; chunk_len_bits=8; ip_regex="$ipv4_regex" ;;
		inet6 ) ip_len_bits=128; chunk_len_bits=16; ip_regex="$ipv6_regex" ;;
		* ) printf '%s\n' "set_family_vars: Error: invalid family '$family'." >&2; return 1 ;;
	esac
	ip_len_bytes=$((ip_len_bits/8))
}

trim_subnet() {
	# convert to lower case
	subnet="$(printf %s "$1" | tr 'A-Z' 'a-z')"
	[ "$2" ] && family="$(printf %s "$2" | tr 'A-Z' 'a-z')"

	case "$subnet" in */*) ;; *) printf '%s\n' "trim_subnet: Error: '$subnet' is not a valid subnet." >&2; return 1; esac
	# get mask bits
	maskbits="${subnet#*/}"
	case "$maskbits" in ''|*[!0-9]*)
		printf '%s\n' "trim_subnet: Error: '$subnet' is not a valid subnet." >&2; return 1
	esac
	# chop off mask bits
	ip="${subnet%%/*}"

	# detect the family
	if [ -z "$family" ]; then
		printf %s "$ip" | grep -E "^${ipv4_regex}$" > /dev/null && family="inet" ||
		{ printf %s "$ip" | grep -E "^${ipv6_regex}$" > /dev/null && family="inet6"; }
	fi

	set_family_vars

	# validate mask bits
	case $(( (maskbits<8) | (maskbits>ip_len_bits)  )) in 1)
		printf '%s\n' "trim_subnet: Error: invalid $family mask bits '$maskbits'." >&2; return 1
	esac

	test_ip_route_get "$family" || return 1

	validate_ip "$ip" "$ip_regex" || return 1

	# convert ip to hex
	ip_hex="$(ip_to_hex "$ip" "$family" "$chunk_len_bits")" || return 1
	mask_hex="$(generate_mask "$maskbits" "$ip_len_bytes" "$chunk_len_bits")" || return 1

	# perform bitwise AND on the ip address and the mask
	newip_hex="$(bitwise_and "$ip_hex" "$mask_hex" "$maskbits" "$ip_len_bytes" "$chunk_len_bits")" || return 1
	hex_to_ip "$newip_hex" "$family" "new_ip" || return 1

	subnet="$new_ip/$maskbits"

	validate_ip "$new_ip" "$ip_regex" && { printf "%s\n" "$subnet"; return 0; } || return 1
}


## check dependencies
! command -v tr >/dev/null || ! command -v grep >/dev/null || ! command -v ip >/dev/null &&
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
