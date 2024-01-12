#!/bin/sh

# detect-local-subnets-AIO.sh

# Unix shell script which uses standard utilities to detect local area ipv4 and ipv6 subnets, regardless of the device it's running on (router or host)
# Some heuristics are employed which are likely to work on Linux but for other Unixes, testing is recommended

# by default, outputs all found local ip addresses, and aggregated subnets
# to output only aggregated subnets (and no other text), run with the '-s' argument
# to only check a specific family (inet or inet6), run with the '-f <family>' argument
# running with the '-n' argument disables validation which speeds up the processing significantly, but the results are not as safe
# '-d' argument is for debug


#### Initial setup

export LC_ALL=C
me=$(basename "$0")
set -f

## Simple args parsing
debugmode=''
for arg in "$@"; do
	case "$arg" in
		-s ) subnets_only="true" ;;
		-n ) novalidation="true" ;;
		-d ) debugmode="true" ;;
		-f ) families_arg="check" ;;
		* ) case "$families_arg" in check) families_arg="$arg"; esac
	esac
done
case "$families_arg" in check) echo "Specify family with '-f'." >&2; exit 1; esac


## Functions

debugprint() {
	case "$debugmode" in '') ;; *) printf '%s\n' "$1" >&2; esac
}

# generates a mask represented as hex chunks
# 1 - CIDR bits
# 2 - address length in bytes
generate_mask() {
	# CIDR bits
	maskbits="$1"

	# address length (32 bits for ipv4, 128 bits for ipv6)
	addr_len_bytes="$2"

	bytes_done='' i='' sum=0 cur=128

	octets=$((maskbits / 8))
	frac=$((maskbits % 8))
	while true; do
		case ${#bytes_done} in "$octets") break; esac
		case $((${#bytes_done}%chunk_len_bytes==0)) in 1) printf ' 0x'; esac
		printf '%s' "ff"
		bytes_done="${bytes_done}1"
	done

	case "${#bytes_done}" in "$addr_len_bytes") ;; *)
		while true; do
			case ${#i} in "$frac") break; esac
			sum=$((sum + cur))
			cur=$((cur / 2))
			i="${i}1"
		done
		case "$((${#bytes_done}%chunk_len_bytes))" in 0) printf ' 0x'; esac
		printf "%02x" "$sum" || { echo "generate_mask: Error: failed to convert byte '$sum' to hex." >&2; return 1; }
		bytes_done="${bytes_done}1"

		while true; do
			case ${#bytes_done} in "$addr_len_bytes") break; esac
			case "$((${#bytes_done}%chunk_len_bytes))" in 0) printf ' 0x'; esac
			printf '%s' "00"
			bytes_done="${bytes_done}1"
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

	case "$ip_route_get_disable" in '')
		# using the 'ip route get' command to put the address through kernel's validation
		# it normally returns 0 if the ip address is correct and it has a route, 1 if the address is invalid
		# 2 if validation successful but for some reason it doesn't want to check the route ('permission denied')
		for address in $addr; do
			ip route get "$address" >/dev/null 2>/dev/null ||
				{ echo "validate_ip: Error: ip address'$address' failed kernel validation." >&2; return 1; }
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

# converts ip address to whitespace-separated hex chunks
# 1 - ip
# 2 - family
ip_to_hex() {
	ip="$1"; family="$2"
	case "$family" in
		inet ) chunk_delim='.'; hex_flag='' ;;
		inet6 )
			chunk_delim=':'; hex_flag='0x'
			# expand ::
			case "$ip" in *::*)
				exp_zeroes=":0:0:0:0:0:0:0:0:0"
				ip_tmp="$ip"
				while true; do
					case "$ip_tmp" in *:*) ip_tmp="${ip_tmp#*:}";; *) break; esac
					exp_zeroes="${exp_zeroes#:0}"
				done
				# replace '::'
				ip="${ip%::*}$exp_zeroes${ip##*::}"
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
	family="$2"; out_var="$3"
	ip="$(IFS=' ' printf "%$_fmt_id$_fmt_delim" $1)" ||
		{ echo "hex_to_ip(): Error: failed to convert hex to ip." >&2; return 1; }

	case "$family" in inet6 )
		## compress ipv6

		case "$ip" in :* ) ;; *) ip=":$ip"; esac
		# compress 0's across neighbor chunks
		for zero_chain in ":0:0:0:0:0:0:0:0" ":0:0:0:0:0:0:0" ":0:0:0:0:0:0" ":0:0:0:0:0" ":0:0:0:0" ":0:0:0" ":0:0"; do
			case "$ip" in
				*$zero_chain* )
					ip="${ip%%"$zero_chain"*}::${ip#*"$zero_chain"}"
					break
			esac
		done

		# trim leading colon if it's not a double colon
		case "$ip" in
			::*) ;;
			:*) ip="${ip#:}"
		esac
	esac
	eval "$out_var"='${ip%$_fmt_delim}'
}

# finds local subnets
# 1- family
get_local_subnets() {
	calc_failed() { echo "get_local_subnets: Error: failed to calculate '$1'." >&2; exit 1; }

	family="$1"; res_subnets=''; res_ips=''

	case "$family" in
		inet ) addr_len_bits=32; chunk_len_bits=8; addr_regex="$ipv4_regex"; _fmt_id='d'; _fmt_delim='.' ;;
		inet6 ) addr_len_bits=128; chunk_len_bits=16; addr_regex="$ipv6_regex"; _fmt_id='x'; _fmt_delim=':' ;;
		* ) echo "get_local_subnets: invalid family '$family'." >&2; return 1
	esac

	addr_len_bytes=$((addr_len_bits/8))
	chunk_len_bytes=$((chunk_len_bits/8))
	chunk_len_chars=$((chunk_len_bytes*2))

	sorted_subnets_hex=$(
		case "$family" in
			inet )
				# gets local interface names. filters by "scope link" because this should filter out WAN interfaces
				# then gets ipv4 addresses with mask bits, corresponding to local interfaces
				# awk finds the next string after 'inet', then validates the string as ipv4 address with mask bits
				ip -f inet route show table local scope link | grep -i -v ' lo ' |
				awk '{for(i=1; i<=NF; i++) if($i~/^dev$/) print $(i+1)}' | sort -u |
				while read -r iface; do
					ip -o -f inet addr show "$iface" |
						awk '{for(i=1; i<=NF; i++) if($i~/^inet$/ && $(i+1)~'"/^$subnet_regex_ipv4$/"') print $(i+1)}'
				done

				;;
			inet6 )
				# get local ipv6 addresses with mask bits
				# awk finds the next string after 'inet6', then filters for ULA (unique local addresses with prefix 'fdxx')
				# and link-local addresses (fe80::), then validates the string as ipv6 address with mask bits
				ip -o -f inet6 addr show |
				awk '{for(i=1; i<=NF; i++) if($i~/^inet6$/ && $(i+1)~/^fd[0-9a-f]{0,2}:|^fe80:/ && $(i+1)~'"\
					/^$subnet_regex_ipv6$/"') print $(i+1)}'
				;;
			* ) echo "get_local_subnets: invalid family '$family'." >&2; return 1
		esac | tr ' ' '\n' | sort -u | tr 'A-Z' 'a-z' |

		while read -r subnet; do
			case "$subnet" in */*) ;; *) echo "get_local_subnets: Error: '$subnet' is not a valid subnet." >&2; return 1; esac
			# get mask bits
			maskbits="${subnet#*/}"
			case "$maskbits" in ''|*[!0-9]*)
				echo "get_local_subnets: Error: input '$subnet' has no mask bits or it's not a number." >&2; return 1
			esac
			# chop off mask bits
			subnet="${subnet%%/*}"

			# validate mask bits
			case $(( (maskbits<8) | (maskbits>addr_len_bits) )) in 1)
				echo "get_local_subnets: Error: invalid $family mask bits '$maskbits'." >&2; return 1
			esac

			printf '%s' "$maskbits/"
			ip_to_hex "$subnet" "$family"
			printf '\n'
		done | sort -n
	)

	case "$sorted_subnets_hex" in '')
		echo "get_local_subnets(): Failed to detect local subnets for family $family." >&2; return 1
	esac

	sorted_subnets_hex="$sorted_subnets_hex$newline"
	while true; do
		case "$sorted_subnets_hex" in ''|"$newline") break; esac

		## trim the 1st (largest) subnet on the list to its mask bits

		# get the first subnet from the list
		IFS_OLD="$IFS"; IFS="$newline"
		# shellcheck disable=SC2086
		set -- $sorted_subnets_hex
		subnet1_hex="$1"

		# remove current subnet from the list
		shift 1
		sorted_subnets_hex="$*$newline"
		IFS="$IFS_OLD"

		# debugprint "processing subnet: $subnet1_hex"

		# get mask bits
		maskbits="${subnet1_hex%/*}"
		# chop off mask bits
		ip_hex="${subnet1_hex#*/}"

		# generate mask if it's not been generated yet
		eval "mask=\"\$mask_${family}_${maskbits}\""
		case "$mask" in '')
			mask="$(generate_mask "$maskbits" "$addr_len_bytes")" || return 1
			eval "mask_${family}_${maskbits}=\"$mask\""
		esac
		
		# calculate ip & mask

		bits_processed=0
		ip1_hex=$(
			# copy ~ $maskbits bits
			IFS=' '; chunks_processed=''
			for hex_chunk in $ip_hex; do
				case $((bits_processed + chunk_len_bits < maskbits)) in 0) break; esac
				printf ' %s' "$hex_chunk"
				bits_processed=$((bits_processed + chunk_len_bits))
				chunks_processed="${chunks_processed}1"
			done
			# calculate the next chunk if needed
			case "$bits_processed" in "$maskbits") ;; *)
				# shellcheck disable=SC2086
				set -- $mask
				chunks_processed="${chunks_processed}1"
				eval "mask_chunk=\"\${${#chunks_processed}}\""

				# shellcheck disable=SC2154
				printf " 0x%0${chunk_len_chars}x" $(( hex_chunk & mask_chunk )) || calc_failed "$hex_chunk & $mask_chunk"
				bits_processed=$((bits_processed + chunk_len_bits))
			esac

			# repeat 00 for every missing byte
			while true; do
				case "$bits_processed" in "$addr_len_bits") break; esac
				case $((bits_processed%chunk_len_bits==0)) in 1) printf ' 0x'; esac
				printf '%s' "00"
				bits_processed=$((bits_processed + 8))
			done
		)
		# debugprint "calculated '$ip_hex' & '$mask' = '$ip1_hex'"

		# format from hex number back to ip
		hex_to_ip "$ip1_hex" "$family" "res_ip"

		# shellcheck disable=SC2154
		# append mask bits and add current subnet to resulting list
		res_subnets="${res_subnets}${res_ip}/${maskbits}${newline}"
		res_ips="${res_ips}${res_ip}${newline}"

		IFS="$newline"
		# iterate over all remaining subnets
		for subnet2_hex in $sorted_subnets_hex; do
#			debugprint "comparing to subnet: '$subnet2_hex'"
			# chop off mask bits
			ip2_hex="${subnet2_hex#*/}"

			bytes_diff=0; bits_processed=0; chunks_processed=''

			# compare ~ $maskbits bits of ip1 and ip2
			IFS=' '
			for ip1_hex_chunk in $ip1_hex; do
				case $((bits_processed + chunk_len_bits < maskbits)) in 0) break; esac
				bits_processed=$((bits_processed + chunk_len_bits))
				chunks_processed="${chunks_processed}1"

				# shellcheck disable=SC2086
				set -- $ip2_hex
				eval "ip2_hex_chunk=\"\${${#chunks_processed}}\""

#				debugprint "comparing chunks '$ip1_hex_chunk' - '$ip2_hex_chunk'"

				# shellcheck disable=SC2154
				bytes_diff=$((ip1_hex_chunk - ip2_hex_chunk)) || calc_failed "$ip1_hex_chunk - $ip2_hex_chunk"
				# if there is any difference, no need to calculate further
				case "$bytes_diff" in 0) ;; *)
#					debugprint "difference found"
					break
				esac

			done

			# if needed, calculate the next ip2 chunk and compare to ip1 chunk
			case "$bits_processed" in "$maskbits") continue; esac
			case "$bytes_diff" in 0) ;; *) continue; esac

#			debugprint "calculating last chunk..."
			chunks_processed="${chunks_processed}1"

			# shellcheck disable=SC2086
			set -- $ip2_hex
			eval "ip2_hex_chunk=\"\${${#chunks_processed}}\""
			# shellcheck disable=SC2086
			set -- $mask
			eval "mask_chunk=\"\${${#chunks_processed}}\""

			bytes_diff=$((ip1_hex_chunk - (ip2_hex_chunk & mask_chunk) )) || calc_failed

			# if no differences found, subnet2 is encapsulated in subnet1 - remove subnet2 from the list
			case "$bytes_diff" in 0)
#				debugprint "No difference found"
				sorted_subnets_hex="${sorted_subnets_hex%%"$subnet2_hex$newline"*}${sorted_subnets_hex#*"$subnet2_hex$newline"}"
			esac
		done
		IFS="$IFS_OLD"
	done

	case "$novalidation" in '') validate_ip "${res_ips%"$newline"}" "$addr_regex" ||
		{ echo "get_local_subnets: Error: failed to validate one or more of output addresses." >&2; return 1; }; esac

	case "$subnets_only" in '') printf '%s\n' "Local $family subnets (aggregated):"; esac
	# shellcheck disable=SC2154
	case "$res_subnets" in
		'') [ -z "$subnets_only" ] && echo "None found." ;;
		*) printf "%s" "$res_subnets"
	esac
	case "$subnets_only" in '') echo; esac

	return 0
}


## Constants
newline='
'
# delim="$(printf '\35')"
ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4})(:[0-9a-f]{0,4}){2,7}'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
subnet_regex_ipv4="${ipv4_regex}\/${maskbits_regex_ipv4}"
subnet_regex_ipv6="${ipv6_regex}\/${maskbits_regex_ipv6}"


## Checks

case "$novalidation" in '') 
	# check dependencies
	! command -v awk >/dev/null || ! command -v tr >/dev/null ||
	! command -v grep >/dev/null || ! command -v ip >/dev/null &&
		{ echo "$me: Error: missing dependencies, can not proceed" >&2; exit 1; }

	# test 'grep -E'
	if ! printf "%s" "32" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null ||
		printf "%s" "0" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null; then
			echo "$me: Error: 'grep -E' command is not working correctly." >&2; exit 1
	fi
esac

## Main

case "$families_arg" in *?*) families_arg="$(printf '%s' "$families_arg" | tr 'A-Z' 'a-z')"; esac
case "$families_arg" in
	inet|inet6|'inet inet6'|'inet6 inet' ) families="$families_arg" ;;
	''|'ipv4 ipv6'|'ipv6 ipv4' ) families="inet inet6" ;;
	ipv4 ) families="inet" ;;
	ipv6 ) families="inet6" ;;
	* ) echo "$me: Error: invalid family '$families_arg'." >&2; exit 1 ;;
esac

rv_global=0
for family in $families; do
	case "$novalidation" in '') test_ip_route_get "$family" || return 1; esac
	get_local_subnets "$family"; rv_global=$((rv_global + $?))
done

exit $rv_global
