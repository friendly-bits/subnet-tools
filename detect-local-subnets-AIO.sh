#!/bin/sh

# detect-local-subnets-AIO.sh

# Unix shell script which uses standard utilities to detect local area ipv4 and ipv6 subnets, regardless of the device it's running on (router or host)
# Some heuristics are employed which are likely to work on Linux but for other Unixes, testing is recommended

# by default, outputs all found local ip addresses, and aggregated subnets
# to output only aggregated subnets (and no other text), run with the '-s' argument
# to only check a specific family (inet or inet6), run with the '-f <family>' argument
# '-d' argument is for debug


#### Initial setup

export LC_ALL=C
me=$(basename "$0")

## Simple args parsing
args=''; debugmode=''
for arg in "$@"; do
	case "$arg" in
		-s ) subnets_only="true" ;;
		-d ) debugmode="true" ;;
		-f ) families_arg="check" ;;
		* ) case "$families_arg" in check) families_arg="$arg" ;; *) args="$args $arg"; esac
	esac
done
[ "$families_arg" = "check" ] && { echo "Specify family with '-f'." >&2; exit 1; }

set -- "$args"


## Functions

debugprint() {
	case "$debugmode" in '') ;; *) printf '%s\n' "$1" >&2; esac
}

# 1 - input string
# 2 - start char pos.
# 3 - end char pos.
substring() {
	printf '%.*s' $(($3 - $2 + 1)) "${1#"$(printf '%.*s' $(($2 - 1)) "$1")"}"
}

# outputs N-th line from input
# 1 - input lines
# 2 - line num. (1-based)
# 3 - var name for output
get_nth_line() {
	in_lines="$1"; line_ind="$2"; out_var="$3"
	IFS_OLD="$IFS"; IFS="$newline"; set -f
	# shellcheck disable=SC2086
	set -- $in_lines
	IFS="$IFS_OLD"; set +f
	eval "$out_var=\"\$$line_ind\""
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

# 1 - ip
# 2 - family
ip_to_hex() {
	convert_ip() {
		IFS="$4"
		for chunk in $ip; do
			printf "%0${2}x" "$3$chunk" || { echo "ip_to_hex(): Error: failed to convert chunk '0x$chunk'." >&2; return 1; }
		done
	}

	ip="$1"; family="$2"
	case "$family" in
		inet ) convert_ip "$ip" "2" "" '.' ;;
		inet6 )
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

			# remove colons, pad with 0's and merge
			convert_ip "$ip" "4" "0x" ':'
	esac
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
				{ echo "hex_to_ip(): Error: failed to convert chunk '0x$chunk'." >&2; return 1; }
		done
	}

	hex="$1"; family="$2"; out_var="$3"
	case "$family" in
		inet )
			ip="$(convert_hex "$hex" "d." "??")"
			ip="${ip%.}"
			;;
		inet6 )
			ip="$(convert_hex "$hex" "x:" "????")"

			## compress ipv6
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
	esac
	eval "$out_var"='$ip'
}

# 1- family
# 2 - whitespace-separated list of subnets
aggregate_subnets() {
	family="$1"; input_subnets="$2"; subnets_hex=''; res_subnets=''; res_ips=''

	case "$family" in
		inet ) addr_len=32; chunk_len=16; addr_regex="$ipv4_regex" ;;
		inet6 ) addr_len=128; chunk_len=32; addr_regex="$ipv6_regex" ;;
		* ) echo "aggregate_subnets: invalid family '$family'." >&2; return 1
	esac

	# characters representing each chunk
	char_num=$((chunk_len / 4))

	# convert to newline-delimited list, remove duplicates from input, convert to lower case
	input_subnets="$(printf "%s" "$input_subnets" | tr ' ' '\n' | sort -u | tr 'A-Z' 'a-z')"
	input_ips=''
	for input_subnet in $input_subnets; do
		input_ips="$input_ips${input_subnet%%/*}$newline"
	done
	validate_ip "${input_ips%"$newline"}" "$addr_regex" ||
		{ echo "aggregate_subnets(): Error: failed to validate one or more of input addresses." >&2; return 1; }
	unset input_ips

	for subnet in $input_subnets; do
		case "$subnet" in */*) ;; *) echo "aggregate_subnets: Error: '$subnet' is not a valid subnet." >&2; return 1; esac
		# get mask bits
		maskbits="${subnet#*/}"
		case "$maskbits" in ''|*[!0-9]*)
			echo "aggregate_subnets: Error: input '$subnet' has no mask bits or it's not a number." >&2; return 1
		esac
		# chop off mask bits
		subnet="${subnet%%/*}"

		# validate mask bits
		case $(( (maskbits<8) | (maskbits>addr_len)  )) in 1)
			echo "aggregate_subnets(): Error: invalid $family mask bits '$maskbits'." >&2; return 1
		esac

		# convert ip address to hex number
		subnet_hex="$(ip_to_hex "$subnet" "$family")"

		# prepend mask bits
		subnets_hex="$maskbits/$subnet_hex$newline$subnets_hex"
	done

	# sort by mask bits
	sorted_subnets_hex="$(printf "%s" "$subnets_hex" | sort -n)"
	while true; do
		case "$sorted_subnets_hex" in '') break; esac

		## trim the 1st (largest) subnet on the list to its mask bits

		# get first subnet from the list
		get_nth_line "$sorted_subnets_hex" 1 subnet1
#		debugprint "processing subnet: $subnet1"

		# get mask bits
		maskbits="${subnet1%/*}"
		# chop off mask bits
		ip="${subnet1#*/}"

		# generate mask if it's not been generated yet
		eval "mask=\"\$mask_${family}_${maskbits}\""
		case "$mask" in '')
			mask="$(generate_mask "$maskbits" "$addr_len")" || return 1
			eval "mask_${family}_${maskbits}=\"$mask\""
		esac
		
		# calculate ip & mask

		bits_processed=0; char_offset=0
		ip1=$(
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
					{ echo "aggregate_subnets: Error: failed to calculate '0x$ip_chunk & 0x$mask_chunk'." >&2; return 1; }
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
		)
#		debugprint "calculated '$ip' & '$mask' = '$ip1'"

		# remove current subnet from the list
		IFS_OLD="$IFS"; IFS="$newline"; set -f
		# shellcheck disable=SC2086
		set -- $sorted_subnets_hex
		shift 1
		sorted_subnets_hex="$*"

		remaining_lines_cnt=$#
		IFS="$IFS_OLD"; set +f

		# format from hex number back to ip
		hex_to_ip "$ip1" "$family" "res_ip"

		# append mask bits and add current subnet to resulting list
		res_subnets="${res_subnets}${res_ip}/${maskbits}${newline}"
		res_ips="${res_ips}${res_ip}${newline}"

		remaining_subnets_hex="$sorted_subnets_hex"
		i=0
		# iterate over all remaining subnets
		while true; do
			case "$i" in "$remaining_lines_cnt") break; esac
			i=$((i+1))
			get_nth_line "$remaining_subnets_hex" "$i" subnet2_hex
#			debugprint "comparing to subnet: '$subnet2_hex'"
			# chop off mask bits
			ip2="${subnet2_hex#*/}"

			bytes_diff=0; bits_processed=0; char_offset=0

			# compare ~ $maskbits bits of ip1 and ip2
			while true; do
				case $((bits_processed + chunk_len >= maskbits)) in 1) break; esac
				chunk_start=$((char_offset + 1))
				chunk_end=$((char_offset + char_num))

				ip1_chunk="$(substring "$ip1" "$chunk_start" "$chunk_end")"
				ip2_chunk="$(substring "$ip2" "$chunk_start" "$chunk_end")"

#				debugprint "comparing chunks '$ip1_chunk' - '$ip2_chunk'"

				bytes_diff=$((0x$ip1_chunk - 0x$ip2_chunk)) ||
					{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip1_chunk - 0x$ip2_chunk'." >&2; return 1; }
				# if there is any difference, no need to calculate further
				case "$bytes_diff" in 0) ;; *)
#					debugprint "difference found"
					break
				esac

				bits_processed=$((bits_processed + chunk_len))
				char_offset=$((char_offset + char_num))
			done

			# if needed, calculate the next ip2 chunk and compare to ip1 chunk
			case "$bits_processed" in "$maskbits") continue; esac
			case "$bytes_diff" in 0) ;; *) continue; esac

#			debugprint "calculating last chunk..."
			chunk_start=$((char_offset + 1))
			chunk_end=$((char_offset + char_num))

			ip1_chunk="$(substring "$ip1" "$chunk_start" "$chunk_end")"
			ip2_chunk="$(substring "$ip2" "$chunk_start" "$chunk_end")"
			mask_chunk="$(substring "$mask" "$chunk_start" "$chunk_end")"

			# bitwise $ip2_chunk & $mask_chunk
			ip2_chunk=$(printf "%0${char_num}x" $(( 0x$ip2_chunk & 0x$mask_chunk )) ) ||
				{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip2_chunk & 0x$mask_chunk'." >&2; return 1; }

#			debugprint "comparing chunks '$ip1_chunk' - '$ip2_chunk'"

			bytes_diff=$((0x$ip1_chunk - 0x$ip2_chunk)) ||
				{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip1_chunk - 0x$ip2_chunk'." >&2; return 1; }

			# if no differences found, subnet2 is encapsulated in subnet1 - remove subnet2 from the list
			case "$bytes_diff" in 0)
#				debugprint "No difference found"
				sorted_subnets_hex="$(printf "%s\n" "$sorted_subnets_hex" | grep -vx "$subnet2_hex")"
			esac
		done
	done

	validate_ip "${res_ips%"$newline"}" "$addr_regex" ||
		{ echo "aggregate_subnets(): Error: failed to validate one or more of output addresses." >&2; return 1; }
	printf "%s" "$res_subnets"
	return 0
}

# finds local subnets
# 1 - family
get_local_subnets() {
	family="$1"
	case "$family" in
		inet )
			# get local interface names. filters by "scope link" because this should filter out WAN interfaces
			local_ifaces_ipv4="$(ip -f inet route show table local scope link | grep -i -v ' lo ' |
				awk '{for(i=1; i<=NF; i++) if($i~/^dev$/) print $(i+1)}' | sort -u)"
			case "$local_ifaces_ipv4" in '')
				echo "get_local_subnets(): Error detecting LAN network interfaces for ipv4." >&2; return 1
			esac

			# get ipv4 addresses with mask bits, corresponding to local interfaces
			# awk finds the next string after 'inet'
			# then validates the string as ipv4 address with mask bits
			local_addresses="$(
				for iface in $local_ifaces_ipv4; do
					ip -o -f inet addr show "$iface" |
						awk '{for(i=1; i<=NF; i++) if($i~/^inet$/ && $(i+1)~'"/^$subnet_regex_ipv4$/"') print $(i+1)}'
				done
			)"
		;;
		inet6 )
			# get local ipv6 addresses with mask bits
			# awk finds the next string after 'inet6', then filters for ULA (unique local addresses with prefix 'fdxx')
			# and link-nocal addresses (fe80::)
			# then validates the string as ipv6 address with mask bits
			local_addresses="$(ip -o -f inet6 addr show |
				awk '{for(i=1; i<=NF; i++) if($i~/^inet6$/ && $(i+1)~/^fd[0-9a-f]{0,2}:|^fe80:/ && $(i+1)~'"\
					/^$subnet_regex_ipv6$/"') print $(i+1)}' )"
		;;
		* ) echo "get_local_subnets: invalid family '$family'." >&2; return 1 ;;
	esac

	case "$local_addresses" in '')
		echo "get_local_subnets(): Error detecting local addresses for family $family." >&2; return 1
	esac

	case "$subnets_only" in '')
		printf '%s\n%s\n\n' "Local $family addresses:" "$local_addresses"
	esac

	local_subnets="$(aggregate_subnets "$family" "$local_addresses")"; rv1=$?

	case $rv1 in
		0) [ -z "$subnets_only" ] && printf '%s\n' "Local $family subnets (aggregated):"
			case "$local_subnets" in
				'') [ -z "$subnets_only" ] && echo "None found." ;;
				*) printf "%s\n" "$local_subnets"
			esac
		;;
		*) echo "Error detecting $family subnets." >&2
	esac
	case "$subnets_only" in '') echo; esac

	return $rv1
}


## Constants
newline='
'
ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}:?'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
subnet_regex_ipv4="${ipv4_regex}\/${maskbits_regex_ipv4}"
subnet_regex_ipv6="${ipv6_regex}\/${maskbits_regex_ipv6}"


## Checks

# check dependencies
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


## Main

[ -n "$families_arg" ] && families_arg="$(printf '%s' "$families_arg" | tr 'A-Z' 'a-z')"
case "$families_arg" in
	inet|inet6|'inet inet6'|'inet6 inet' ) families="$families_arg" ;;
	''|'ipv4 ipv6'|'ipv6 ipv4' ) families="inet inet6" ;;
	ipv4 ) families="inet" ;;
	ipv6 ) families="inet6" ;;
	* ) echo "$me: Error: invalid family '$families_arg'." >&2; exit 1 ;;
esac

rv_global=0
for family in $families; do
	test_ip_route_get "$family" || return 1
	get_local_subnets "$family"; rv_global=$((rv_global + $?))
done

exit $rv_global
