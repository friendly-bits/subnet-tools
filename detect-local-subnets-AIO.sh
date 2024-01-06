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
debugmode=''
for arg in "$@"; do
	case "$arg" in
		-s ) subnets_only="true" ;;
		-d ) debugmode="true" ;;
		-f ) families_arg="check" ;;
		* ) case "$families_arg" in check) families_arg="$arg"; esac
	esac
done
[ "$families_arg" = "check" ] && { echo "Specify family with '-f'." >&2; exit 1; }


## Functions

debugprint() {
	case "$debugmode" in '') ;; *) printf '%s\n' "$1" >&2; esac
}

# outputs N-th element from input
# 1 - input string
# 2 - element num. (1-based)
# 3 - delimiter
# 4 - var name for output
get_nth_el() {
	line_ind="$2"; __out_var="$4"
	__IFS_OLD="$IFS"; IFS="$3"; set -f
	# shellcheck disable=SC2086
	set -- $1
	IFS="$__IFS_OLD"; set +f
	eval "$__out_var=\"\$$line_ind\""
}

# generates a mask represented as a whitespace-separated chunks of hex number
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
		case $((bytes_done!=0 && bytes_done%chunk_len_bytes==0)) in 1) printf '%s' "$delim"; esac
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
		case "$((bytes_done%chunk_len_bytes))" in 0) printf '%s' "$delim"; esac
		printf "%02x" "$sum" || { echo "generate_mask: Error: failed to convert byte '$sum' to hex." >&2; return 1; }
		bytes_done=$((bytes_done + 1))

		while true; do
			case "$bytes_done" in "$mask_bytes") break; esac
			case "$((bytes_done%chunk_len_bytes))" in 0) printf '%s' "$delim"; esac
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

# outpus whitespace-separated hex chunks
# 1 - ip
# 2 - family
ip_to_hex() {
	convert_ip() {
		IFS="$4"
		chunks_done=0
		source_chunk_len_bytes=$(($2/2))
		for source_chunk in $ip; do
			case $((chunks_done!=0 && chunks_done*source_chunk_len_bytes%chunk_len_bytes==0)) in 1) printf '%s' "$delim"; esac
			printf "%0${2}x" "$3$source_chunk" ||
				{ echo "ip_to_hex(): Error: failed to convert chunk '0x$source_chunk'." >&2; return 1; }
			chunks_done=$((chunks_done+1))
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

			# convert to hex chunks
			convert_ip "$ip" "4" "0x" ':'
	esac
}

# 1 - input hex number
# 2 - family
# 3 - var name for output
hex_to_ip() {
	convert_hex() {
		IFS_OLD="$IFS"; IFS="$delim"
		for chunk in $hex; do
			while true; do
				case "$chunk" in '') break; esac
				printf '%.*s\n' "${#3}" "$chunk"
				chunk="${chunk#$3}"
			done
		done |
		while IFS="$IFS_OLD" read -r chunk; do	printf "%$2" "0x$chunk" ||
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
	family="$1"; input_subnets="$2"; res_subnets=''; res_ips=''

	case "$family" in
		inet ) addr_len=32; chunk_len_bits=16; addr_regex="$ipv4_regex" ;;
		inet6 ) addr_len=128; chunk_len_bits=32; addr_regex="$ipv6_regex" ;;
		* ) echo "aggregate_subnets: invalid family '$family'." >&2; return 1
	esac

	chunk_len_bytes=$((chunk_len_bits / 8))
	chunk_len_chars=$((chunk_len_bytes*2))

	# convert to newline-delimited list, remove duplicates from input, convert to lower case
	input_subnets="$(printf "%s" "$input_subnets" | tr ' ' '\n' | sort -u | tr 'A-Z' 'a-z')"
	input_ips=''
	for input_subnet in $input_subnets; do
		input_ips="$input_ips${input_subnet%%/*}$newline"
	done
	validate_ip "${input_ips%"$newline"}" "$addr_regex" ||
		{ echo "aggregate_subnets(): Error: failed to validate one or more of input addresses." >&2; return 1; }
	unset input_ips

	# convert to hex, prepend mask bits, sort by mask bits
	sorted_subnets_hex=$(
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
			case $(( (maskbits<8) | (maskbits>addr_len) )) in 1)
				echo "aggregate_subnets(): Error: invalid $family mask bits '$maskbits'." >&2; return 1
			esac

			printf '%s' "$maskbits/"
			ip_to_hex "$subnet" "$family"
			printf '\n'
		done | sort -n
	)

	while true; do
		case "$sorted_subnets_hex" in '') break; esac

		## trim the 1st (largest) subnet on the list to its mask bits

		# get first subnet from the list
		get_nth_el "$sorted_subnets_hex" 1 "$newline" subnet1_hex
#		debugprint "processing subnet: $subnet1_hex"

		# get mask bits
		maskbits="${subnet1_hex%/*}"
		# chop off mask bits
		ip_hex="${subnet1_hex#*/}"

		# generate mask if it's not been generated yet
		eval "mask=\"\$mask_${family}_${maskbits}\""
		case "$mask" in '')
			mask="$(generate_mask "$maskbits" "$addr_len")" || return 1
			eval "mask_${family}_${maskbits}=\"$mask\""
		esac
		
		# calculate ip & mask

		bits_processed=0
		ip1_hex=$(
			# copy ~ $maskbits bits
			IFS="$delim"
			for hex_chunk in $ip_hex; do
				case $((bits_processed + chunk_len_bits > maskbits)) in 1) break; esac
				case $((bits_processed!=0 && bits_processed%chunk_len_bits==0)) in 1) printf '%s' "$delim"; esac
				printf '%s' "$hex_chunk"
				bits_processed=$((bits_processed + chunk_len_bits))
			done
			# calculate the next chunk if needed
			case "$bits_processed" in "$maskbits") ;; *)
				set -f
				# shellcheck disable=SC2086
				set -- $mask; set +f
				eval "mask_chunk=\"\$$((bits_processed/chunk_len_bits + 1))\""

				case $((bits_processed%chunk_len_bits==0)) in 1) printf '%s' "$delim"; esac
				printf "%0${chunk_len_chars}x" $(( 0x$hex_chunk & 0x$mask_chunk )) ||
					{ echo "aggregate_subnets: Error: failed to calculate '0x$hex_chunk & 0x$mask_chunk'." >&2; return 1; }
				bits_processed=$((bits_processed + chunk_len_bits))
			esac

			# repeat 00 for every missing byte
			while true; do
				case "$bits_processed" in "$addr_len") break; esac
				case $((bits_processed%chunk_len_bits==0)) in 1) printf '%s' "$delim"; esac
				printf '%s' "00"
				bits_processed=$((bits_processed + 8))
			done
		)
#		debugprint "calculated '$ip_hex' & '$mask' = '$ip1_hex'"

		# remove current subnet from the list
		IFS_OLD="$IFS"; IFS="$newline"; set -f
		# shellcheck disable=SC2086
		set -- $sorted_subnets_hex
		shift 1
		sorted_subnets_hex="$*"

		remaining_lines_cnt=$#
		IFS="$IFS_OLD"; set +f

		# format from hex number back to ip
		hex_to_ip "$ip1_hex" "$family" "res_ip"

		# append mask bits and add current subnet to resulting list
		res_subnets="${res_subnets}${res_ip}/${maskbits}${newline}"
		res_ips="${res_ips}${res_ip}${newline}"

		remaining_subnets_hex="$sorted_subnets_hex"
		i=0
		# iterate over all remaining subnets
		while true; do
			case "$i" in "$remaining_lines_cnt") break; esac
			i=$((i+1))
			get_nth_el "$remaining_subnets_hex" "$i" "$newline" subnet2_hex
#			debugprint "comparing to subnet: '$subnet2_hex'"
			# chop off mask bits
			ip2_hex="${subnet2_hex#*/}"

			bytes_diff=0; bits_processed=0

			# compare ~ $maskbits bits of ip1 and ip2
			IFS_OLD="$IFS"; IFS="$delim"
			for ip1_hex_chunk in $ip1_hex; do
				case $((bits_processed + chunk_len_bits >= maskbits)) in 1) break; esac
				get_nth_el "$ip2_hex" $((bits_processed/chunk_len_bits + 1)) "$delim" ip2_hex_chunk

#				debugprint "comparing chunks '$ip1_hex_chunk' - '$ip2_hex_chunk'"

				bytes_diff=$((0x$ip1_hex_chunk - 0x$ip2_hex_chunk)) ||
					{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip1_hex_chunk - 0x$ip2_hex_chunk'." >&2; return 1; }
				# if there is any difference, no need to calculate further
				case "$bytes_diff" in 0) ;; *)
#					debugprint "difference found"
					break
				esac

				bits_processed=$((bits_processed + chunk_len_bits))
			done
			IFS="$IFS_OLD"

			# if needed, calculate the next ip2 chunk and compare to ip1 chunk
			case "$bits_processed" in "$maskbits") continue; esac
			case "$bytes_diff" in 0) ;; *) continue; esac

#			debugprint "calculating last chunk..."
			get_nth_el "$ip2_hex" $((bits_processed/chunk_len_bits + 1)) "$delim" ip2_hex_chunk
			get_nth_el "$mask" $((bits_processed/chunk_len_bits + 1)) "$delim" mask_chunk

			# bitwise $ip2_hex_chunk & $mask_chunk
			ip2_hex_chunk=$(printf "%0${chunk_len_chars}x" $(( 0x$ip2_hex_chunk & 0x$mask_chunk )) ) ||
				{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip2_hex_chunk & 0x$mask_chunk'." >&2; return 1; }

#			debugprint "comparing chunks '$ip1_hex_chunk' - '$ip2_hex_chunk'"

			bytes_diff=$((0x$ip1_hex_chunk - 0x$ip2_hex_chunk)) ||
				{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip1_hex_chunk - 0x$ip2_hex_chunk'." >&2; return 1; }

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
			# and link-local addresses (fe80::)
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
# delim="$(printf '\35')"
delim="#"
ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4})(:[0-9a-f]{0,4}){2,7}'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
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
[ "$rv" != 0 ] && { echo "$me: Error: 'grep -E' command is not working correctly." >&2; exit 1; }
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
