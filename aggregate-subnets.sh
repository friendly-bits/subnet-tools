#!/bin/sh
# shellcheck disable=SC2154,SC2034

# aggregate-subnets.sh

# Posix-compliant shell script which calculates an efficient configuration for subnets given as an input 
# by trimming down each input subnet to its mask bits and removing subnets that are encapsulated inside other subnets on the list.
# Designed for easier automated creation of firewall rules, but perhaps someone has a different application for this functionality.
# Utilizes the trim-subnet.sh script as a library.

# arg 1 is family (inet or inet6)
# next args are subnets to aggregate. for ipv6, enclose each subnet in double quotes

#### Initial setup

#debug=true
export LC_ALL=C
me=$(basename "$0")
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
export source_trim_subnet="true"

# convert to lower case and store in a variable
family="$(printf "%s" "$1" | awk '{print tolower($0)}')"; shift

# source the trim-subnet.sh script
# shellcheck disable=SC1091
. "$script_dir/trim-subnet.sh" || { echo "$me: Error: Can't source '$script_dir/trim-subnet.sh'." >&2; exit 1; }

# check dependencies
! command -v awk >/dev/null || ! command -v sed >/dev/null || ! command -v tr >/dev/null || \
! command -v grep >/dev/null || ! command -v ip >/dev/null || ! command -v cut >/dev/null && \
	{ echo "get_subnet(): Error: missing dependencies, can not proceed" >&2; exit 1; }

# test 'grep -E'
rv=0; rv1=0; rv2=0
printf "%s" "32" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null; rv1=$?
printf "%s" "0" | grep -E "^${maskbits_regex_ipv4}$" > /dev/null; rv2=$?
rv=$((rv1 || ! rv2))
[ "$rv" -ne 0 ] && { echo "get_subnet(): Error: 'grep -E' command is not working correctly on this machine." >&2; exit 1; }
unset rv rv1 rv2

test_ip_route_get


#### Constants
newline='
'
# chunk length in bits
chunk_len=32

# characters representing each chunk
char_num=$((chunk_len / 4))


#### Main

[ -z "$family" ] && { echo "$me: Specify family (inet or inet6) in 1st argument." >&2; exit 1; }

case "$family" in
	inet ) ip_bytes=4; mask_len=32; addr_regex="$ipv4_regex" ;;
	inet6 ) ip_bytes=16; mask_len=128; addr_regex="$ipv6_regex" ;;
	* ) echo "$me: Invalid family '$family'. Specify family (inet or inet6) in 1st argument." >&2; exit 1
esac

# remove duplicates from input, convert to lower case
input_subnets="$(printf "%s" "$*" | tr ' ' '\n' | sort -u | tr '\n' ' ' | awk '{print tolower($0)}')"

validate_ip "$(printf "%s" "$input_subnets" | awk -F/ '{print $1}')" || exit 1

for subnet in $input_subnets; do
	# get mask bits
	maskbits="$(printf "%s" "$subnet" | awk -F/ '{print $2}')"
	[ -z "$maskbits" ] && { echo "$me: Error: input '$subnet' has no mask bits." >&2; exit 1; }

	# chop off mask bits
	input_addr="$(printf "%s" "$subnet" | awk -F/ '{print $1}')"

	# validate mask bits
	if [ "$maskbits" -lt 8 ] || [ "$maskbits" -gt $mask_len ]; then echo "$me: Error: invalid $family mask bits '$maskbits'." >&2; exit 1; fi

	# convert ip address to hex. ip_to_hex() is in the sourced script
	subnet_hex="$(ip_to_hex "$input_addr" "$family")" || exit 1
	# prepend mask bits
	subnets_hex="$(printf "%s/%s\n%s" "$maskbits" "$subnet_hex" "$subnets_hex")"
done

# sort by mask bits, remove empty lines if any
sorted_subnets_hex="$(printf "%s\n" "$subnets_hex" | sort -n | awk -F_ '$1{print $1}')"

while [ -n "$sorted_subnets_hex" ]; do
	## trim the 1st (largest) subnet on the list to its mask bits

	# get the subnet
	subnet1="$(printf "%s" "$sorted_subnets_hex" | head -n 1)"
	[ "$debug" ] && echo >&2
	[ "$debug" ] && echo "processing subnet: $subnet1" >&2

	# get mask bits
	maskbits="$(printf "%s" "$subnet1" | awk -F/ '{print $1}')"

	# chop off mask bits
	ip1="$(printf "%s" "$subnet1" | cut -d/ -f2)"

	# generate mask
	mask="$(generate_mask "$maskbits")" || exit 1

	## perform bitwise AND on the ip and the mask

	# split input into whitespace-separated chunks
	ip_chunks="$(printf "%s" "$ip1" | sed 's/.\{'$char_num'\}/& /g;s/[ ]$//')"
	mask_chunks="$(printf "%s" "$mask" | sed 's/.\{'$char_num'\}/& /g;s/[ ]$//')"

	ip1=""; ip1_chunks=""; bits_processed=0
	for i in $(seq 1 $(( mask_len / chunk_len )) ); do
		mask_chunk="$(printf "%s" "$mask_chunks" | cut -d' ' -f "$i")"
		ip_chunk="$(printf "%s" "$ip_chunks" | cut -d' ' -f "$i")"
		ip_chunk="$(printf "%0${char_num}x" $(( 0x$ip_chunk & 0x$mask_chunk )) )" || \
			{ echo "$me: Error: failed to calculate '0x$ip_chunk & 0x$mask_chunk'." >&2; exit 1; }
		ip1="$ip1$(printf "%s" "${ip_chunk}")"
		ip1_chunks="$ip1_chunks $(printf "%s" "${ip_chunk}")"
		bits_processed=$((bits_processed + chunk_len))

		[ "$debug" ] && echo "ip1_chunks: '$ip1_chunks'" >&2

		# if we processed $maskbits bits already, no need to calculate further
		if [ "$bits_processed" -ge "$maskbits" ]; then
			bytes_missing=$(( (mask_len - bits_processed) /8 ))
			# repeat 00 for every missing byte
			for b in $(seq 1 $bytes_missing); do ip1="$ip1$(printf "%s" '00')"; done
			break
		fi
	done

	# remove leading whitespace
	ip1_chunks="${ip1_chunks# }"

	# remove current subnet from the list
	sorted_subnets_hex="$(printf "%s" "$sorted_subnets_hex" | tail -n +2)"
	remaining_subnets_hex="$sorted_subnets_hex"

	# iterate over all remaining subnets
	while [ -n "$remaining_subnets_hex" ]; do
		subnet2_hex=$(printf "%s" "$remaining_subnets_hex" | head -n 1)
		[ "$debug" ] && echo "comparing to subnet: '$subnet2_hex'" >&2

		if [ -n "$subnet2_hex" ]; then
			# chop off mask bits
			ip2="$(printf "%s" "$subnet2_hex" | cut -d/ -f2)"
			# split into whitespace-separated chunks
			ip2_chunks="$(printf "%s" "$ip2" | sed 's/.\{'$char_num'\}/& /g;s/[ ]$//')"
			[ "$debug" ] && echo "ip2_chunks: '$ip2_chunks'" >&2

			ip2_chunk=""; ip2_differs=""; bytes_diff=0; bits_processed=0

			for i in $(seq 1 $(( mask_len / chunk_len )) ); do
				ip1_chunk="$(printf "%s" "$ip1_chunks" | cut -d' ' -f "$i")"
				[ "$debug" ] && echo "ip1_chunk: '$ip1_chunk'" >&2

				# perform bitwise AND on the 2nd address and the mask of 1st address
				mask_chunk="$(printf "%s" "$mask_chunks" | cut -d' ' -f "$i")"
				ip2_chunk="$(printf "%s" "$ip2_chunks" | cut -d' ' -f "$i")"
				# bitwise AND on a chunk of subnet2 and corresponding chunk of mask from subnet1
				ip2_chunk=$(printf "%0${char_num}x" $(( 0x$ip2_chunk & 0x$mask_chunk )) ) || \
							{ echo "$me: Error: failed to calculate '0x$ip2_chunk & 0x$mask_chunk'." >&2; exit 1; }
				[ "$debug" ] && echo "mask_chunk: '$mask_chunk', ip2_chunk: '$ip2_chunk'" >&2

				# check for difference between current chunk in subnet1 and subnet2

				bytes_diff=$((0x$ip1_chunk - 0x$ip2_chunk)) || \
							{ echo "$me: Error: failed to calculate '0x$ip1_chunk - 0x$ip2_chunk'." >&2; exit 1; }
				# if there is any difference, no need to calculate further
				if [ $bytes_diff -ne 0 ]; then
					[ "$debug" ] && echo "difference found" >&2
					ip2_differs=true; break
				fi

				bits_processed=$((bits_processed + chunk_len))

				# if we processed $maskbits bits already, no need to calculate further
				[ "$bits_processed" -ge "$maskbits" ] && break
			done

			# if no differences found, subnet2 is encapsulated in subnet1 - remove subnet2 from the list
			if [ -z "$ip2_differs" ]; then
				[ "$debug" ] && echo "No difference found" >&2
				sorted_subnets_hex="$(printf "%s\n" "$sorted_subnets_hex" | grep -vx "$subnet2_hex")"
				chunks_processed=0
			fi
		fi
		remaining_subnets_hex="$(printf "%s" "$remaining_subnets_hex" | tail -n +2)"
	done

	# format from hex back to ip
	ip1="$(format_ip "$ip1" "$family")" || exit 1
	if validate_ip "$ip1"; then
		# append mask bits
		subnet1="$ip1/$maskbits"
		# add current subnet to resulting list
		res_subnets="${subnet1}${newline}${res_subnets}"
	else
		exit 1
	fi
done

printf "%s\n" "$res_subnets"
