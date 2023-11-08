#!/bin/sh
# shellcheck disable=SC2154,SC2034

# aggregate-subnets.sh

# Posix-compliant shell script which calculates an efficient configuration for subnets given as an input 
# by trimming down each input subnet to its mask bits and removing subnets that are encapsulated inside other subnets on the list.
# Designed for easier automated creation of firewall rules, but perhaps someone has a different application for this functionality.
# Utilizes the get-subnet.sh script as a library.


# arg 1 is family (inet or inet6)
# next args are subnets to aggregate. for ipv6, enclose each subnet in double quotes


#### Initial setup

#debug=true
export LC_ALL=C
me=$(basename "$0")
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
export source_get_subnet="true"

# source the get-subnet.sh script
# shellcheck disable=SC1091
. "$script_dir/get-subnet.sh" || { echo "$me: Error: Can't source '$script_dir/get-subnet.sh'." >&2; exit 1; }

# 1st arg is family
family="$1"; shift

[ -z "$family" ] && { echo "$me: Specify family (inet or inet6) in 1st argument." >&2; exit 1; }

case "$family" in
	inet ) mask_len=32; addr_regex="$ipv4_regex" ;;
	inet6 ) mask_len=128; addr_regex="$ipv6_regex" ;;
	* ) echo "$me: Invalid family '$family'. Specify family (inet or inet6) in 1st argument." >&2; exit 1
esac

# remove duplicates from input and store in a variable
input_subnets="$(printf "%s" "$*" | sort -u)"

for in_subnet in $input_subnets; do
	# trim the subnet to its mask bits
	subnet="$(get_subnet "$in_subnet")" || { echo "$me: Error processing input '$in_subnet'." >&2; exit 1; }

	# get mask bits
	maskbits="$(printf "%s" "$subnet" | awk -F/ '{print $2}')"
	[ -z "$maskbits" ] && { echo "$me: Error: input '$subnet' has no mask bits." >&2; exit 1; }

	# chop off mask bits
	input_addr="$(printf "%s" "$subnet" | awk -F/ '{print $1}')"

	# convert ip address to hex. ip_to_hex() is in the sourced script
	subnet_hex="$(ip_to_hex "$input_addr" "$family")"
	# prepend mask bits
	subnets_hex="$(printf "%s/%s\n%s\n" "${maskbits}" "${subnet_hex}" "$subnets_hex")"
done

# remove duplicates, then sort by mask bits
sorted_subnets_hex="$(printf "%s\n" "$subnets_hex" | sort -u | sort -n)"

newline='
'
OLDIFS="$IFS"

[ "$debug" ] && echo "sorted_subnets_hex: '$sorted_subnets_hex'"

while [ -n "$sorted_subnets_hex" ]; do
	# grab the 1st subnet
	subnet1_hex="$(printf "%s\n" "$sorted_subnets_hex" | head -n 1)"
	if [ -n "$subnet1_hex" ]; then
		# get mask bits
		maskbits="$(printf "%s" "$subnet1_hex" | cut -d/ -f1)"

		# chop off mask bits
		ip1_chunks="$(printf "%s" "$subnet1_hex" | cut -d/ -f2)"

		# generate mask formatted as 4-bytes long hex chunks
		mask_chunks="$(generate_mask "$maskbits")" || exit 1

		[ "$debug" ] && echo "mask_chunks: '$mask_chunks'"

		# remove current subnet from the initial list
		sorted_subnets_hex="$(printf "%s\n" "$sorted_subnets_hex"  | tail -n +2)"

		IFS="$newline"
		# iterate over all remaining subnets
		for subnet2_hex in $sorted_subnets_hex; do
			IFS="$OLDIFS"
			# chop off mask bits
			ip2_chunks="$(printf "%s" "$subnet2_hex" | cut -d/ -f2)"
			if [ -n "$ip2_chunks" ]; then
				ip2_chunk=""; bytes_diff=0
				for i in $(seq 1 $(( mask_len/32 )) ); do
					# perform bitwise AND on the 2nd address and the mask of 1st address
					mask_chunk="$(printf "%s" "$mask_chunks" | cut -d' ' -f "$i")"
					ip2_chunk="$(printf "%s" "$ip2_chunks" | cut -d' ' -f "$i")"
					[ "$debug" ] && echo "mask_chunk: '$mask_chunk', ip2_chunk: '$ip2_chunk'"
					# bitwise AND on a chunk of subnet2 and corresponding chunk of mask from subnet1
					ip2_chunk=$(printf "%08x" $(( 0x$ip2_chunk & 0x$mask_chunk )) )

					# check for difference between current chunk in subnet1 and subnet2
					ip1_chunk="$(printf "%s" "$ip1_chunks" | cut -d' ' -f "$i")"
					[ "$debug" ] && echo "ip1_chunk: '$ip1_chunk'"
					bytes_diff=$((0x$ip1_chunk - 0x$ip2_chunk))
					# if there is any difference, no need to calculate further
					if [ $bytes_diff -ne 0 ]; then
						[ "$debug" ] && echo "difference found" >&2
						break
					fi
				done

				# if no differences found, subnet2 is encapsulated in subnet1 - remove subnet2 from the list
				if [ $bytes_diff -eq 0 ]; then
					[ "$debug" ] && echo "No difference found" >&2
					sorted_subnets_hex="$(printf "%s\n" "$sorted_subnets_hex" | grep -vx "$subnet2_hex")"
				fi
			fi
		done
		IFS="$OLDIFS"

		ip1_merged="$(printf "%s" "$ip1_chunks" | tr -d ' ')"
		[ "$debug" ] && echo "ip1_merged: '$ip1_merged'" >&2
		# format from bytes back to ip
		subnet1="$(format_ip "$ip1_merged" "$family")" || exit 1
		[ "$debug" ] && echo "subnet1: '$subnet1'" >&2
		# add current subnet to resulting list
		if validate_ip "$subnet1"; then
			# append mask bits
			subnet1="${subnet1}/$maskbits"
			res_subnets="${subnet1}${newline}${res_subnets}"
		else
			exit 1
		fi
	fi
done

echo "Aggregated subnets:" >&2
printf "%s\n" "$res_subnets"
