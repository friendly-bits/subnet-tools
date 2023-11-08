#!/bin/sh

# aggregate-subnets.sh

# Posix-compliant shell script which calculates an efficient configuration for subnets given as an input 
# by trimming down each input subnet to its mask bits and removing subnets that are encapsulated inside other subnets on the list.
# Designed for easier automated creation of firewall rules, but perhaps someone has a different application for this functionality.
# Utilizes the get-subnet.sh script as a library.


# arg 1 is family (inet or inet6)
# next args are subnets to aggregate, each enclosed in double quotes

#### Initial setup

export LC_ALL=C
me=$(basename "$0")
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
export source_get_subnet="true"

# source the get-subnet.sh script
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

	# convert ip address to bytes. ip_to_bytes() is in the sourced script
	subnet_bytes="$(ip_to_bytes "$input_addr" "$family")"
	# prepend mask bits
	subnets_bytes="$(printf "%s/%s\n%s\n" "${maskbits}" "${subnet_bytes}" "$subnets_bytes")"
done

# remove duplicates, then sort by mask bits
sorted_subnets_bytes="$(printf "%s\n" "$subnets_bytes" | sort -u | sort -n)"

newline='
'
OLDIFS="$IFS"

while [ -n "$sorted_subnets_bytes" ]; do
	# grab the 1st subnet
	subnet1_bytes="$(printf "%s\n" "$sorted_subnets_bytes" | head -n 1)"
	if [ -n "$subnet1_bytes" ]; then
		# get mask bits
		maskbits="$(printf "%s" "$subnet1_bytes" | cut -d/ -f1)"

		# chop off mask bits
		ip_bytes1="$(printf "%s" "$subnet1_bytes" | cut -d/ -f2)"

		# generate mask bytes
		mask_bytes="$(generate_mask "$maskbits")" || exit 1

		# remove current subnet from the initial list
		sorted_subnets_bytes="$(printf "%s\n" "$sorted_subnets_bytes"  | tail -n +2)"

		IFS="$newline"
		# iterate over all remaining subnets
		for subnet2_bytes in $sorted_subnets_bytes; do
			IFS="$OLDIFS"
			# chop off mask bits
			ip_bytes2="$(printf "%s" "$subnet2_bytes" | cut -d/ -f2)"
			if [ -n "$ip_bytes2" ]; then
				ip_byte2=""; bytes_diff=0
				for i in $(seq 1 $(( mask_len/8 )) ); do
					# perform bitwise AND on the 2nd address and the mask bytes of 1st address
					mask_byte="$(printf "%s" "$mask_bytes" | cut -d' ' -f "$i")"
					ip_byte2="$(printf "%s" "$ip_bytes2" | cut -d' ' -f "$i")"
					ip_byte2=$(( ip_byte2 & mask_byte ))

					# check for difference between current byte in subnet1 and subnet2
					ip_byte1="$(printf "%s" "$ip_bytes1" | cut -d' ' -f "$i")"
					bytes_diff=$((ip_byte1-ip_byte2))
					# if there is any difference, no need to calculate further
					[ $bytes_diff -ne 0 ] && break
				done

				# if no differences found, subnet2 is encapsulated in subnet1 - remove subnet2 from the list
				if [ $bytes_diff -eq 0 ]; then
					sorted_subnets_bytes="$(printf "%s\n" "$sorted_subnets_bytes" | grep -vx "$subnet2_bytes")"
				fi
			fi
		done
		IFS="$OLDIFS"

		# format from bytes back to ip
		subnet1="$(format_ip "$ip_bytes1" "$family")" || exit 1
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
