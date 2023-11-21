#!/bin/sh
# shellcheck disable=SC2154,SC2034

# aggregate-subnets.sh

# Posix-compliant shell script which calculates an efficient configuration for subnets given as an input 
# by trimming down each input subnet to its mask bits and removing subnets that are encapsulated inside other subnets on the list.
# Designed for easier automated creation of firewall rules, but perhaps someone has a different application for this functionality.
# Utilizes the trim-subnet.sh script as a library.

# to check a specific family (inet or inet6), run with the '-f <family>' argument
# if run without the '-f <family>' argument, auto-detects families
# use the '-d' argument for debug
# besides the above, all other args are subnets to aggregate


#### Initial setup

#debugmode=true
export LC_ALL=C
me=$(basename "$0")
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
export source_trim_subnet="true"

# source the trim-subnet.sh script
# shellcheck disable=SC1091
. "$script_dir/trim-subnet.sh" || { echo "$me: Error: Can't source '$script_dir/trim-subnet.sh'." >&2; exit 1; }


## Simple args parsing
args=""
for arg in "$@"; do
	if [ "$arg" = "-d" ]; then debugmode="true"
	elif [ "$arg" = "-f" ]; then family_arg="check"
	elif [ "$family_arg" = "check" ]; then family_arg="$arg"
	else args="$args $arg"
	fi
done
[ "$family_arg" = "check" ] && { echo "Specify family with '-f'."; exit 1; }

set -- "$args"


#### Functions

aggregate_subnets() {
	family="$1"; input_subnets="$2"; subnets_hex=""; res_subnets=""

	case "$family" in
		inet ) addr_len=32; chunk_len=16; addr_regex="$ipv4_regex" ;;
		inet6 ) addr_len=128; chunk_len=32; addr_regex="$ipv6_regex" ;;
		* ) echo "aggregate_subnets(): invalid family '$family'." >&2; return 1 ;;
	esac

	# characters representing each chunk
	char_num=$((chunk_len / 4))

	# convert to newline-delimited list, remove duplicates from input, convert to lower case
	input_subnets="$(printf "%s" "$input_subnets" | tr ' ' '\n' | sort -u | awk '{print tolower($0)}')"
	input_ips="$(printf '%s' "$input_subnets" | cut -s -d/ -f1)" || \
			{ echo "aggregate_subnets(): Error: failed to process input '$input_subnets'." >&2; return 1; }
	validate_ip "$input_ips" "$addr_regex" || \
				{ echo "aggregate_subnets(): Error: failed to validate one or more of input addresses." >&2; return 1; }
	unset input_ips

	for subnet in $input_subnets; do
		# get mask bits
		maskbits="$(printf "%s" "$subnet" | cut -s -d/ -f2 )" || \
				{ echo "aggregate_subnets(): Error: failed to process subnet '$subnet'." >&2; return 1; }
		case "$maskbits" in ''|*[!0-9]*) echo "aggregate_subnets(): Error: input '$subnet' has no mask bits or it's not a number." >&2; return 1;; esac
		# chop off mask bits
		subnet="${subnet%/*}"

		# shellcheck disable=SC2086
		# validate mask bits
		if [ "$maskbits" -lt 8 ] || [ "$maskbits" -gt $addr_len ]; then
			echo "aggregate_subnets(): Error: invalid $family mask bits '$maskbits'." >&2; return 1; fi

		# convert ip address to hex number
		subnet_hex="$(ip_to_hex "$subnet" "$family")" || return 1
		# prepend mask bits
		subnets_hex="$maskbits/$subnet_hex$newline$subnets_hex"
	done

	# sort by mask bits, remove empty lines if any
	sorted_subnets_hex="$(printf "%s\n" "$subnets_hex" | sort -n | awk -F_ '$1{print $1}')"

	while [ -n "$sorted_subnets_hex" ]; do
		## trim the 1st (largest) subnet on the list to its mask bits

		# get first subnet from the list
		subnet1="$(printf "%s" "$sorted_subnets_hex" | head -n 1)"
		[ "$debugmode" ] && echo >&2
		[ "$debugmode" ] && echo "processing subnet: $subnet1" >&2

		# get mask bits
		maskbits="${subnet1%/*}"
		# chop off mask bits
		ip="${subnet1#*/}"

		# shellcheck disable=SC2086
		# generate mask if it's not been generated yet
		if eval [ -z "\$mask_${family}_${maskbits}" ]; then eval mask_${family}_${maskbits}="$(generate_mask "$maskbits" $addr_len)" || return 1; fi
		eval mask=\$mask_"${family}_${maskbits}"

		# shellcheck disable=SC2086
		# calculate ip & mask
		ip1="$(bitwise_and "$ip" "$mask" "$maskbits" $addr_len $chunk_len)" || return 1
		[ "$debugmode" ] && echo "calculated '$ip' & '$mask' = '$ip1'" >&2

		# remove current subnet from the list
		sorted_subnets_hex="$(printf "%s" "$sorted_subnets_hex" | tail -n +2)"
		remaining_subnets_hex="$sorted_subnets_hex"
		remaining_lines_cnt=$(printf '%s' "$remaining_subnets_hex" | wc -l)

		i=0
		# shellcheck disable=SC2086
		# iterate over all remaining subnets
		while [ $i -le $remaining_lines_cnt ]; do
			i=$((i+1))
			subnet2_hex="$(printf "%s" "$remaining_subnets_hex" | awk "NR==$i")"
			[ "$debugmode" ] && echo "comparing to subnet: '$subnet2_hex'" >&2

			if [ -n "$subnet2_hex" ]; then
				# chop off mask bits
				ip2="${subnet2_hex#*/}"

				ip2_differs=""; bytes_diff=0
				bits_processed=0; char_offset=0

				# shellcheck disable=SC2086
				# compare ~ $maskbits bits of ip1 and ip2
				while [ $((bits_processed + chunk_len)) -le $maskbits ]; do
					chunk_start=$((char_offset + 1))
					chunk_end=$((char_offset + char_num))

					ip1_chunk="$(printf "%s" "$ip1" | cut -c${chunk_start}-${chunk_end} )"
					ip2_chunk="$(printf "%s" "$ip2" | cut -c${chunk_start}-${chunk_end} )"

					[ "$debugmode" ] && echo "comparing chunks '$ip1_chunk' - '$ip2_chunk'" >&2

					bytes_diff=$((0x$ip1_chunk - 0x$ip2_chunk)) || \
								{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip1_chunk - 0x$ip2_chunk'." >&2; return 1; }
					# if there is any difference, no need to calculate further
					if [ $bytes_diff -ne 0 ]; then
						[ "$debugmode" ] && echo "difference found" >&2
						ip2_differs=true; break
					fi

					bits_processed=$((bits_processed + chunk_len))
					char_offset=$((char_offset + char_num))
				done

				# shellcheck disable=SC2086
				# if needed, calculate the next ip2 chunk and compare to ip1 chunk
				if [ $bits_processed -ne $maskbits ] && [ -z  "$ip2_differs" ]; then
					[ "$debugmode" ] && echo "calculating last chunk..." >&2
					chunk_start=$((char_offset + 1))
					chunk_end=$((char_offset + char_num))

					ip1_chunk="$(printf "%s" "$ip1" | cut -c${chunk_start}-${chunk_end} )"
					ip2_chunk="$(printf "%s" "$ip2" | cut -c${chunk_start}-${chunk_end} )"
					mask_chunk="$(printf "%s" "$mask" | cut -c${chunk_start}-${chunk_end} )"

					# bitwise $ip2_chunk & $mask_chunk
					ip2_chunk=$(printf "%0${char_num}x" $(( 0x$ip2_chunk & 0x$mask_chunk )) ) || \
						{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip2_chunk & 0x$mask_chunk'." >&2; return 1; }

					[ "$debugmode" ] && echo "comparing chunks '$ip1_chunk' - '$ip2_chunk'" >&2

					bytes_diff=$((0x$ip1_chunk - 0x$ip2_chunk)) || \
								{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip1_chunk - 0x$ip2_chunk'." >&2; return 1; }
					if [ $bytes_diff -ne 0 ]; then
						[ "$debugmode" ] && echo "difference found" >&2
						ip2_differs=true
					fi
				fi

				# if no differences found, subnet2 is encapsulated in subnet1 - remove subnet2 from the list
				if [ -z "$ip2_differs" ]; then
					[ "$debugmode" ] && echo "No difference found" >&2
					sorted_subnets_hex="$(printf "%s\n" "$sorted_subnets_hex" | grep -vx "$subnet2_hex")" || \
					{ [ -n "$sorted_subnets_hex" ] && { echo "aggregate_subnets(): Error: failed to remove '$subnet2_hex' from the list." >&2; return 1; }; }
				fi
			fi
		done

		# format from hex number back to ip
		ip1="$(hex_to_ip "$ip1" "$family")" || return 1
		# append mask bits and add current subnet to resulting list
		res_subnets="${ip1}/${maskbits}${newline}${res_subnets}"
	done

	output_ips="$(printf '%s' "$res_subnets" | cut -s -d/ -f1)"
	validate_ip "$output_ips" "$addr_regex" || \
		{ echo "aggregate_subnets(): Error: failed to validate one or more of output addresses." >&2; return 1; }
	printf "%s" "$res_subnets"
	return 0
}


#### Constants
newline='
'
ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}:?'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
subnet_regex_ipv4="${ipv4_regex}/${maskbits_regex_ipv4}"
subnet_regex_ipv6="${ipv6_regex}/${maskbits_regex_ipv6}"


#### Main

# convert to lower case
[ -n "$family_arg" ] && family_arg="$(printf "%s" "$family_arg" | awk '{print tolower($0)}')"

case "$family_arg" in
	inet) families="inet"; subnets_inet="$*" ;;
	inet6 ) families="inet6"; subnets_inet6="$*" ;;
	'' ) ;;
	* ) echo "$me: Error: invalid family '$family_arg'." >&2; exit 1 ;;
esac

# sort input subnets by family
if [ -z "$family_arg" ]; then
	subnets_inet="$(printf "%s" "$*" | tr ' ' '\n' | grep -E "^${subnet_regex_ipv4}$" | tr '\n' ' ')"
	subnets_inet6="$(printf "%s" "$*" | tr ' ' '\n' | grep -E "^${subnet_regex_ipv6}$" | tr '\n' ' ')"

	# trim extra whitespace
	subnets_inet="${subnets_inet% }"
	subnets_inet6="${subnets_inet6% }"

	[ -n "$subnets_inet" ] && families="inet"
	[ -n "$subnets_inet6" ] && families="$families inet6"
fi

# check for invalid args
invalid_args="$*"
for family in $families; do
	case "$family" in
		inet ) invalid_args="$(printf "%s" "$invalid_args" | tr ' ' '\n' | grep -vE "^${subnet_regex_ipv4}$" | tr '\n' ' ')" ;;
		inet6 ) invalid_args="$(printf "%s" "$invalid_args" | tr ' ' '\n' | grep -vE "^${subnet_regex_ipv6}$" | tr '\n' ' ')"
	esac
done

# trim extra whitespaces
invalid_args="${invalid_args% }"
invalid_args="${invalid_args# }"

[ -n "$invalid_args" ] && { echo "Error: These do not appear to be valid subnets for families '$families': '$invalid_args'" >&2; exit 1; }

rv_global=0
for family in $families; do
	test_ip_route_get "$family" || exit 1
	[ "$debugmode" ] && eval echo "Aggregating for family \'$family\'." >&2
	eval aggregate_subnets "$family" \"\$subnets_"$family"\"; rv_global=$((rv_global + $?))
done

exit $rv_global
