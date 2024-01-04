#!/bin/sh
# shellcheck disable=SC2154,SC2034,SC2317

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
. "$script_dir/trim-subnet.sh" || { echo "$me: Error: Can't source '$script_dir/trim-subnet.sh'." >&2; exit 1; }


## Simple args parsing
args=''
for arg in "$@"; do
	case "$arg" in
		-s ) subnets_only="true" ;;
		-d ) export debugmode="true" ;;
		-f ) family_arg="check" ;;
		* ) case "$family_arg" in check) family_arg="$arg" ;; *) args="$args $arg"; esac
	esac
done
[ "$family_arg" = "check" ] && { echo "Specify family with '-f'." >&2; exit 1; }

set -- "$args"


#### Functions

debugprint() {
	case "$debugmode" in '') ;; *) printf '%s\n' "$1" >&2; esac
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
		case "$maskbits" in ''|*[!0-9]*) echo "aggregate_subnets: Error: input '$subnet' has no mask bits or it's not a number." >&2; return 1;; esac
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
		debugprint "processing subnet: $subnet1"

		# get mask bits
		maskbits="${subnet1%/*}"
		# chop off mask bits
		ip="${subnet1#*/}"

		# generate mask if it's not been generated yet
		eval "mask=\"\$mask_${family}_${maskbits}\""
		case "$mask" in '')
			mask="$(generate_mask "$maskbits" $addr_len)" || return 1
			eval "mask_${family}_${maskbits}=\"$mask\""
		esac

		# calculate ip & mask
		ip1="$(bitwise_and "$ip" "$mask" "$maskbits" "$addr_len" "$chunk_len")" || return 1
		debugprint "calculated '$ip' & '$mask' = '$ip1'"

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

			ip2_differs=""; bytes_diff=0
			bits_processed=0; char_offset=0

			# compare ~ $maskbits bits of ip1 and ip2
			while true; do
				case $((bits_processed + chunk_len >= maskbits)) in 1) break; esac
				chunk_start=$((char_offset + 1))
				chunk_end=$((char_offset + char_num))

				ip1_chunk="$(substring "$ip1" "$chunk_start" "$chunk_end")"
				ip2_chunk="$(substring "$ip2" "$chunk_start" "$chunk_end")"

				debugprint "comparing chunks '$ip1_chunk' - '$ip2_chunk'"

				bytes_diff=$((0x$ip1_chunk - 0x$ip2_chunk)) ||
					{ echo "aggregate_subnets(): Error: failed to calculate '0x$ip1_chunk - 0x$ip2_chunk'." >&2; return 1; }
				# if there is any difference, no need to calculate further
				case "$bytes_diff" in 0) ;; *)
#						debugprint "difference found"
					ip2_differs=true; break
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


#### Constants
newline='
'
ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}:?'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
subnet_regex_ipv4="${ipv4_regex}\/${maskbits_regex_ipv4}"
subnet_regex_ipv6="${ipv6_regex}\/${maskbits_regex_ipv6}"
subnet_regex_ipv4_grep="${ipv4_regex}/${maskbits_regex_ipv4}"
subnet_regex_ipv6_grep="${ipv6_regex}/${maskbits_regex_ipv6}"


#### Main

# convert to lower case
[ -n "$family_arg" ] && family_arg="$(printf "%s" "$family_arg" | tr 'A-Z' 'a-z')"

case "$family_arg" in
	inet) families="inet"; subnets_inet="$*" ;;
	inet6 ) families="inet6"; subnets_inet6="$*" ;;
	'' ) ;;
	* ) echo "$me: Error: invalid family '$family_arg'." >&2; exit 1 ;;
esac

# sort input subnets by family
if [ -z "$family_arg" ]; then
	subnets_inet="$(printf "%s" "$*" | tr ' ' '\n' | grep -E "^${subnet_regex_ipv4_grep}$" | tr '\n' ' ')"
	subnets_inet6="$(printf "%s" "$*" | tr ' ' '\n' | grep -E "^${subnet_regex_ipv6_grep}$" | tr '\n' ' ')"

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
	# debugprint "Aggregating for family '$family'."
	eval "aggregate_subnets \"$family\" \"\$subnets_$family\""; rv_global=$((rv_global + $?))
done

exit $rv_global
