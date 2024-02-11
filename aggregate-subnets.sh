#!/bin/sh
# shellcheck disable=SC2154,SC2317,SC2086,SC2018,SC2019,SC2048

# Copyright: blunderful scripts
# github.com/blunderful-scripts

# aggregate-subnets.sh

# Posix-compliant shell script which calculates an efficient configuration for subnets given as an input 
# by trimming down each input subnet to its mask bits and removing subnets that are encapsulated inside other subnets on the list.
# Designed for easier automated creation of firewall rules, but perhaps someone has a different application for this functionality.
# Utilizes the trim-subnet.sh script as a library.

# to check a specific family (inet or inet6), run with the '-f <family>' option
# if run without the '-f <family>' option, auto-detects families
# '-d' option is for debug
# besides the above, all other args are subnets to aggregate


#### Initial setup

#debugmode=true
export LC_ALL=C
set -f
me=$(basename "$0")
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source_trim_subnet="true"

. "$script_dir/trim-subnet.sh" || { printf '%s\n' "$me: Error: Can't source '$script_dir/trim-subnet.sh'." >&2; exit 1; }
. "$script_dir/ip-regex.sh"


## Simple args parsing
args=''
for arg in "$@"; do
	case "$arg" in
		-d ) export debugmode="true" ;;
		-f ) family_arg="check" ;;
		* ) case "$family_arg" in check) family_arg="$arg" ;; *) args="$args $arg"; esac
	esac
done
[ "$family_arg" = "check" ] && { echo "Specify family with '-f'." >&2; exit 1; }

set -- "$args"


#### Functions

debugprint() {
	case "$debugmode" in *?*) printf '%s\n' "$1" >&2; esac
}

aggregate_subnets() {
	family="$1"; input_subnets="$2"; subnets_hex=''; res_subnets=''; res_ips=''

	set_family_vars

	# convert to newline-delimited list, remove duplicates from input, convert to lower case
	input_subnets="$(printf %s "$input_subnets" | tr ' ' '\n' | sort -u | tr 'A-Z' 'a-z')"
	input_ips=''
	for input_subnet in $input_subnets; do
		input_ips="$input_ips${input_subnet%%/*}$_nl"
	done
	validate_ip "${input_ips%"$_nl"}" "$ip_regex" ||
				{ echo "aggregate_subnets: Error: failed to validate one or more of input addresses." >&2; return 1; }
	unset input_ips

	for subnet in $input_subnets; do
		case "$subnet" in */*) ;; *) printf '%s\n' "aggregate_subnets: Error: '$subnet' is not a valid subnet." >&2; return 1; esac
		# get mask bits
		maskbits="${subnet#*/}"
		case "$maskbits" in ''|*[!0-9]*) printf '%s\n' "aggregate_subnets: Error: input '$subnet' has no mask bits or it's not a number." >&2; return 1;; esac
		# chop off mask bits
		subnet="${subnet%%/*}"

		# validate mask bits
		case $(( (maskbits<8) | (maskbits>ip_len_bits)  )) in 1)
			printf '%s\n' "aggregate_subnets: Error: invalid $family mask bits '$maskbits'." >&2; return 1
		esac

		# convert ip address to hex number
		subnet_hex="$(ip_to_hex "$subnet" "$family" "$chunk_len_bits")"

		# prepend mask bits
		subnets_hex="$subnets_hex$maskbits/$subnet_hex$_nl"
	done

	# sort by mask bits
	subnets_hex="$(printf %s "$subnets_hex" | sort -n)"
	[ -z "$subnets_hex" ] && { printf '%s\n' "aggregate_subnets: Failed to detect local subnets for family $family." >&2; return 1; }

	subnets_hex="$subnets_hex$_nl"
	while true; do
		case "$subnets_hex" in ''|"$_nl") break; esac

		## trim the 1st (largest) subnet on the list to its mask bits

		# get the first subnet from the list
		IFS_OLD="$IFS"; IFS="$_nl"
		set -- $subnets_hex
		subnet1_hex="$1"

		# remove current subnet from the list
		shift 1
		subnets_hex="$*$_nl"
		IFS="$IFS_OLD"

#		debugprint "processing subnet: $subnet1_hex"

		# get mask bits
		maskbits="${subnet1_hex%/*}"
		# chop off mask bits
		ip_hex="${subnet1_hex#*/}"

		# generate mask if it's not been generated yet
		eval "mask=\"\$mask_${family}_${maskbits}\""
		[ ! "$mask" ] && {
			mask="$(generate_mask "$maskbits" "$ip_len_bytes" "$chunk_len_bits")" || return 1
			eval "mask_${family}_${maskbits}=\"$mask\""
		}

		# calculate ip & mask
		ip1_hex="$(bitwise_and "$ip_hex" "$mask" "$maskbits" "$ip_len_bytes" "$chunk_len_bits")" || return 1
#		debugprint "calculated '$ip_hex' & '$mask' = '$ip1_hex'"

		# format from hex number back to ip
		hex_to_ip "$ip1_hex" "$family" "res_ip"
#		debugprint "resulting ip: '$res_ip'"

		# append mask bits and add current subnet to resulting list
		res_subnets="${res_subnets}${res_ip}/${maskbits}${_nl}"
		res_ips="${res_ips}${res_ip}${_nl}"

		IFS="$_nl"
		# iterate over all remaining subnets
		for subnet2_hex in $subnets_hex; do
#			debugprint "comparing to subnet: '$subnet2_hex'"
			# chop off mask bits
			ip2_hex="${subnet2_hex#*/}"

			bytes_diff=0; bits_done=0; chunks_done=''

			# compare ~ $maskbits bits of ip1 and ip2
			IFS=' '
			for ip1_chunk in $ip1_hex; do
				[ $((bits_done + chunk_len_bits < maskbits)) = 0 ] && break
				bits_done=$((bits_done + chunk_len_bits))
				chunks_done="${chunks_done}1"

				set -- $ip2_hex
				eval "ip2_chunk=\"\${${#chunks_done}}\""

				bytes_diff=$((ip1_chunk - ip2_chunk))
#				debugprint "calculated chunks diff '$ip1_chunk' - '$ip2_chunk' = '$bytes_diff'"

				# if there is any difference, no need to calculate further
				[ "$bytes_diff" != 0 ] && break
			done

			# if needed, calculate the next ip2 chunk and compare to ip1 chunk
			[ "$bits_done" = "$maskbits" ] || [ "$bytes_diff" != 0 ] && continue

#			debugprint "calculating last chunk..."
			chunks_done="${chunks_done}1"

			set -- $ip2_hex
			eval "ip2_chunk=\"\${${#chunks_done}}\""
			set -- $mask
			eval "mask_chunk=\"\${${#chunks_done}}\""

			bytes_diff=$((ip1_chunk - (ip2_chunk & mask_chunk) ))
#			debugprint "calculated chunks diff '$ip1_chunk' - '($ip2_chunk & $mask_chunk)' = '$bytes_diff'"

			# if no differences found, subnet2 is encapsulated in subnet1 - remove subnet2 from the list
			[ "$bytes_diff" = 0 ] && subnets_hex="${subnets_hex%%"$subnet2_hex$_nl"*}${subnets_hex#*"$subnet2_hex$_nl"}"
		done
		IFS="$IFS_OLD"
	done

	validate_ip "${res_ips%"$_nl"}" "$ip_regex" ||
		{ echo "aggregate_subnets: Error: failed to validate one or more of output addresses." >&2; return 1; }

	printf %s "$res_subnets"

	return 0
}


#### Main
_nl='
'

[ -n "$family_arg" ] && family_arg="$(printf %s "$family_arg" | tr 'A-Z' 'a-z')"

case "$family_arg" in
	inet|ipv4) families="inet"; subnets_inet="$*" ;;
	inet6|ipv6) families="inet6"; subnets_inet6="$*" ;;
	'' ) ;;
	* ) printf '%s\n' "$me: Error: invalid family '$family_arg'." >&2; exit 1 ;;
esac

# auto-detect families
if [ -z "$family_arg" ]; then
	subnets_inet="$(printf %s "$*" | tr ' ' '\n' | grep -E "^${subnet_regex_ipv4}$" | tr '\n' ' ')"
	subnets_inet6="$(printf %s "$*" | tr ' ' '\n' | grep -E "^${subnet_regex_ipv6}$" | tr '\n' ' ')"

	subnets_inet="${subnets_inet% }"
	subnets_inet6="${subnets_inet6% }"

	[ -n "$subnets_inet" ] && families="inet"
	[ -n "$subnets_inet6" ] && families="$families inet6"
fi

# check for invalid args
for family in $families; do
	case "$family" in
		inet ) curr_regex="$subnet_regex_ipv4" ;;
		inet6 ) curr_regex="$subnet_regex_ipv6"
	esac
	subnets_regex="$subnets_regex($curr_regex)|"
done
subnets_regex="^(${subnets_regex%|})$"
invalid_args="$(printf '%s\n' $* | grep -vE "$subnets_regex" | tr '\n' ' ')"
# trim trailing whitespace
invalid_args="${invalid_args% }"

[ -n "$invalid_args" ] &&
	{ printf '%s\n' "Error: These do not appear to be valid subnets for families '$families': '$invalid_args'" >&2; exit 1; }

rv_global=0
for family in $families; do
	test_ip_route_get "$family" || exit 1
	eval "subnets=\"\$subnets_$family\""
	aggregate_subnets "$family" "$subnets"; rv_global=$((rv_global + $?))
done

exit $rv_global