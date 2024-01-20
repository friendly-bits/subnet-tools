#!/bin/sh
# shellcheck disable=SC2018,SC2019

# Copyright: blunderful scripts
# github.com/blunderful-scripts

# detect-local-subnets.sh

# Unix shell script which uses standard utilities to detect local area ipv4 and ipv6 subnets, regardless of the device it's running on (router or host)
# Some heuristics are employed which are likely to work on Linux but for other Unixes, testing is recommended
# Requires the trim-subnet.sh script to process found ip addresses

# by default, outputs all found local ip addresses, and aggregated subnets
# to output only aggregated subnets (and no other text), run with the '-s' argument
# to only check a specific family (inet or inet6), run with the '-f <family>' argument
# '-d' option is for debug

export LC_ALL=C
set -f
me=$(basename "$0")
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/ip-regex.sh"

## Simple args parsing
args=''; debugmode=''
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


## Functions

# finds local subnets
# 1 - family
get_local_subnets() {
	family="$1"
	local_addresses="$(
		if [ "$family" = inet ]; then
			ip -f inet route show table local scope link |
			grep -v "[[:space:]]lo[[:space:]]" | grep -oE "dev[[:space:]]+[^[:space:]]+" | sed 's/^dev[[:space:]]*//g' | sort -u |
			while read -r iface; do
				ip -o -f inet addr show "$iface" | grep -oE "$subnet_regex_ipv4"
			done
		else
			ip -o -f inet6 addr show | grep -oE "(fd[0-9a-f]{0,2}:|fe80:)(([[:alnum:]:/])+)" | grep -oE "^$subnet_regex_ipv6$"
		fi
	)"

	[ -z "$local_addresses" ] &&
		{ printf '%s\n' "get_local_subnets(): Error detecting local addresses for family $family." >&2; return 1; }

	[ -z "$subnets_only" ] && printf '%s\n%s\n\n' "Local $family addresses:" "$local_addresses"

	local_subnets="$(sh "$script_dir/aggregate-subnets.sh" -f "$family" "$local_addresses")"; rv1=$?

	case $rv1 in
		0) [ -z "$subnets_only" ] && printf '%s\n' "Local $family subnets (aggregated):"
			case "$local_subnets" in
				'') [ -z "$subnets_only" ] && echo "None found." ;;
				*) printf '%s\n' "$local_subnets"
			esac
		;;
		*) printf '%s\n' "Error detecting $family subnets." >&2
	esac
	case "$subnets_only" in '') echo; esac

	return $rv1
}


## Main

[ -n "$family_arg" ] && family_arg="$(printf '%s' "$family_arg" | tr 'A-Z' 'a-z')"
case "$family_arg" in
	inet|inet6 ) families="$family_arg" ;;
	'' ) families="inet inet6" ;;
	* ) printf '%s\n' "$me: Error: invalid family '$family_arg'." >&2; exit 1 ;;
esac

rv=0
for family in $families; do
	get_local_subnets "$family"; rv=$((rv + $?))
done

exit $rv
