#!/bin/sh

# detect-local-subnets.sh

# Unix shell script which uses standard utilities to detect local area ipv4 and ipv6 subnets, regardless of the device it's running on (router or host)
# Some heuristics are employed which are likely to work on Linux but for other Unixes, testing is recommended
# Requires the trim-subnet.sh script to process found ip addresses

# by default, outputs all found local ip addresses, and aggregated subnets
# to output only aggregated subnets (and no other text), run with the '-s' argument
# to only check a specific family (inet or inet6), run with the '-f <family>' argument
# use '-d' argument for debug

export LC_ALL=C
me=$(basename "$0")

## Simple args parsing
args=""
for arg in "$@"; do
	if [ "$arg" = "-s" ]; then subnets_only="true"
	elif [ "$arg" = "-d" ]; then export debugmode="true"
	elif [ "$arg" = "-f" ]; then family_arg="check"
	elif [ "$family_arg" = "check" ]; then family_arg="$arg"
	else args="$args $arg"
	fi
done
[ "$family_arg" = "check" ] && { echo "Specify family with '-f'." >&2; exit 1; }

set -- "$args"


## Functions

# attempts to find local subnets, requires family in 1st arg
get_local_subnets() {

	family="$1"

	case "$family" in
		inet )
			# get local interface names. filters by "scope link" because this should filter out WAN interfaces
			local_ifaces_ipv4="$(ip -f inet route show table local scope link | grep -i -v ' lo ' | \
				awk '{for(i=1; i<=NF; i++) if($i~/^dev$/) print $(i+1)}' | sort -u)"

			# get ipv4 addresses with mask bits, corresponding to local interfaces
			# awk prints the next string after 'inet'
			# grep validates the string as ipv4 address with mask bits
			local_addresses="$(
				for iface in $local_ifaces_ipv4; do
					ip -o -f inet addr show "$iface" | \
					awk '{for(i=1; i<=NF; i++) if($i~/^inet$/) print $(i+1)}' | grep -E "^$subnet_regex_ipv4$"
				done
			)"
		;;
		inet6 )
			# get local ipv6 addresses with mask bits
			# awk prints the next string after 'inet6'
			# 1st grep filters for ULA (unique local addresses with prefix 'fdxx') and link-nocal addresses (fe80::)
			# 2nd grep validates the string as ipv6 address with mask bits
			local_addresses="$(ip -o -f inet6 addr show | awk '{for(i=1; i<=NF; i++) if($i~/^inet6$/) print $(i+1)}' | \
				grep -E -i '^fd[0-9a-f]{0,2}:|^fe80:' | grep -E -i "^$subnet_regex_ipv6$")"
		;;
		* ) echo "get_local_subnets(): invalid family '$family'." >&2; return 1 ;;
	esac

	[ -z "$subnets_only" ] && {
		echo "Local $family addresses:"
		echo "$local_addresses"
		echo
	}

	local_subnets="$(sh aggregate-subnets.sh -f "$family" "$local_addresses")"; rv1=$?

	if [ $rv1 -eq 0 ]; then
		[ -z "$subnets_only" ] && echo "Local $family subnets (aggregated):"
		if [ -n "$local_subnets" ]; then printf "%s\n" "$local_subnets"; else echo "None found."; fi
	else
		echo "Error detecting $family subnets." >&2
	fi
	[ -z "$subnets_only" ] && echo

	return $rv1
}


## Main

ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}:?'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
subnet_regex_ipv4="${ipv4_regex}/${maskbits_regex_ipv4}"
subnet_regex_ipv6="${ipv6_regex}/${maskbits_regex_ipv6}"

[ -n "$family_arg" ] && family_arg="$(printf '%s' "$family_arg" | awk '{print tolower($0)}')"
case "$family_arg" in
	inet|inet6 ) families="$family_arg" ;;
	'' ) families="inet inet6" ;;
	* ) echo "$me: Error: invalid family '$family_arg'." >&2; exit 1 ;;
esac

rv=0
for family in $families; do
	get_local_subnets "$family"; rv=$((rv + $?))
done

exit $rv
