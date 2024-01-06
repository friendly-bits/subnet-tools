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
args=''; debugmode=''
for arg in "$@"; do
	case "$arg" in
		-s ) subnets_only="true" ;;
		-d ) export debugmode="true" ;;
		-f ) families_arg="check" ;;
		* ) case "$families_arg" in check) families_arg="$arg" ;; *) args="$args $arg"; esac
	esac
done
[ "$families_arg" = "check" ] && { echo "Specify family with '-f'." >&2; exit 1; }

set -- "$args"


## Functions

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
			# awk prints the next string after 'inet'
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
			# awk prints the next string after 'inet6', then filters for ULA (unique local addresses with prefix 'fdxx')
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
		echo "Local $family addresses:"
		echo "$local_addresses"
		echo
	esac

	local_subnets="$(sh aggregate-subnets.sh -f "$family" "$local_addresses")"; rv1=$?

	case $rv1 in
		0) [ -z "$subnets_only" ] && echo "Local $family subnets (aggregated):"
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


## Main

ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4})(:[0-9a-f]{0,4}){2,7}'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
subnet_regex_ipv4="${ipv4_regex}\/${maskbits_regex_ipv4}"
subnet_regex_ipv6="${ipv6_regex}\/${maskbits_regex_ipv6}"

[ -n "$family_arg" ] && family_arg="$(printf '%s' "$family_arg" | tr 'A-Z' 'a-z')"
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
