#!/bin/sh

# Unix shell script which uses standard utilities to detect local area ipv4 and ipv6 subnets, regardless of the device it's running on (router or host)
# Some heuristics are employed which are likely to work on Linux but for other Unixes, testing is recommended
# Requires the trim-subnet.sh script to process found ip addresses

# find-lan-subnets.sh

export LC_ALL=C


get_local_subnets() (
# attempts to find local subnets, requires family in 1st arg

	family="$1"

	case "$family" in
		inet )
			# get local interface names. filters by "broadcast" because this seems to always filter out WAN interfaces
			local_ifaces_ipv4="$(ip -f inet route show table local | grep -i broadcast | grep -i -v ' lo ' | \
				awk '{for(i=1; i<=NF; i++) if($i~/^dev$/) print $(i+1)}' | sort -u)"

			# get ipv4 addresses with mask bits, corresponding to local interfaces
			# awk prints the next word after 'inet'
			# grep validates found string as ipv4 address with mask bits
			local_addresses="$(
				for iface in $local_ifaces_ipv4; do
					ip -o -f "$family" addr show "$iface" | \
					awk '{for(i=1; i<=NF; i++) if($i~/^inet$/) print $(i+1)}' | grep -E "^$subnet_regex_ipv4$"
				done
			)"
		;;
		inet6 )
			# get local ipv6 addresses with mask bits
			# awk prints the next word after 'inet6'
			# 1st grep filters for ULA (unique local addresses with prefix 'fdxx')
			# 2nd grep validates found string as ipv6 address with mask bits
			local_addresses="$(ip -o -f inet6 addr show | awk '{for(i=1; i<=NF; i++) if($i~/^inet6$/) print $(i+1)}' | \
				grep -E -i '^fd[0-9a-f]{0,2}:' | grep -E -i "^$subnet_regex_ipv6$")"
		;;
		* ) echo "get_local_subnets: invalid family '$family'." >&2; return 1 ;;
	esac

	for local_address in $local_addresses; do
		# uses external trim-subnet.sh script to trim the subnets to mask bits
		local_subnets="$(sh trim-subnet.sh "$local_address") $local_subnets"
	done

	# adds link-local subnet fe80::/10
	[ "$family" = "inet6" ] && local_subnets="$local_subnets fe80::/10"

	# removes extra whitespaces, converts to newline-delimited list and removes duplicates
	local_subnets="$(printf "%s" "$local_subnets" | awk '{$1=$1};1' | tr ' ' '\n' | sort -u )"

	[ -n "$local_subnets" ] && { printf "%s" "$local_subnets"; return 0; } || return 1
)



ipv4_regex='((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])'
ipv6_regex='([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}:?'
maskbits_regex_ipv6='(12[0-8]|((1[0-1]|[1-9])[0-9])|[8-9])'
maskbits_regex_ipv4='(3[0-2]|([1-2][0-9])|[8-9])'
subnet_regex_ipv4="^${ipv4_regex}/${maskbits_regex_ipv4}$"
subnet_regex_ipv6="^${ipv6_regex}/${maskbits_regex_ipv6}$"

rv=0
for family in inet inet6; do
	localsubnets="$(get_local_subnets "$family")"; rv=$((rv + $?))
	echo "Local $family subnets:" >&2
	if [ -n "$localsubnets" ]; then printf "%s\n" "$localsubnets"; else echo "None found." >&2; fi
	echo >&2
done

exit $rv
