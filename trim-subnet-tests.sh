#!/bin/sh
# shellcheck disable=SC2034,SC2154

# tests expand_ipv6(), compress_ipv6() and validate_ip()

#### Initial setup
export LC_ALL=C
me=$(basename "$0")

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC2015

export source_trim_subnet="true"
# shellcheck disable=SC1091
. "$script_dir/trim-subnet.sh" || { echo "$me: Error: Can't source '$script_dir/trim-subnet.sh'." >&2; exit 1; }

test_exp_comp_ipv6(){

tests=" \
20014567121200b20000000000000000 2001:4567:1212:b2::
20014567111156ff0000000000000000 2001:4567:1111:56ff::
20014567111156ff0000000000000001 2001:4567:1111:56ff::1
ff020000000000000000000000000001 ff02::1
ff050000000000000000000000010003 ff05::1:3
ff0200000000000000000001ff000001 ff02::1:ff00:1
ff0200000000000000000001ffce4ee3 ff02::1:ffce:4ee3
fe80000000000000021b2bfffece4ee3 fe80::21b:2bff:fece:4ee3
fd0e21465cf545600000000000000001 fd0e:2146:5cf5:4560::1
20010db8000000000000000000020001 2001:db8::2:1
20010db8000000010001000100010001 2001:db8:0:1:1:1:1:1
20010db8000000000001000000000001 2001:db8::1:0:0:1
20010db8000000000000000000000001 2001:db8::1
00000000000000000000000000000000 ::
00000000000000000000000000000001 ::1
00010000000000000000000000000000 1::
"

	# remove extra spaces and tabs
	tests="$(printf "%s" "$tests" | awk '{$1=$1};1')"

	tests_num="$(echo "$tests" | wc -l)"

	status_comp=0; status_exp=0
	tests_done=0

	for i in $(seq 1 "$tests_num" ); do
		line="$(echo "$tests" | awk -v i="$i" 'NR==i{ print; }')"
		expanded_ip="$(printf "%s" "$line" | cut -d' ' -f1 )"
		compressed_ip="$(printf "%s" "$line" | cut -d' ' -f2 )"
		if [ -n "$expanded_ip" ] && [ -n "$compressed_ip" ]; then
			printf "%s" "."

			# expand_ipv6 test
			result="$(expand_ipv6 "$compressed_ip")"
			if [ "$result" != "$expanded_ip" ]; then
				echo "Error in expand_ipv6 with input '$compressed_ip'. Expected '$expanded_ip', got '$result'."
				status_exp=1
			fi

			# # this tests the validate_ip() function
			# validate_ip "$result" "$addr_regex" || echo "Expanded ipv6 failed validation: '$result'." >&2

			# compress_ipv6 test
			result="$(compress_ipv6 "$expanded_ip")"
			if [ "$result" != "$compressed_ip" ]; then
				echo "Error in compress_ipv6 with input '$expanded_ip'. Expected '$compressed_ip', got '$result'."
				status_comp=1
			fi

			# this tests the validate_ip() function
			validate_ip "$result" "$addr_regex" || echo "Compressed ipv6 failed validation: '$result'." >&2

			tests_done=$((tests_done+1))
		fi
	done

	return $((status_exp + status_comp))
}

addr_regex="$ipv6_regex"
test_exp_comp_ipv6
status=$?
echo
echo "Tests done: $tests_done"
echo "Test status: $status"
