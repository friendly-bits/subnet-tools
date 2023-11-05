#!/bin/sh

# tests expand_ipv6(), compress_ipv6() and validate_ip()

#### Initial setup

me=$(basename "$0")

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC2015
[ -n "$script_dir" ] && cd "$script_dir" || { echo "$me: Error: Couldn't cd into '$script_dir'." >&2; exit 1; }

export test_cut_ip="true"
. "$script_dir/cut-ip.sh" || { echo "$me: Error: Can't source '$script_dir/cut-ip.sh'." >&2; exit 1; }

test_exp_comp_ipv6(){

tests=" \
2001:4567:1212:00b2:0000:0000:0000:0000 2001:4567:1212:b2::
2001:4567:1111:56ff:0000:0000:0000:0000 2001:4567:1111:56ff::
2001:4567:1111:56ff:0000:0000:0000:0001 2001:4567:1111:56ff::1
ff02:0000:0000:0000:0000:0000:0000:0001 ff02::1
ff05:0000:0000:0000:0000:0000:0001:0003 ff05::1:3
ff02:0000:0000:0000:0000:0001:ff00:0001 ff02::1:ff00:1
ff02:0000:0000:0000:0000:0001:ffce:4ee3 ff02::1:ffce:4ee3
fe80:0000:0000:0000:021b:2bff:fece:4ee3 fe80::21b:2bff:fece:4ee3
fd0e:2146:5cf5:4560:0000:0000:0000:0001 fd0e:2146:5cf5:4560::1
2001:0db8:0000:0000:0000:0000:0002:0001 2001:db8::2:1
2001:0db8:0000:0001:0001:0001:0001:0001 2001:db8:0:1:1:1:1:1
2001:0db8:0000:0000:0001:0000:0000:0001 2001:db8::1:0:0:1
2001:0db8:0000:0000:0000:0000:0000:0001 2001:db8::1
0000:0000:0000:0000:0000:0000:0000:0000 ::
0000:0000:0000:0000:0000:0000:0000:0001 ::1
0001:0000:0000:0000:0000:0000:0000:0000 1::
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

			# compress_ipv6 test
			result="$(compress_ipv6 "$expanded_ip")"
			if [ "$result" != "$compressed_ip" ]; then
				echo "compress_ipv6 '$expanded_ip': expected '$compressed_ip', got '$result'."
				status_comp=1
			fi

			# this tests the validate_ip() function
			validate_ip "$result" "inet6" || echo "result failed validation: '$result'" >&2


			# expand_ipv6 test
			result="$(expand_ipv6 "$compressed_ip")"
			if [ "$result" != "$expanded_ip" ]; then
				echo "compress_ipv6 '$compressed_ip': expected '$expanded_ip', got '$result'."
				status_exp=1
			fi

			# this tests the validate_ip() function
			validate_ip "$result" "inet6" || echo "result failed validation: '$result'" >&2


			tests_done=$((tests_done+1))
		fi
	done
	return $((status_exp + status_comp))
}

test_exp_comp_ipv6
echo
echo "Tests done: $tests_done"
echo "Test status: $?"
