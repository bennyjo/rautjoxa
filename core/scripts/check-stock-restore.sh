#!/usr/bin/env bash
# Restores the test vector packs in DIR with the stock age and tar tools alone,
# then checks every restored file against manifest.json and against the
# checked-in originals, and the manifest's signature against signer.pub.
# It skips tolerated.age, which only the Go tests read: one of its names is
# deliberately not in NFC, and bsdtar rewrites such names.
# Needs age, age-inspect, tar, jq, sha256sum, xxd, and OpenSSL 3.0 or later.
# On macOS, put OpenSSL 3.0 or later first on PATH.
# Set TAR to use another tar command.
#
# Usage: check-stock-restore.sh DIR
#
# DIR holds key1.txt, key2.txt, signer.pub, the vector packs, and originals/,
# as in core/pack/testdata/v1. To write a fresh set from the current code, run
# this in core/, with DIR an absolute path:
#
#   go test ./pack -run TestWriteVectors -vectors-out=DIR
set -euo pipefail

dir=${1:?usage: check-stock-restore.sh DIR}
tar=${TAR:-tar}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# check PACK KEY RECIPIENTS ORIGINALS
#
# ORIGINALS is yes if the pack holds the files in originals/.
check() {
	local pack=$dir/$1 key=$dir/$2 recipients=$3 originals=$4
	echo "== $1 with $2, using $tar"

	age-inspect --json "$pack" >"$work/inspect.json"
	jq -e --argjson n "$recipients" \
		'.postquantum == "yes" and (.stanza_types | length == $n) and all(.stanza_types[]; . == "mlkem768x25519")' \
		"$work/inspect.json" >/dev/null ||
		fail "$1: expected $recipients post-quantum recipients, age-inspect says $(cat "$work/inspect.json")"

	local out
	out=$(mktemp -d "$work/out.XXXXXX")
	age -d -i "$key" "$pack" | "$tar" -x -f - -C "$out"

	# Every member listed in the manifest was restored with its SHA-256, and
	# nothing else was. These are the commands of docs/format.md.
	(
		cd "$out"
		chmod -R u+r .
		jq -e '.members | type == "array"' manifest.json >/dev/null
		test -f manifest.sig
		test "$(jq '.members | map(.path) + ["manifest.json", "manifest.sig"] | unique | length' manifest.json)" -eq "$(find . ! -type d | wc -l)"
		sums=$(jq -r '.members[] | "\(.sha256)  \(.path)"' manifest.json)
		if [ -n "$sums" ]; then
			sha256sum -c - <<<"$sums"
		fi
	)

	# The manifest names and is signed by the trusted signer key.
	local trusted
	trusted=$(cat "$dir/signer.pub")
	[ "$(jq -r .signer "$out/manifest.json")" = "$trusted" ] || fail "$1: the signer in manifest.json isn't the key in signer.pub"
	{ printf 302a300506032b6570032100; printf %s "$trusted"; } | xxd -r -p >"$work/signer.der"
	openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/signer.der" -rawin -in "$out/manifest.json" -sigfile "$out/manifest.sig" >/dev/null ||
		fail "$1: manifest.sig isn't a signature of manifest.json by the key in signer.pub"

	# Every original is byte for byte the checked-in original.
	if [ "$originals" = yes ]; then
		local sidecar path count=0
		for sidecar in "$out"/items/*.json; do
			path=$(jq -r .path "$sidecar")
			cmp "$out/$path" "$dir/originals/${path##*/}" || fail "$1: $path differs from the original"
			count=$((count + 1))
		done
		[ "$count" -eq "$(find "$dir/originals" -type f | wc -l)" ] || fail "$1: restored $count originals"
	fi
	echo "ok: $(jq '.members | length / 2' "$out/manifest.json") items restored and verified"
}

check one-recipient.age key1.txt 1 yes
check two-recipients.age key1.txt 2 yes
check two-recipients.age key2.txt 2 yes
check empty.age key1.txt 1 no
check edge.age key1.txt 1 no
