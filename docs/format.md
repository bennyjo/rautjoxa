# Pack format, version 1

A pack is the unit that Rautjoxa stores: an encrypted tar archive of original files, one JSON sidecar per file, a manifest, and the writing device's signature of the manifest.
Packs are stored under write-once retention and are never rewritten, so this format is permanent.
Every reader must keep reading version 1. Any change to what follows needs a new format version.

The reference implementation is the Go package [`core/pack`](../core/pack).
You can restore a pack without it, using only the stock `age` and `tar` tools. See [Restore without Rautjoxa](#restore-without-rautjoxa).

## Object names

A pack is stored as `packs/<id>.age`.
The pack ID is 128 random bits written as 32 lowercase hexadecimal characters, such as `c47ec5adb00f113075989abe6d0be5eb`.
The manifest records the same ID, so a pack can be identified even if its object is renamed.
A reader that knows the object name checks that it is `packs/<id>.age` for the manifest's `id`, because anyone who can write to the archive can copy a genuine, signed pack under another name.
The Go reader doesn't see the object name, so its caller makes this check.

## Encryption

- A pack is a binary (not armored) [age v1](https://age-encryption.org/v1) file.
- It is encrypted to one or two recipients: the owner and, optionally, a successor.
- Every recipient is a post-quantum hybrid ML-KEM-768 and X25519 recipient (`age1pq1...`), so the header holds one or two `mlkem768x25519` stanzas and nothing else.
  age refuses to mix post-quantum and classic recipients, because a classic recipient would remove the post-quantum protection.
  A reader rejects a pack with any other stanza type or stanza count.
- The plaintext is exactly one tar archive, which ends with the end-of-archive marker of two zero blocks.
  Writers write nothing after the marker. Readers ignore any zero bytes after it, because tar tools pad archives with zeros to a whole record.

## Tar layout

The tar archive uses the POSIX pax interchange format, in the one layout that the version 1 writer produces, so that every pack restores the same way with GNU tar and bsdtar.
Readers reject every other header, even one that tar tools would read: other numbers, padding, fields, or records.

A member's header is one ustar block, after one pax extended header only if that block can't hold the member's path, size, or time.
A header block is 512 bytes, and every byte that this table doesn't set is NUL:

| Offset | Field | Member block | Extended header block |
|---|---|---|---|
| 0 | `name` | The member's path, see below | The member's directory, then `PaxHeaders.0/`, then its file name, such as `items/PaxHeaders.0/000001.json` or `PaxHeaders.0/manifest.json`, with non-ASCII characters removed, cut to 100 bytes, and with trailing slashes removed |
| 100 | `mode` | `0000644\0` | `0000000\0` |
| 108, 116 | `uid`, `gid` | `0000000\0` | `0000000\0` |
| 124 | `size` | The member's size as 11 octal digits and a NUL, or zeros if a `size` record holds it | The length of the records as 11 octal digits and a NUL |
| 136 | `mtime` | The time in whole seconds since the Unix epoch, rounded down, as 11 octal digits and a NUL, or zeros if it is negative or doesn't fit | `00000000000\0` |
| 148 | `chksum` | 6 octal digits, a NUL, and a space | The same |
| 156 | `typeflag` | `0` | `x` |
| 257 | `magic`, `version` | `ustar\0` and `00` | The same |
| 329, 337 | `devmajor`, `devminor` | `0000000\0` | NUL bytes |
| 345 | `prefix` | See below | NUL bytes |

An extended header's block is followed by its records, in order of their keys, each written as `<length> <key>=<value>\n`, and zero bytes up to a whole block. It holds only the records that the member needs:

- `mtime`, if the time has a fraction of a second or doesn't fit in the `mtime` field, as decimal seconds without leading zeros, with a `-` if negative and a fraction of at most 9 digits without trailing zeros, such as `-1.5`. The whole seconds fit in a signed 64-bit integer, and the time isn't exactly `-62135596800`, the start of year 1.
- `size`, if the size is 8 GiB or more, as decimal digits without leading zeros, at most 2^63-1.
- `path`, if the path isn't ASCII or is longer than 100 bytes, except as the next paragraph says.

In a member's `name` field, a path of up to 100 ASCII bytes is stored as it is.
An ASCII path of more than 100 bytes, with a `<name>` of up to 100 bytes and no other record to store, has no extended header: `prefix` is `items/000001`, for item 1, and `name` is `<name>`.
With a `path` record, `name` holds the path without its non-ASCII characters, cut to 100 bytes, and `prefix` is empty.

Zero bytes pad every member's content to a whole block.
The archive holds only regular files: no directories, links, or global headers. Members appear in this order:

| Member | Content |
|---|---|
| `items/000001.json` | The sidecar of item 1 |
| `items/000001/<name>` | The original bytes of item 1 |
| `items/000002.json`, `items/000002/<name>`, ... | The same for each further item |
| `manifest.json` | The manifest |
| `manifest.sig` | The signature of the manifest, always last |

- Items are numbered from `000001` with six decimal digits, so a pack holds at most 999,999 items.
  The manifest's size limit usually comes first: with 23-byte names, the Go writer stops at about 760,000 items, and sooner with longer names.
- `<name>` is the original's file name: 1 to 255 bytes of UTF-8, with no `/`, `\`, or control characters (U+0000 to U+001F and U+007F to U+009F), and not `.` or `..`.
  Writers store the name in Unicode Normalization Form C (NFC), because some tar tools convert names to NFC when they restore files. Readers accept a name in any form.
- Each original's modification time in the tar header is the item's `modified` time, so that stock tools restore files with that time.
  Some tar tools restore some times incorrectly, such as times before 1970, so the sidecar's `modified` time is authoritative.
  Readers check the form of a tar time, but not that it matches the sidecar.

## JSON

Every sidecar and the manifest is one JSON object in UTF-8 that holds exactly the fields shown below, each once and with the type shown.
Key order, whitespace, and escapes are free, but a string doesn't hold an unpaired surrogate escape such as `\ud800`.

- Sizes and the version are non-negative integers of at most 2^63-1, without a sign, fraction, or exponent.
- Times are RFC 3339 in UTC: `YYYY-MM-DDTHH:MM:SS`, optionally followed by a fraction of 1 to 9 digits, then `Z`, with an uppercase `T` and `Z`. Seconds are 00 to 59, and the date and time must be real.

Readers reject a member that breaks any of these rules.

## Sidecar

Each sidecar is a JSON object of at most 1 MiB:

```json
{
  "path": "items/000001/IMG_20261030_101500.jpg",
  "size": 70000,
  "modified": "2026-10-30T10:15:00.25Z",
  "mime_type": "image/jpeg",
  "source": {
    "id": "android.media",
    "key": "content://media/external/images/media/1001",
    "metadata": {
      "bucket_display_name": "Camera",
      "datetaken": "1793355300000",
      "relative_path": "DCIM/Camera/"
    }
  }
}
```

| Field | Meaning |
|---|---|
| `path` | The tar path of the original, the member that follows this sidecar |
| `size` | The original's length in bytes |
| `modified` | When the original was last modified at its source, with optional fractional seconds |
| `mime_type` | The media type the source reports, or `""` if unknown |
| `source.id` | The ID of the source that supplied the item, such as `android.media` or `google.takeout`. Not empty, and it never changes for a source |
| `source.key` | The item's key within that source. Not empty, and it never changes for the item |
| `source.metadata` | String keys and values, stored exactly as the source reported them |

The `source` block is the same for every source, so items from any later source fit this format without a change.

## Manifest

`manifest.json` is a JSON object of at most 256 MiB that lists every member before it, in tar order, with its size and lowercase hexadecimal SHA-256:

```json
{
  "format": "rautjoxa-pack",
  "version": 1,
  "id": "c47ec5adb00f113075989abe6d0be5eb",
  "created": "2026-10-30T02:12:41Z",
  "writer": "rautjoxa-core/0.1.0",
  "signer": "8fa9fdd7d110b3644fbd663237e20f47a5b5b12613aa3fc406df824a8c216153",
  "members": [
    {
      "path": "items/000001.json",
      "size": 380,
      "sha256": "82a3936801fe8e6b5baac71704c43d0efc39563e87ec66f77f978fc3db8db55e"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `created` | When the pack was written, to the second, without a fraction |
| `writer` | The software that wrote the pack and its version, as `<name>/<version>`: at most 128 bytes, with a name of ASCII letters, digits, `.`, `_`, and `-`, and a version of the same characters and `+`. Readers don't act on it, but it lets you find the packs that a faulty writer version wrote |
| `signer` | The Ed25519 public key that signed the manifest, as 64 lowercase hexadecimal characters. |

## Signature

`manifest.sig` holds the 64-byte Ed25519 signature ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), pure Ed25519) of the exact bytes of `manifest.json`.
Readers verify it as Go's `crypto/ed25519` does: by the RFC 8032 equation without the cofactor, with `S` less than the group order.
The device that writes the pack makes it with its own signing key, which signs nothing but pack manifests.

A valid signature proves that whoever holds the private key of `signer` wrote the manifest, and so, through its sizes and hashes, every member of the pack.
It proves that one of your devices wrote the pack only if you compare `signer` with your devices' public keys, kept apart from the packs. Anyone can sign a pack with a key of their own.
The signature doesn't cover the age header: whoever can decrypt a pack can encrypt its content again to other recipients, and the signature stays valid.
It binds no trusted time either, because the signer sets `created`: whoever steals a device's signing key can sign packs dated in the past.
Removing that key from the trusted keys then also rejects the device's genuine packs, unless a record of the genuine packs' IDs and manifest hashes, kept apart from the packs, tells them apart.

Restoring a pack needs only an age identity. Neither a stock restore nor the Go reader needs the signing key, and checking the signature needs only the public key.

## Reader checks

A reader accepts a pack only if all of these hold:

1. The header has one or two `mlkem768x25519` stanzas and nothing else.
1. age decrypts and authenticates the whole file. A changed byte or a truncated file fails here.
1. The tar members follow the layout above exactly, with nothing missing, added, or out of order. The archive ends with two zero blocks, followed by nothing but zero bytes.
1. Every sidecar and the manifest follows the JSON rules, every sidecar is valid, and each original's size matches its sidecar.
1. The manifest lists exactly the members found before it, in order, with matching sizes and SHA-256 hashes.
1. `manifest.sig` is a valid signature of `manifest.json` by `signer`, and `signer` is one of the keys the reader trusts. An empty list of trusted keys trusts none; accepting any signer takes an explicit choice.

These checks are part of the format: what a reader accepts never gets stricter, even when the rules for what a writer writes do.

In the Go reader, `pack.Read` takes the trusted keys, and `pack.ReadAnySigner` accepts any signer.
The Go reader returns `pack.ErrWrongKey` when the key opens no stanza, `pack.ErrUntrustedSigner` when a valid signature is by a key the caller doesn't trust, and `pack.ErrInvalid` with a description for every other failure of the pack.
When reading the pack's bytes fails, for example because of a network error, it returns an error that wraps that failure and isn't `pack.ErrInvalid`, because it says nothing about the pack.

## Restore without Rautjoxa

You need [age](https://github.com/FiloSottile/age) v1.3.0 or later, which added post-quantum keys, and the standard `tar` and `sha256sum` tools.
On macOS, `shasum -a 256` works in place of `sha256sum`.
The hash check uses [jq](https://jqlang.org); without it, `manifest.json` is plain JSON that you can read and check by hand.

To check who wrote the pack, the script also needs OpenSSL 3.0 or later and `xxd`, and the hexadecimal public key of the device you trust to have written it.
Save the script as `restore.sh` outside the directory you restore to.
Then, from an empty directory and in a UTF-8 locale (`locale` shows it), run it with paths that lead outside that directory, such as `bash /path/to/restore.sh /path/to/pack.age /path/to/key.txt TRUSTED`, where `TRUSTED` is that public key:

```bash
set -euo pipefail
age-inspect "$1"                       # Shows the stanza types and confirms post-quantum encryption.
age -d -i "$2" "$1" | tar -x -f -
chmod -R u+r .
jq -e '.members | type == "array"' manifest.json >/dev/null
test -f manifest.sig
test "$(jq '.members | map(.path) + ["manifest.json", "manifest.sig"] | unique | length' manifest.json)" -eq "$(find . ! -type d | wc -l)"
sums=$(jq -r '.members[] | "\(.sha256)  \(.path)"' manifest.json)
if [ -n "$sums" ]; then
  sha256sum -c - <<<"$sums"
fi
if [ -z "${3:-}" ]; then
  echo "Restored. Every file matches manifest.json, but who wrote the pack is unchecked."
  exit
fi
der=$(mktemp)
{ printf 302a300506032b6570032100; printf %s "$3"; } | xxd -r -p >"$der"
openssl pkeyutl -verify -pubin -keyform DER -inkey "$der" -rawin -in manifest.json -sigfile manifest.sig
echo "Restored and verified: every file matches manifest.json, and the trusted key signed it."
```

`key.txt` holds the owner's or the successor's `AGE-SECRET-KEY-PQ-1...` identity.
The originals are restored under `items/`, next to the sidecars that describe them.
The script stops at the first failure.
It makes the restored files readable before it checks them, so that the hash check decides whatever mode a tar header holds.
It prints `Restored and verified` only if the number of restored files matches the manifest, counting the manifest and its signature, every listed file matches its hash, and the manifest's signature verifies with the trusted key.
The hexadecimal prefix turns the raw public key into the DER form that OpenSSL reads, and OpenSSL checks the signature with your trusted key, not with the `signer` field of the pack, so a pack signed by any other key fails.

Without a trusted key, the script checks only that the files match the manifest.
That proves the pack is intact but not who wrote it: anyone who has the recipient's public key can write a pack that passes, so treat its content as unverified.

If age reports an error, the pack is damaged or was tampered with, and no extracted file can be trusted: restore the pack from the other archive.
age stops at the first damaged 64 KiB chunk, so nothing after it is restored.

## Test vectors

[`core/pack/testdata/v1`](../core/pack/testdata/v1) holds packs, the original files, the two keys that open the packs, and `signer.pub`, the hexadecimal public key that signed them:

- `one-recipient.age` and `two-recipients.age` hold the files in `originals/`, encrypted to `key1.txt`, and to `key1.txt` and `key2.txt`.
- `empty.age` holds no items.
- `edge.age` holds items with edge-case names, times, and metadata, as the version 1 writer writes them.
- `tolerated.age` is a pack that a writer must not write but every reader must accept: one name isn't in NFC, and zero bytes follow the tar archive.
  It also uses JSON layouts, key orders, and escapes that the Go writer doesn't write. Its tar headers are in the one layout that the format allows.

These keys are public test keys: never use them for real data.
The vectors never change. The Go tests pin the SHA-256 of every file, and they and CI check that every later version still reads the vectors, all of them with the Go reader and all but `tolerated.age` with GNU tar and bsdtar. CI also restores packs from the current writer with both tools.
`tolerated.age` is checked only with the Go reader, because one of its names is deliberately not in NFC, and bsdtar rewrites such names, so the hash check would fail.
