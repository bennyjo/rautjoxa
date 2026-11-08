package pack

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// These tests pin what the reader accepts: everything the format allows, and
// nothing else.

// forgePack encrypts entries followed by a manifest that lists them and its
// signature by testSigner. manifest makes the manifest from the JSON array
// of members.
func forgePack(t *testing.T, id *age.HybridIdentity, entries []tarEntry, manifest func(members string) string) []byte {
	t.Helper()
	var members []string
	for _, e := range entries {
		path, err := json.Marshal(e.hdr.Name)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, fmt.Sprintf(`{"path":%s,"size":%d,"sha256":"%x"}`, path, len(e.body), sha256.Sum256(e.body)))
	}
	m := manifest("[" + strings.Join(members, ",") + "]")
	all := append(entries, regular(manifestPath, m), tarEntry{regular(signaturePath, "").hdr, ed25519.Sign(testSigner, []byte(m))})
	return encryptTar(t, all, id.Recipient())
}

func stdManifest(members string) string {
	return fmt.Sprintf(`{"format":"rautjoxa-pack","version":1,"id":"c47ec5adb00f113075989abe6d0be5eb",`+
		`"created":"2026-10-30T02:12:41Z","writer":"test-writer/1.0.0","signer":"%x","members":%s}`, trusted[0], members)
}

const goodSidecar = `{"path":"items/000001/a.jpg","size":3,"modified":"2026-10-30T10:15:00Z","mime_type":"image/jpeg",` +
	`"source":{"id":"s","key":"k","metadata":{}}}`

// checkRead reads data and checks that it is accepted if want is empty, or
// rejected as invalid with an error containing want.
func checkRead(t *testing.T, data []byte, id age.Identity, want string) {
	t.Helper()
	_, err := Read(bytes.NewReader(data), id, trusted, func(_ Item, r io.Reader) error {
		_, err := io.ReadAll(r)
		return err
	})
	switch {
	case want == "" && err != nil:
		t.Errorf("Read error = %v, want the pack accepted", err)
	case want != "" && (!errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want)):
		t.Errorf("Read error = %v, want ErrInvalid containing %q", err, want)
	}
}

func TestStrictJSON(t *testing.T) {
	id := newIdentity(t)
	sidecar := func(old, new string) string {
		if !strings.Contains(goodSidecar, old) {
			t.Fatalf("sidecar doesn't contain %q", old)
		}
		return strings.Replace(goodSidecar, old, new, 1)
	}
	for _, tc := range []struct {
		name, sidecar, want string
	}{
		{"valid", goodSidecar, ""},
		{"other key order, escapes, and whitespace",
			"{ \"source\" : {\"metadata\":{\"b\":\"1\",\"a\":\"2\"},\"key\":\"\\u006b\",\"id\":\"s\"},\n" +
				"\t\"mime_type\":\"\",\"modified\":\"2026-10-30T10:15:00.000000001Z\",\"size\":3,\"path\":\"items\\/000001\\/a.jpg\" }\n", ""},
		{"escaped time", sidecar(`10:15:00Z`, `10\u003a15:00\u005a`), ""},
		{"escaped time with offset", sidecar(`10:15:00Z`, `12\u003a15:00+02:00`), `is not an RFC 3339 UTC time`},
		{"key in other case", sidecar(`"path"`, `"PATH"`), `unknown field "PATH"`},
		{"duplicate key", sidecar(`"path":"items/000001/a.jpg"`, `"path":"items/000001/x.jpg","path":"items/000001/a.jpg"`), `duplicate`},
		{"duplicate metadata key", sidecar(`"metadata":{}`, `"metadata":{"a":"1","a":"2"}`), `duplicate`},
		{"unknown nested field", sidecar(`"id":"s"`, `"id":"s","extra":"x"`), `unknown field "source.extra"`},
		{"missing field", sidecar(`"mime_type":"image/jpeg",`, ``), `missing field "mime_type"`},
		{"missing nested field", sidecar(`,"metadata":{}`, ``), `missing field "source.metadata"`},
		{"null metadata", sidecar(`"metadata":{}`, `"metadata":null`), `field "source.metadata" is null, expected an object`},
		{"null string", sidecar(`"image/jpeg"`, `null`), `field "mime_type" is null, expected a string`},
		{"metadata number value", sidecar(`"metadata":{}`, `"metadata":{"k":1}`), `field "source.metadata.k" is number, expected a string`},
		{"time with offset", sidecar(`10:15:00Z`, `12:15:00+02:00`), `is not an RFC 3339 UTC time`},
		{"time with lowercase z", sidecar(`10:15:00Z`, `10:15:00z`), `is not an RFC 3339 UTC time`},
		{"time with 10 fraction digits", sidecar(`10:15:00Z`, `10:15:00.0123456789Z`), `is not an RFC 3339 UTC time`},
		{"time with space", sidecar(`T10:15:00Z`, ` 10:15:00Z`), `is not an RFC 3339 UTC time`},
		{"impossible time", sidecar(`2026-10-30`, `2026-13-30`), `month out of range`},
		{"leap second", sidecar(`2026-10-30T10:15:00Z`, `2016-12-31T23:59:60Z`), `second out of range`},
		{"fractional size", sidecar(`"size":3`, `"size":3.0`), `"size" 3.0 is not a non-negative integer`},
		{"exponent size", sidecar(`"size":3`, `"size":3e0`), `is not a non-negative integer`},
		{"negative zero size", sidecar(`"size":3`, `"size":-0`), `is not a non-negative integer`},
		{"string size", sidecar(`"size":3`, `"size":"3"`), `is not a non-negative integer`},
		{"invalid UTF-8", sidecar(`"key":"k"`, "\"key\":\"k\xff\""), `invalid UTF-8`},
		{"unpaired surrogate escape", sidecar(`"key":"k"`, `"key":"k\ud800"`), `surrogate`},
		{"byte order mark", "\ufeff" + goodSidecar, `invalid character`},
		{"trailing value", goodSidecar + "{}", `data after the JSON value`},
		{"not an object", "[" + goodSidecar + "]", `the JSON value is [, expected an object`},
		{"empty", "", `unexpected EOF`},
	} {
		t.Run("sidecar "+tc.name, func(t *testing.T) {
			entries := []tarEntry{regular(sidecarPath(1), tc.sidecar), regular(originalPath(1, "a.jpg"), "abc")}
			checkRead(t, forgePack(t, id, entries, stdManifest), id, tc.want)
		})
	}

	manifest := func(old, new string) func(string) string {
		return func(members string) string {
			m := stdManifest(members)
			if !strings.Contains(m, old) {
				t.Fatalf("manifest doesn't contain %q", old)
			}
			return strings.Replace(m, old, new, 1)
		}
	}
	for _, tc := range []struct {
		name     string
		manifest func(string) string
		want     string
	}{
		{"valid", stdManifest, ""},
		{"writer with build metadata", manifest(`test-writer/1.0.0`, `test_writer.x/1.0.0-rc.1+build.5`), ""},
		{"escaped created time", manifest(`02:12:41Z`, `02\u003a12:41Z`), ""},
		{"leap second in created time", manifest(`2026-10-30T02:12:41Z`, `2016-12-31T23:59:60Z`), `second out of range`},
		{"fractional created time", manifest(`02:12:41Z`, `02:12:41.5Z`), `is not an RFC 3339 UTC time to the second`},
		{"created time with offset", manifest(`02:12:41Z`, `04:12:41+02:00`), `is not an RFC 3339 UTC time to the second`},
		{"key in other case", manifest(`"format"`, `"Format"`), `unknown field "Format"`},
		{"members under another key", manifest(`,"members":[`, `,"x":[`), `unknown field "x"`},
		{"null members", func(string) string { return stdManifest("null") }, `field "members" is null, expected an array`},
		{"member with unknown field", manifest(`"size":`, `"extra":1,"size":`), `unknown field "members[0].extra"`},
		{"member hash under another key", manifest(`,"sha256":"`, `,"x":"`), `unknown field "members[0].x"`},
		{"fractional version", manifest(`"version":1`, `"version":1.0`), `is not a non-negative integer`},
		{"writer with space", manifest(`test-writer/1.0.0`, `test writer/1.0.0`), `malformed writer`},
		{"writer with two slashes", manifest(`test-writer/1.0.0`, `test/writer/1.0.0`), `malformed writer`},
		{"writer of 128 bytes", manifest(`test-writer/1.0.0`, `w/`+strings.Repeat("1", 126)), ""},
		{"writer of 129 bytes", manifest(`test-writer/1.0.0`, `w/`+strings.Repeat("1", 127)), `malformed writer`},
		{"writer without a version", manifest(`test-writer/1.0.0`, `w/`), `malformed writer`},
		{"writer with a non-ASCII letter", manifest(`test-writer/1.0.0`, `rautjöxa-core/1`), `malformed writer`},
	} {
		t.Run("manifest "+tc.name, func(t *testing.T) {
			entries := []tarEntry{regular(sidecarPath(1), goodSidecar), regular(originalPath(1, "a.jpg"), "abc")}
			checkRead(t, forgePack(t, id, entries, tc.manifest), id, tc.want)
		})
	}

	t.Run("manifest of an empty pack without members", func(t *testing.T) {
		checkRead(t, forgePack(t, id, nil, manifest(`,"members":[]`, ``)), id, `missing field "members"`)
	})
}

func TestStrictTar(t *testing.T) {
	id := newIdentity(t)
	long := strings.Repeat("x", 200) + ".jpg"
	for _, tc := range []struct {
		name   string
		format tar.Format
		file   string
		pax    map[string]string
		want   string
	}{
		{"plain ustar header", tar.FormatPAX, "a.jpg", nil, ""},
		{"long name in a pax record", tar.FormatPAX, long, nil, ""},
		{"GNU headers", tar.FormatGNU, "a.jpg", nil, "tar header"},
		{"GNU long name", tar.FormatGNU, long, nil, "tar header"},
		{"extended attribute", tar.FormatPAX, "a.jpg", map[string]string{"SCHILY.xattr.com.apple.quarantine": "0081;0;x;"}, "tar header"},
		{"comment record", tar.FormatPAX, "a.jpg", map[string]string{"comment": "hi"}, "tar header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, orig := regular(sidecarPath(1), strings.Replace(goodSidecar, "a.jpg", tc.file, 1)), regular(originalPath(1, tc.file), "abc")
			sc.hdr.Format, orig.hdr.Format = tc.format, tc.format
			orig.hdr.PAXRecords = tc.pax
			checkRead(t, forgePack(t, id, []tarEntry{sc, orig}, stdManifest), id, tc.want)
		})
	}

	t.Run("global header", func(t *testing.T) {
		global := tarEntry{&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "global", PAXRecords: map[string]string{"comment": "x"}, Format: tar.FormatPAX}, nil}
		entries := []tarEntry{global, regular(sidecarPath(1), goodSidecar), regular(originalPath(1, "a.jpg"), "abc")}
		checkRead(t, forgePack(t, id, entries, stdManifest), id, "tar header")
	})
}

// TestArchiveEnd checks the end of the tar archive: two zero blocks must end
// it, and only zero bytes may follow, as tar tools pad archives to records.
func TestArchiveEnd(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, testItems()[:1], id.Recipient())
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		t.Fatal(err)
	}
	p, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(p, make([]byte, 2*blockSize)) || len(p)%blockSize != 0 {
		t.Fatal("the writer's tar archive doesn't end with exactly two zero blocks")
	}
	zeros := func(n int) []byte { return make([]byte, n) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for _, tc := range []struct {
		name      string
		plaintext []byte
		want      string
	}{
		{"one trailing zero byte", cat(p, zeros(1)), ""},
		{"one trailing zero block", cat(p, zeros(blockSize)), ""},
		{"padded to a 10240-byte record", cat(p, zeros(10240-len(p)%10240)), ""},
		{"many trailing zero bytes", cat(p, zeros(200_000)), ""},
		{"trailing data", cat(p, []byte("trailing")), "data after the end of the tar archive"},
		{"trailing data after zero bytes", cat(p, zeros(100_000), []byte{1}), "data after the end of the tar archive"},
		{"only one zero block", p[:len(p)-blockSize], "doesn't end with two zero blocks"},
		{"no end-of-archive marker", p[:len(p)-2*blockSize], "doesn't end with two zero blocks"},
		{"data block after one zero block", cat(p[:len(p)-blockSize], bytes.Repeat([]byte{1}, blockSize)), "read tar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkRead(t, encrypt(t, tc.plaintext, id.Recipient()), id, tc.want)
		})
	}
}

// rawHeader returns a header block as docs/format.md specifies it, for a
// member if typeflag is '0' and for an extended header otherwise. edit changes
// the block before it gets its checksum.
func rawHeader(name, prefix string, typeflag byte, size, mtime int64, edit func(blk []byte)) []byte {
	blk := make([]byte, blockSize)
	copy(blk, name)
	copy(blk[100:], "0000000\x000000000\x000000000\x00")
	copy(blk[124:], fmt.Sprintf("%011o\x00%011o\x00", size, mtime))
	blk[156] = typeflag
	copy(blk[257:], "ustar\x0000")
	if typeflag == '0' {
		copy(blk[100:], "0000644\x00")
		copy(blk[329:], "0000000\x000000000\x00")
	}
	copy(blk[345:], prefix)
	if edit != nil {
		edit(blk)
	}
	copy(blk[148:], "        ")
	sum := 0
	for _, b := range blk {
		sum += int(b)
	}
	copy(blk[148:], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

// rawBody returns body padded to whole blocks.
func rawBody(body []byte) []byte {
	return append(bytes.Clone(body), make([]byte, -len(body)&(blockSize-1))...)
}

func rawMember(name string, body []byte, edit func(blk []byte)) []byte {
	return append(rawHeader(name, "", '0', int64(len(body)), 0, edit), rawBody(body)...)
}

// asciiName returns a path as a name field holds it, without its non-ASCII
// characters and cut to 100 bytes.
func asciiName(path string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 0x80 {
			return r
		}
		return -1
	}, path)
	return ascii[:min(len(ascii), 100)]
}

// rawExtended returns the extended header for the member at path, which holds
// records.
func rawExtended(path, records string, edit func(blk []byte)) []byte {
	dir, file := path[:strings.LastIndex(path, "/")+1], path[strings.LastIndex(path, "/")+1:]
	header := rawHeader(strings.TrimRight(asciiName(dir+"PaxHeaders.0/"+file), "/"), "", 'x', int64(len(records)), 0, edit)
	return append(header, rawBody([]byte(records))...)
}

// rawPaxMember returns the member at path with an extended header of records.
func rawPaxMember(path, records string, edit func(blk []byte), body []byte) []byte {
	return append(rawExtended(path, records, edit), rawMember(asciiName(path), body, nil)...)
}

func paxPath(path string) string {
	return paxRecord("path", path)
}

// paxRecord returns one pax extended header record.
func paxRecord(key, value string) string {
	record := " " + key + "=" + value + "\n"
	n := len(record)
	for len(fmt.Sprint(n))+len(record) != n {
		n = len(fmt.Sprint(n)) + len(record)
	}
	return fmt.Sprint(n) + record
}

// TestHeaderLayout checks that the headers the writer writes are the bytes
// that docs/format.md specifies. If archive/tar ever writes other bytes, this
// fails before a pack in another layout exists.
func TestHeaderLayout(t *testing.T) {
	const octalLimit = 1 << 33 // the first value that 11 octal digits can't hold
	seconds := time.Unix(1000, 0)
	fits, long := strings.Repeat("a", 84)+".jpg", strings.Repeat("a", 97)+".jpg"
	for _, tc := range []struct {
		name       string
		path       string
		size       int64
		modified   time.Time
		records    string
		ustar      string
		prefix     string
		sizeField  int64
		mtimeField int64
	}{
		{name: "short ASCII path", path: "items/000001/a.jpg", size: 3, modified: seconds, ustar: "items/000001/a.jpg", sizeField: 3, mtimeField: 1000},
		{name: "ASCII path of 101 bytes", path: "items/000001/" + fits, size: 3, modified: seconds, ustar: fits, prefix: "items/000001", sizeField: 3, mtimeField: 1000},
		{name: "ASCII name of 101 bytes", path: "items/000001/" + long, size: 3, modified: seconds, records: paxPath("items/000001/" + long), ustar: asciiName("items/000001/" + long), sizeField: 3, mtimeField: 1000},
		{name: "non-ASCII name", path: "items/000001/ö.jpg", size: 3, modified: seconds, records: paxPath("items/000001/ö.jpg"), ustar: "items/000001/.jpg", sizeField: 3, mtimeField: 1000},
		{name: "fraction of a second", path: "items/000001/a.jpg", size: 3, modified: time.Unix(1000, 250_000_000), records: paxRecord("mtime", "1000.25"), ustar: "items/000001/a.jpg", sizeField: 3, mtimeField: 1000},
		{name: "before 1970", path: "items/000001/a.jpg", size: 3, modified: time.Unix(-2, 500_000_000), records: paxRecord("mtime", "-1.5"), ustar: "items/000001/a.jpg", sizeField: 3},
		{name: "time that doesn't fit", path: "items/000001/a.jpg", size: 3, modified: time.Unix(octalLimit, 0), records: paxRecord("mtime", fmt.Sprint(octalLimit)), ustar: "items/000001/a.jpg", sizeField: 3},
		{name: "last time that fits", path: "items/000001/a.jpg", size: 3, modified: time.Unix(octalLimit-1, 0), ustar: "items/000001/a.jpg", sizeField: 3, mtimeField: octalLimit - 1},
		{name: "size that doesn't fit", path: "items/000001/a.jpg", size: octalLimit, modified: seconds, records: paxRecord("size", fmt.Sprint(octalLimit)), ustar: "items/000001/a.jpg", mtimeField: 1000},
		{name: "last size that fits", path: "items/000001/a.jpg", size: octalLimit - 1, modified: seconds, ustar: "items/000001/a.jpg", sizeField: octalLimit - 1, mtimeField: 1000},
		{name: "records in order of their keys", path: "items/000001/" + fits, size: octalLimit, modified: time.Unix(1000, 500_000_000),
			records: paxRecord("mtime", "1000.5") + paxPath("items/000001/"+fits) + paxRecord("size", fmt.Sprint(octalLimit)), ustar: asciiName("items/000001/" + fits), mtimeField: 1000},
		{name: "name with no ASCII characters", path: "items/000001/日本語", size: 3, modified: seconds, records: paxPath("items/000001/日本語"), ustar: "items/000001/", sizeField: 3, mtimeField: 1000},
		{name: "sidecar with a fraction of a second", path: "items/000001.json", size: 3, modified: time.Unix(1000, 500_000_000), records: paxRecord("mtime", "1000.5"), ustar: "items/000001.json", sizeField: 3, mtimeField: 1000},
		{name: "manifest with a fraction of a second", path: "manifest.json", size: 3, modified: time.Unix(1000, 500_000_000), records: paxRecord("mtime", "1000.5"), ustar: "manifest.json", sizeField: 3, mtimeField: 1000},
		{name: "top-level member", path: "manifest.json", size: 3, modified: seconds, ustar: "manifest.json", sizeField: 3, mtimeField: 1000},
		{name: "path of exactly 100 bytes", path: "items/000001/" + strings.Repeat("a", 87), size: 3, modified: seconds, ustar: "items/000001/" + strings.Repeat("a", 87), sizeField: 3, mtimeField: 1000},
		{name: "long name with a non-ASCII end", path: "items/000001/" + strings.Repeat("a", 100) + "é", size: 3, modified: seconds,
			records: paxPath("items/000001/" + strings.Repeat("a", 100) + "é"), ustar: asciiName("items/000001/" + strings.Repeat("a", 100) + "é"), sizeField: 3, mtimeField: 1000},
		{name: "fraction of a second past the octal limit", path: "items/000001/a.jpg", size: 3, modified: time.Unix(octalLimit, 5),
			records: paxRecord("mtime", fmt.Sprint(octalLimit)+".000000005"), ustar: "items/000001/a.jpg", sizeField: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got bytes.Buffer
			if err := tar.NewWriter(&got).WriteHeader(memberHeader(tc.path, tc.size, tc.modified)); err != nil {
				t.Fatal(err)
			}
			var want []byte
			if tc.records != "" {
				want = rawExtended(tc.path, tc.records, nil)
			}
			want = append(want, rawHeader(tc.ustar, tc.prefix, '0', tc.sizeField, tc.mtimeField, nil)...)
			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("the writer's header differs from the specified bytes:\n got %q\nwant %q", got.Bytes(), want)
			}
			// The reader must accept every layout the writer produces.
			body := &countingReader{r: bytes.NewReader(got.Bytes())}
			hdr, err := nextMember(tar.NewReader(body), body)
			if err != nil || hdr.Name != tc.path || hdr.Size != tc.size || !hdr.ModTime.Equal(tc.modified) {
				t.Errorf("the reader doesn't accept the writer's header: %+v, %v", hdr, err)
			}
		})
	}
}

// TestTarHeaderBlocks reads packs whose raw headers differ from what the writer
// writes, each in one way. All of them are rejected, even those that stock tar
// tools write or archive/tar reads without complaint.
func TestTarHeaderBlocks(t *testing.T) {
	id := newIdentity(t)
	body := []byte("abc")

	const plain = "a.jpg"
	path := originalPath(1, plain)
	set := func(offset int, value string) func([]byte) {
		return func(blk []byte) { copy(blk[offset:], value) }
	}
	setChecksum := func(member []byte, format string) []byte {
		member = bytes.Clone(member)
		copy(member[148:156], fmt.Sprintf(format, member[148:154]))
		return member
	}
	for _, tc := range []struct {
		name     string
		original []byte
		want     string
	}{
		{"the writer's layout", rawMember(path, body, nil), ""},
		{"no magic", rawMember(path, body, set(257, "\x00\x00\x00\x00\x00\x00\x00\x00")), "tar header"},
		{"GNU magic", rawMember(path, body, set(257, "ustar  \x00")), "tar header"},
		{"other ustar version", rawMember(path, body, set(263, "01")), "tar header"},
		{"star trailer", rawMember(path, body, set(508, "tar\x00")), "tar header"},
		{"numbers as bsdtar writes them", rawMember(path, body, func(blk []byte) { copy(blk[100:], "000644 \x00000000 \x00000000 \x00") }), "tar header"},
		{"mode 0600", rawMember(path, body, set(100, "0000600\x00")), "tar header"},
		{"uid", rawMember(path, body, set(108, "0000001\x00")), "tar header"},
		{"gid", rawMember(path, body, set(116, "0000001\x00")), "tar header"},
		{"linkname", rawMember(path, body, set(157, "x")), "tar header"},
		{"uname", rawMember(path, body, set(265, "someone")), "tar header"},
		{"gname", rawMember(path, body, set(297, "someone")), "tar header"},
		{"prefix", rawMember(plain, body, set(345, "items/000001")), "tar header"},
		{"data in an unused byte", rawMember(path, body, set(500, "x")), "tar header"},
		{"old regular file type", rawMember(path, body, set(156, "\x00")), "tar header"},
		{"checksum after a space", setChecksum(rawMember(path, body, nil), " %s\x00"), "tar header"},
		{"checksum after a NUL", setChecksum(rawMember(path, body, nil), "\x00%s "), "tar header"},
		{"checksum without its space", setChecksum(rawMember(path, body, nil), "%s\x00\x00"), "tar header"},
		{"extended header the member doesn't need", rawPaxMember(path, paxPath(path), nil, body), "tar header"},
		{"data in a member's padding", append(rawHeader(path, "", '0', 3, 0, nil), append([]byte("abcx"), make([]byte, blockSize-4)...)...), "padding"},
	} {
		t.Run("member/"+tc.name, func(t *testing.T) {
			checkRead(t, packWithOriginal(t, id, plain, body, tc.original), id, tc.want)
		})
	}

	const accented = "ö.jpg"
	path = originalPath(1, accented)
	pax := func(records string) []byte { return rawPaxMember(path, records, nil, body) }
	twoHeaders := rawExtended(path, paxPath("a"), nil)
	for _, tc := range []struct {
		name     string
		original []byte
		want     string
	}{
		{"the writer's layout", pax(paxPath(path)), ""},
		{"with a time", pax(paxRecord("mtime", "-1.5") + paxPath(path)), ""},
		{"no extended header", rawMember(path, body, nil), "tar header"},
		{"records out of order", pax(paxPath(path) + paxRecord("mtime", "1.5")), "tar header"},
		{"empty path record, with the name in the block", rawPaxMember(path, paxRecord("path", ""), nil, body), "tar header"},
		{"size record that isn't needed", pax(paxPath(path) + paxRecord("size", "3")), "tar header"},
		{"empty size record", pax(paxPath(path) + paxRecord("size", "")), "tar header"},
		{"size record with a plus sign", pax(paxPath(path) + paxRecord("size", "+3")), "tar header"},
		{"record length with a plus sign", pax(fmt.Sprintf("+%d path=%s\n", len(paxPath(path))+1, path)), "tar header"},
		{"record length with a leading zero", pax("0" + paxPath(path)), "tar"},
		{"mtime record that isn't needed", pax(paxRecord("mtime", "1") + paxPath(path)), "tar header"},
		{"mtime record with a trailing zero", pax(paxRecord("mtime", "1.50") + paxPath(path)), "tar header"},
		{"mtime record with a leading zero", pax(paxRecord("mtime", "-01.5") + paxPath(path)), "tar header"},
		{"mtime record at the start of year 1", pax(paxRecord("mtime", "-62135596800") + paxPath(path)), "tar header"},
		{"mtime record over 64 bits", pax(paxRecord("mtime", "9223372036854775808") + paxPath(path)), "tar header"},
		{"mtime record with a plus sign", pax(paxRecord("mtime", "+1.5") + paxPath(path)), "tar header"},
		{"empty mtime record", pax(paxRecord("mtime", "") + paxPath(path)), "tar header"},
		{"empty uid record", pax(paxPath(path) + paxRecord("uid", "")), "tar header"},
		{"uid record", pax(paxPath(path) + paxRecord("uid", "3")), "tar header"},
		{"uid record that isn't an integer", pax(paxPath(path) + paxRecord("uid", "abc")), "tar header"},
		{"uname with invalid UTF-8", pax(paxPath(path) + paxRecord("uname", "\xff")), "tar header"},
		{"uname with a NUL", pax(paxPath(path) + paxRecord("uname", "a\x00b")), "tar header"},
		{"atime record", pax(paxRecord("atime", "1") + paxPath(path)), "tar header"},
		{"comment record", pax(paxRecord("comment", "") + paxPath(path)), "tar header"},
		{"other header name", append(rawHeader("ext", "", 'x', int64(len(paxPath(path))), 0, nil), append(rawBody([]byte(paxPath(path))), rawMember(asciiName(path), body, nil)...)...), "tar header"},
		{"header with GNU magic", rawPaxMember(path, paxPath(path), set(257, "ustar  \x00"), body), "tar header"},
		{"header with device numbers", rawPaxMember(path, paxPath(path), set(329, "0000000\x000000000\x00"), body), "tar header"},
		{"data in the padding of the records", append(append(rawHeader(asciiName("items/000001/PaxHeaders.0/ö.jpg"), "", 'x', int64(len(paxPath(path))), 0, nil), append([]byte(paxPath(path)+"x"), make([]byte, blockSize-len(paxPath(path))-1)...)...), rawMember(asciiName(path), body, nil)...), "tar header"},
		{"GNU long name", append(append(rawHeader("ext", "", 'L', int64(len(path)+1), 0, nil), rawBody([]byte(path+"\x00"))...), rawMember("short", body, nil)...), "tar header"},
		{"two extended headers", append(bytes.Clone(twoHeaders), pax(paxPath(path))...), "tar header"},
		{"unbounded extended headers", append(bytes.Repeat(twoHeaders, 4000), pax(paxPath(path))...), "extended header"},
		{"extended header's checksum after a NUL", setChecksum(pax(paxPath(path)), "\x00%s "), "tar header"},
	} {
		t.Run("pax/"+tc.name, func(t *testing.T) {
			checkRead(t, packWithOriginal(t, id, accented, body, tc.original), id, tc.want)
		})
	}
}

// packWithOriginal returns a pack of one item with the given name and bytes,
// whose original is written as the given raw member.
func packWithOriginal(t *testing.T, id *age.HybridIdentity, file string, body, original []byte) []byte {
	t.Helper()
	sidecar := []byte(strings.Replace(goodSidecar, "a.jpg", file, 1))
	sum := func(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
	manifest := []byte(stdManifest(fmt.Sprintf(`[{"path":%q,"size":%d,"sha256":%q},{"path":%q,"size":%d,"sha256":%q}]`,
		sidecarPath(1), len(sidecar), sum(sidecar), originalPath(1, file), len(body), sum(body))))
	plaintext := bytes.Join([][]byte{
		rawMember(sidecarPath(1), sidecar, nil),
		original,
		rawMember(manifestPath, manifest, nil),
		rawMember(signaturePath, ed25519.Sign(testSigner, manifest), nil),
		make([]byte, 2*blockSize),
	}, nil)
	return encrypt(t, plaintext, id.Recipient())
}

// TestNumericHeaderFields reads packs whose member block or extended header
// block has one numeric field in a form other than the writer's. Each form
// keeps the field's value, so only the form differs, and every form is
// rejected.
func TestNumericHeaderFields(t *testing.T) {
	id := newIdentity(t)
	body := []byte("abc")
	forms := []struct {
		name string
		form func(digits string, width int) string
	}{
		{"digits and NULs", func(d string, _ int) string { return d }},
		{"leading spaces", func(d string, _ int) string { return "  " + d }},
		{"no terminator", func(d string, w int) string { return strings.Repeat("0", w-len(d)) + d }},
		{"trailing space", func(d string, _ int) string { return d + " " }},
		{"junk after a NUL", func(d string, _ int) string { return d + "\x00x" }},
		{"NUL before the digits", func(d string, _ int) string { return "\x00" + d }},
		{"space among the digits", func(d string, _ int) string { return d + " 0" }},
		{"all spaces", func(_ string, w int) string { return strings.Repeat(" ", w) }},
		{"base-256 marker 0x80", func(string, int) string { return "\x80" }},
		{"base-256 marker 0xff", func(_ string, w int) string { return strings.Repeat("\xff", w) }},
		{"base-256 marker 0x81", func(string, int) string { return "\x81" }},
		{"base-256 marker 0xc0", func(string, int) string { return "\xc0" }},
	}
	fields := []struct {
		name       string
		start, end int
	}{
		{"mode", 100, 108},
		{"uid", 108, 116},
		{"gid", 116, 124},
		{"size", 124, 136},
		{"mtime", 136, 148},
		{"chksum", 148, 156},
		{"devmajor", 329, 337},
		{"devminor", 337, 345},
	}
	for _, f := range fields {
		for _, tc := range forms {
			setField := func(blk []byte) {
				digits := strings.TrimLeft(strings.TrimRight(string(blk[f.start:f.end]), " \x00"), " 0")
				if digits == "" {
					digits = "0"
				}
				field := tc.form(digits, f.end-f.start)
				copy(blk[f.start:f.end], field+strings.Repeat("\x00", f.end-f.start-len(field)))
			}
			edit, finish := setField, func(member []byte) []byte { return member }
			if f.name == "chksum" {
				edit = nil
				finish = func(member []byte) []byte {
					setField(member)
					return member
				}
			}
			t.Run(f.name+"/"+tc.name+"/member", func(t *testing.T) {
				original := finish(rawMember(originalPath(1, "a.jpg"), body, edit))
				checkRead(t, packWithOriginal(t, id, "a.jpg", body, original), id, "tar")
			})
			t.Run(f.name+"/"+tc.name+"/extended header", func(t *testing.T) {
				path := originalPath(1, "ö.jpg")
				original := finish(rawPaxMember(path, paxPath(path), edit, body))
				checkRead(t, packWithOriginal(t, id, "ö.jpg", body, original), id, "tar")
			})
		}
	}
}
