package pack

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"filippo.io/age"
)

// testSigner signs the packs that tests write, and trusted trusts it.
var (
	testSigner = func() ed25519.PrivateKey {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		return key
	}()
	trusted = []ed25519.PublicKey{testSigner.Public().(ed25519.PublicKey)}
)

type testItem struct {
	Item
	content []byte
}

func newTestItem(name string, content []byte) testItem {
	return testItem{
		Item: Item{
			Name:     name,
			Size:     int64(len(content)),
			Modified: time.Date(2026, 10, 30, 10, 15, 0, 123456789, time.UTC),
			MimeType: "image/jpeg",
			Source: Source{
				ID:       "test.source",
				Key:      "key/" + name,
				Metadata: map[string]string{"album": "Camera", "note": "<b>&</b>"},
			},
		},
		content: content,
	}
}

// pseudoRandom returns n deterministic, incompressible-looking bytes.
func pseudoRandom(n int, seed byte) []byte {
	b := make([]byte, n)
	var block [32]byte
	for i := 0; i < n; i += len(block) {
		block = sha256.Sum256(append(block[:], seed))
		copy(b[i:], block[:])
	}
	return b
}

func testItems() []testItem {
	old := newTestItem(strings.Repeat("long name ", 20)+".jpg", []byte("a path over 100 bytes"))
	old.Modified = time.Date(1969, 12, 31, 23, 59, 59, 500_000_000, time.UTC)
	return []testItem{
		newTestItem("IMG_0001.jpg", pseudoRandom(1000, 1)),
		newTestItem("empty.jpg", nil),
		// Larger than one 64 KiB age chunk.
		newTestItem("VID_0002.mp4", pseudoRandom(200_000, 2)),
		newTestItem("Sommar på ön ✓.heic", []byte("unicode name")),
		old,
	}
}

func newIdentity(t *testing.T) *age.HybridIdentity {
	t.Helper()
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func writePack(t *testing.T, items []testItem, recipients ...*age.HybridRecipient) ([]byte, *Manifest) {
	t.Helper()
	return writePackSigned(t, testSigner, items, recipients...)
}

func writePackSigned(t *testing.T, signer ed25519.PrivateKey, items []testItem, recipients ...*age.HybridRecipient) ([]byte, *Manifest) {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, signer, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if err := w.Add(it.Item, bytes.NewReader(it.content)); err != nil {
			t.Fatal(err)
		}
	}
	m, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != w.ID() {
		t.Fatalf("manifest ID %q, writer ID %q", m.ID, w.ID())
	}
	return buf.Bytes(), m
}

func readPack(data []byte, id age.Identity) ([]testItem, *Manifest, error) {
	var got []testItem
	m, err := Read(bytes.NewReader(data), id, trusted, func(it Item, r io.Reader) error {
		content, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		got = append(got, testItem{Item: it, content: content})
		return nil
	})
	return got, m, err
}

func checkItems(t *testing.T, got, want []testItem) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("read %d items, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Name != w.Name || g.Size != w.Size || !g.Modified.Equal(w.Modified) || g.MimeType != w.MimeType ||
			g.Source.ID != w.Source.ID || g.Source.Key != w.Source.Key {
			t.Errorf("item %d metadata = %+v, want %+v", i+1, g.Item, w.Item)
		}
		wantMeta := w.Source.Metadata
		if wantMeta == nil {
			wantMeta = map[string]string{}
		}
		if fmt.Sprint(g.Source.Metadata) != fmt.Sprint(wantMeta) {
			t.Errorf("item %d source metadata = %v, want %v", i+1, g.Source.Metadata, wantMeta)
		}
		if !bytes.Equal(g.content, w.content) {
			t.Errorf("item %d content differs: got %d bytes, want %d", i+1, len(g.content), len(w.content))
		}
	}
}

func TestRoundTrip(t *testing.T) {
	owner, successor := newIdentity(t), newIdentity(t)
	items := testItems()

	for _, tc := range []struct {
		name       string
		recipients []*age.HybridRecipient
		readers    []*age.HybridIdentity
	}{
		{"owner only", []*age.HybridRecipient{owner.Recipient()}, []*age.HybridIdentity{owner}},
		{"owner and successor", []*age.HybridRecipient{owner.Recipient(), successor.Recipient()}, []*age.HybridIdentity{owner, successor}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, written := writePack(t, items, tc.recipients...)
			if !packIDPattern.MatchString(written.ID) {
				t.Errorf("pack ID %q is malformed", written.ID)
			}
			if written.Writer != WriterVersion || written.Signer != hex.EncodeToString(trusted[0]) {
				t.Errorf("manifest writer %q, signer %q", written.Writer, written.Signer)
			}
			if len(written.Members) != 2*len(items) {
				t.Errorf("manifest has %d members, want %d", len(written.Members), 2*len(items))
			}
			for _, id := range tc.readers {
				got, m, err := readPack(data, id)
				if err != nil {
					t.Fatal(err)
				}
				checkItems(t, got, items)
				if m.ID != written.ID || !m.Created.Equal(written.Created) || m.Writer != written.Writer ||
					m.Signer != written.Signer || !slices.Equal(m.Members, written.Members) {
					t.Errorf("read manifest %+v, wrote %+v", m, written)
				}
			}
		})
	}
}

func TestWriterVersion(t *testing.T) {
	if !writerPattern.MatchString(WriterVersion) || len(WriterVersion) > maxWriterBytes {
		t.Errorf("WriterVersion %q doesn't follow the format", WriterVersion)
	}
}

func TestEmptyPack(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, nil, id.Recipient())
	got, m, err := readPack(data, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || len(m.Members) != 0 {
		t.Errorf("empty pack read back %d items and %d members", len(got), len(m.Members))
	}
}

func TestMemberLayout(t *testing.T) {
	id := newIdentity(t)
	items := testItems()
	data, m := writePack(t, items, id.Recipient())
	var want []string
	for i, it := range items {
		want = append(want, sidecarPath(i+1), originalPath(i+1, it.Name))
	}
	want = append(want, manifestPath, signaturePath)

	var names []string
	for i, e := range decryptTar(t, data, id) {
		names = append(names, e.hdr.Name)
		// A ustar header is a valid pax header; pax records are added where a
		// name or time needs them.
		if e.hdr.Format&(tar.FormatUSTAR|tar.FormatPAX) == 0 || e.hdr.Format&tar.FormatGNU != 0 {
			t.Errorf("member %q has tar format %v, want ustar or pax", e.hdr.Name, e.hdr.Format)
		}
		// Stock tar tools restore files with these times.
		wantTime := m.Created
		if i < 2*len(items) {
			wantTime = items[i/2].Modified
		}
		if !e.hdr.ModTime.Equal(wantTime) {
			t.Errorf("member %q has tar time %v, want %v", e.hdr.Name, e.hdr.ModTime.UTC(), wantTime)
		}
	}
	if !slices.Equal(names, want) {
		t.Errorf("members = %q, want %q", names, want)
	}
}

func TestWriterNormalizesNames(t *testing.T) {
	id := newIdentity(t)
	nfd := "Sommar på ön Ångström.heic"
	nfc := "Sommar på ön Ångström.heic"
	it := newTestItem(nfd, []byte("x"))
	data, m := writePack(t, []testItem{it}, id.Recipient())
	got, _, err := readPack(data, id)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != nfc || m.Members[1].Path != originalPath(1, nfc) {
		t.Errorf("stored name %q, path %q, want %q", got[0].Name, m.Members[1].Path, nfc)
	}
	if got[0].Source.Key != "key/"+nfd {
		t.Errorf("source key %q changed, want %q", got[0].Source.Key, "key/"+nfd)
	}
}

// TestExtremeTimes round-trips the first and last times that RFC 3339 can
// hold.
func TestExtremeTimes(t *testing.T) {
	id := newIdentity(t)
	first, last := newTestItem("first.jpg", []byte("a")), newTestItem("last.jpg", []byte("b"))
	first.Modified = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
	last.Modified = time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC)
	items := []testItem{first, last}
	data, _ := writePack(t, items, id.Recipient())
	got, _, err := readPack(data, id)
	if err != nil {
		t.Fatal(err)
	}
	checkItems(t, got, items)
}

// TestWriterStoresUTC checks that a time in another zone is stored in UTC,
// which is the only form the reader accepts.
func TestWriterStoresUTC(t *testing.T) {
	id := newIdentity(t)
	it := newTestItem("IMG_0001.jpg", []byte("abc"))
	it.Modified = time.Date(2026, 10, 30, 11, 15, 0, 5, time.FixedZone("CET", 3600))
	data, _ := writePack(t, []testItem{it}, id.Recipient())
	got, _, err := readPack(data, id)
	if err != nil {
		t.Fatal(err)
	}
	checkItems(t, got, []testItem{it})
	if sidecar := decryptTar(t, data, id)[0].body; !bytes.Contains(sidecar, []byte(`"modified": "2026-10-30T10:15:00.000000005Z"`)) {
		t.Errorf("sidecar doesn't hold the time in UTC:\n%s", sidecar)
	}
}

func TestSignature(t *testing.T) {
	owner := newIdentity(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Anyone with the owner's public key can write a pack for the owner, but
	// only a trusted device can sign it.
	recipient, err := age.ParseHybridRecipient(owner.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	forged, m := writePackSigned(t, other, testItems()[:1], recipient)
	if _, err := Read(bytes.NewReader(forged), owner, trusted, nil); !errors.Is(err, ErrUntrustedSigner) || !strings.Contains(err.Error(), m.Signer) {
		t.Errorf("pack from another signer: Read error = %v, want ErrUntrustedSigner", err)
	}
	// No list of trusted signers, however it came about, trusts every key.
	for name, signers := range map[string][]ed25519.PublicKey{
		"nil":                   nil,
		"empty":                 {},
		"collected from no key": slices.Collect(maps.Values(map[string]ed25519.PublicKey{})),
	} {
		if _, err := Read(bytes.NewReader(forged), owner, signers, nil); !errors.Is(err, ErrUntrustedSigner) {
			t.Errorf("pack from another signer, %s signers: Read error = %v, want ErrUntrustedSigner", name, err)
		}
	}
	// Accepting any signer takes an explicit choice, and still checks the
	// signature.
	got, err := ReadAnySigner(bytes.NewReader(forged), owner, nil)
	if err != nil {
		t.Fatalf("pack from another signer, any signer: ReadAnySigner error = %v", err)
	}
	if got.Signer != hex.EncodeToString(other.Public().(ed25519.PublicKey)) {
		t.Errorf("ReadAnySigner returned signer %q", got.Signer)
	}
	entries := decryptTar(t, forged, owner)
	entries[len(entries)-1].body = ed25519.Sign(other, []byte("another manifest"))
	if _, err := ReadAnySigner(bytes.NewReader(encryptTar(t, entries, owner.Recipient())), owner, nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "doesn't verify") {
		t.Errorf("bad signature, any signer: ReadAnySigner error = %v, want ErrInvalid", err)
	}
	both := append(slices.Clone(trusted), other.Public().(ed25519.PublicKey))
	if _, err := Read(bytes.NewReader(forged), owner, both, nil); err != nil {
		t.Errorf("pack from the second trusted signer: Read error = %v", err)
	}
}

func TestPartialReadByCallback(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, testItems(), id.Recipient())
	n := 0
	_, err := Read(bytes.NewReader(data), id, trusted, func(it Item, r io.Reader) error {
		n++
		_, err := io.ReadFull(r, make([]byte, min(it.Size, 3)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testItems()) {
		t.Errorf("callback ran %d times, want %d", n, len(testItems()))
	}
	if _, err := Read(bytes.NewReader(data), id, trusted, nil); err != nil {
		t.Errorf("Read with nil callback: %v", err)
	}
}

func TestCallbackError(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, testItems(), id.Recipient())
	stop := errors.New("stop")
	_, err := Read(bytes.NewReader(data), id, trusted, func(Item, io.Reader) error { return stop })
	if err != stop {
		t.Errorf("Read error = %v, want the callback's error", err)
	}
}

func TestWrongKey(t *testing.T) {
	owner, successor, other := newIdentity(t), newIdentity(t), newIdentity(t)
	for _, recipients := range [][]*age.HybridRecipient{
		{owner.Recipient()},
		{owner.Recipient(), successor.Recipient()},
	} {
		data, _ := writePack(t, testItems(), recipients...)
		if _, err := Read(bytes.NewReader(data), other, trusted, nil); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%d recipients: Read error = %v, want ErrWrongKey", len(recipients), err)
		}
	}

	classic, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := writePack(t, testItems(), owner.Recipient())
	if _, err := Read(bytes.NewReader(data), classic, trusted, nil); !errors.Is(err, ErrWrongKey) {
		t.Errorf("classic identity: Read error = %v, want ErrWrongKey", err)
	}
}

// failsClearly reports whether err is one of the documented pack errors.
func failsClearly(err error) bool {
	return errors.Is(err, ErrInvalid) || errors.Is(err, ErrWrongKey)
}

func TestFlippedByte(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, testItems(), id.Recipient())
	headerLen := bytes.Index(data, []byte("\n--- ")) + 1

	positions := []int{0, headerLen - 1, headerLen + 3, headerLen + 50, len(data) / 2, len(data) - 1}
	for i := 0; i < len(data); i += len(data) / 97 {
		positions = append(positions, i)
	}
	for _, pos := range positions {
		for _, mask := range []byte{0x01, 0x80} {
			damaged := bytes.Clone(data)
			damaged[pos] ^= mask
			_, _, err := readPack(damaged, id)
			if !failsClearly(err) {
				t.Fatalf("byte %d of %d flipped with %#x: Read error = %v", pos, len(data), mask, err)
			}
			// Damage after the header can't look like a wrong key.
			if pos > headerLen+100 && !errors.Is(err, ErrInvalid) {
				t.Errorf("byte %d flipped: Read error = %v, want ErrInvalid", pos, err)
			}
		}
	}
}

func TestTruncated(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, testItems(), id.Recipient())
	lengths := []int{0, 1, 20, len(data) / 2, len(data) - 17, len(data) - 1}
	// Cut at and around 64 KiB chunk boundaries of the payload.
	headerLen := bytes.Index(data, []byte("\n--- ")) + 1
	for _, off := range []int{0, 1, 15, 16, 17} {
		for chunk := 1; chunk <= 3; chunk++ {
			l := headerLen + 16 + chunk*(64*1024+16) + off - 16
			if l < len(data) {
				lengths = append(lengths, l)
			}
		}
	}
	for l := 1; l < len(data); l += len(data) / 61 {
		lengths = append(lengths, l)
	}
	for _, l := range lengths {
		_, _, err := readPack(data[:l], id)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("truncated to %d of %d bytes: Read error = %v, want ErrInvalid", l, len(data), err)
		}
	}
}

// TestSourceError checks that a failure to read the pack isn't reported as
// damage to the pack.
func TestSourceError(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, testItems(), id.Recipient())
	reset := errors.New("connection reset by peer")
	resetAfter := func(n int) func() io.Reader {
		return func() io.Reader { return io.MultiReader(bytes.NewReader(data[:n]), iotest.ErrReader(reset)) }
	}
	for _, tc := range []struct {
		name string
		src  func() io.Reader
		want error
	}{
		{"timeout on the second read", func() io.Reader { return iotest.TimeoutReader(bytes.NewReader(data)) }, iotest.ErrTimeout},
		{"reset in the payload", resetAfter(len(data) / 2), reset},
		{"reset near the end", resetAfter(len(data) - 10), reset},
	} {
		for name, fn := range map[string]func(Item, io.Reader) error{
			"no callback":            nil,
			"callback returns error": func(_ Item, r io.Reader) error { _, err := io.ReadAll(r); return err },
			"callback replaces error": func(_ Item, r io.Reader) error {
				if _, err := io.ReadAll(r); err != nil {
					return errors.New("restore failed")
				}
				return nil
			},
		} {
			_, err := Read(tc.src(), id, trusted, fn)
			if !errors.Is(err, tc.want) || failsClearly(err) {
				t.Errorf("%s, %s: Read error = %v, want %v and not ErrInvalid", tc.name, name, err, tc.want)
			}
		}
	}
}

type tarEntry struct {
	hdr  *tar.Header
	body []byte
}

func decryptTar(t *testing.T, data []byte, id age.Identity) []tarEntry {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(r)
	var entries []tarEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, tarEntry{hdr, body})
	}
}

// tarBytes returns a tar archive of entries, with each header's size set to
// the length of its body.
func tarBytes(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := *e.hdr
		hdr.Size = int64(len(e.body))
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encrypt(t *testing.T, plaintext []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encryptTar(t *testing.T, entries []tarEntry, recipients ...age.Recipient) []byte {
	t.Helper()
	return encrypt(t, tarBytes(t, entries), recipients...)
}

func regular(name string, body string) tarEntry {
	return tarEntry{&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Format: tar.FormatPAX}, []byte(body)}
}

// resign returns entries with the signature that follows manifest.json
// replaced by testSigner's signature of it. Entries without that pair are
// returned unchanged.
func resign(entries []tarEntry) []tarEntry {
	out := slices.Clone(entries)
	for i := 0; i+1 < len(out); i++ {
		if out[i].hdr.Name == manifestPath && out[i+1].hdr.Name == signaturePath {
			out[i+1] = tarEntry{out[i+1].hdr, ed25519.Sign(testSigner, out[i].body)}
		}
	}
	return out
}

// withManifest returns entries with the manifest, the second-to-last entry,
// rewritten to list exactly the entries before it.
func withManifest(t *testing.T, entries []tarEntry) []tarEntry {
	t.Helper()
	at := len(entries) - 2
	m, err := parseManifest(entries[at].body)
	if err != nil {
		t.Fatal(err)
	}
	m.Members = []Member{}
	for _, e := range entries[:at] {
		sum := sha256.Sum256(e.body)
		m.Members = append(m.Members, Member{Path: e.hdr.Name, Size: int64(len(e.body)), SHA256: hex.EncodeToString(sum[:])})
	}
	body, err := marshalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	out := slices.Clone(entries)
	out[at] = tarEntry{entries[at].hdr, body}
	return out
}

func TestTamperedMembers(t *testing.T) {
	id := newIdentity(t)
	data, _ := writePack(t, testItems()[:2], id.Recipient())
	orig := decryptTar(t, data, id)
	// orig: 0 sidecar 1, 1 original 1, 2 sidecar 2, 3 original 2, 4 manifest,
	// 5 signature.

	remove := func(i ...int) []tarEntry {
		var out []tarEntry
		for j, e := range orig {
			if !slices.Contains(i, j) {
				out = append(out, e)
			}
		}
		return out
	}
	insert := func(i int, e tarEntry) []tarEntry { return slices.Insert(slices.Clone(orig), i, e) }
	replaceBody := func(i int, body string) []tarEntry {
		out := slices.Clone(orig)
		out[i] = tarEntry{orig[i].hdr, []byte(body)}
		return out
	}
	sidecar1 := string(orig[0].body)
	manifest := string(orig[4].body)

	for _, tc := range []struct {
		name    string
		entries []tarEntry
		want    string
		// unsigned keeps the signature as it is. Otherwise the manifest is
		// signed again, so that only the tampering itself is detected.
		unsigned bool
	}{
		{"missing original", remove(1), `member "items/000001/IMG_0001.jpg" is missing`, false},
		{"missing original, manifest updated", withManifest(t, remove(1)), `member "items/000001/IMG_0001.jpg" is missing`, false},
		{"missing sidecar", remove(0), `unexpected member "items/000001/IMG_0001.jpg"`, false},
		{"missing last item", withManifest(t, remove(3)), `member "items/000002/empty.jpg" is missing`, false},
		{"missing manifest", remove(4, 5), `member "manifest.json" is missing`, false},
		{"missing signature", remove(5), `member "manifest.sig" is missing`, false},
		{"signature before manifest", append(remove(4, 5), orig[5], orig[4]), `unexpected member "manifest.sig"`, false},
		{"extra member at end", append(slices.Clone(orig), regular("extra.txt", "x")), `unexpected member "extra.txt" after "manifest.sig"`, false},
		{"extra member before signature", insert(5, regular("extra.txt", "x")), `unexpected member "extra.txt" after "manifest.json", expected "manifest.sig"`, false},
		{"extra member in middle", insert(2, regular("extra.txt", "x")), `unexpected member "extra.txt"`, false},
		{"extra member listed in manifest", withManifest(t, insert(4, regular("extra.txt", "x"))), `unexpected member "extra.txt"`, false},
		{"extra member between sidecar and original", insert(1, regular("extra.txt", "x")), `member "items/000001/IMG_0001.jpg" is missing, found "extra.txt"`, false},
		{"duplicate member", insert(2, orig[1]), `unexpected member "items/000001/IMG_0001.jpg"`, false},
		{"directory member", insert(0, tarEntry{&tar.Header{Typeflag: tar.TypeDir, Name: "items/", Mode: 0o755}, nil}), `member "items/" has a tar header`, false},
		{"symlink member", insert(4, tarEntry{&tar.Header{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "/etc/passwd"}, nil}), `member "link" has a tar header`, false},
		{"changed original", replaceBody(1, strings.Repeat("x", 1000)), `member "items/000001/IMG_0001.jpg" has SHA-256`, false},
		{"changed original size", replaceBody(1, "short"), `member "items/000001/IMG_0001.jpg" is 5 bytes, its sidecar says 1000`, false},
		{"changed sidecar", replaceBody(0, strings.Replace(sidecar1, "Camera", "Kamera", 1)), `member "items/000001.json" has SHA-256`, false},
		{"sidecar with unknown field", replaceBody(0, strings.Replace(sidecar1, `"path"`, `"extra": 1, "path"`, 1)), `unknown field "extra"`, false},
		{"sidecar path outside its item", replaceBody(0, strings.Replace(sidecar1, "items/000001/", "items/000002/", 1)), `is not in "items/000001/"`, false},
		{"sidecar path traversal", replaceBody(0, strings.Replace(sidecar1, "IMG_0001.jpg", "../x", 1)), `contains a path separator`, false},
		{"manifest lists member twice", replaceBody(4, strings.Replace(manifest, `"members": [`, `"members": [{"path": "items/000001.json", "size": 1, "sha256": "00"},`, 1)), `lists "items/000001.json" twice`, false},
		{"manifest wrong version", replaceBody(4, strings.Replace(manifest, `"version": 1`, `"version": 2`, 1)), `version 2, expected 1`, false},
		{"manifest wrong format", replaceBody(4, strings.Replace(manifest, `"rautjoxa-pack"`, `"other"`, 1)), `format "other"`, false},
		{"manifest lists a member the pack lacks", replaceBody(4, strings.Replace(manifest, `"members": [`, `"members": [{"path": "items/000009.json", "size": 1, "sha256": "00"},`, 1)), `member "items/000009.json" is in manifest.json but missing from the pack`, false},
		{"manifest out of order", withManifestOrder(t, orig), `manifest.json lists members out of order`, false},
		{"manifest malformed ID", replaceBody(4, strings.Replace(manifest, `"id": "`, `"id": "X`, 1)), `malformed pack ID "X`, false},
		{"manifest without created time", replaceBody(4, strings.Replace(manifest, `"created"`, `"_"`, 1)), `unknown field "_"`, false},
		{"manifest without writer", replaceBody(4, regexpReplace(manifest, `"writer": "[^"]*",`, ``)), `missing field "writer"`, false},
		{"manifest empty writer", replaceBody(4, regexpReplace(manifest, `"writer": "[^"]*"`, `"writer": ""`)), `malformed writer ""`, false},
		{"manifest writer without version", replaceBody(4, regexpReplace(manifest, `"writer": "[^"]*"`, `"writer": "rautjoxa-core"`)), `malformed writer "rautjoxa-core"`, false},
		{"manifest writer too long", replaceBody(4, regexpReplace(manifest, `"writer": "[^"]*"`, `"writer": "w/`+strings.Repeat("1", 127)+`"`)), `malformed writer "w/1111`, false},
		{"manifest uppercase signer", replaceBody(4, regexpReplace(manifest, `"signer": "([^"]*)"`, `"signer": "`+strings.ToUpper(hex.EncodeToString(trusted[0]))+`"`)), `malformed signer key`, false},
		{"oversized sidecar", insert(0, regular("items/000001.json", strings.Repeat(" ", maxSidecarBytes+1))), `the limit is 1048576`, false},
		{"manifest not JSON", replaceBody(4, "not json"), `manifest.json: jsontext: invalid character`, false},
		{"manifest with trailing data", replaceBody(4, manifest+"{}"), `data after the JSON value`, false},
		{"manifest with trailing bracket", replaceBody(4, manifest+"]"), `manifest.json: jsontext: invalid character ']'`, false},
		{"manifest changed, not signed again", replaceBody(4, strings.Replace(manifest, WriterVersion, "rautjoxa-core/9.9.9", 1)), `manifest.sig doesn't verify`, true},
		{"signature of other data", replaceBody(5, string(ed25519.Sign(testSigner, []byte("other")))), `manifest.sig doesn't verify`, true},
		{"short signature", replaceBody(5, "x"), `member "manifest.sig" is 1 bytes, expected 64`, true},
		{"zero signature", replaceBody(5, string(make([]byte, 64))), `manifest.sig doesn't verify`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := tc.entries
			if !tc.unsigned {
				entries = resign(entries)
			}
			_, _, err := readPack(encryptTar(t, entries, id.Recipient()), id)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Read error = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Read error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// withManifestOrder returns entries with the manifest's first two members
// swapped.
func withManifestOrder(t *testing.T, entries []tarEntry) []tarEntry {
	t.Helper()
	at := len(entries) - 2
	m, err := parseManifest(entries[at].body)
	if err != nil {
		t.Fatal(err)
	}
	m.Members[0], m.Members[1] = m.Members[1], m.Members[0]
	body, err := marshalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	out := slices.Clone(entries)
	out[at] = tarEntry{entries[at].hdr, body}
	return out
}

func TestRecipientRule(t *testing.T) {
	id := newIdentity(t)
	entries := decryptTar(t, func() []byte { d, _ := writePack(t, testItems()[:1], id.Recipient()); return d }(), id)

	classic, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	data := encryptTar(t, entries, classic.Recipient())
	if _, err := Read(bytes.NewReader(data), classic, trusted, nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not \"mlkem768x25519\"") {
		t.Errorf("classic recipient: Read error = %v, want ErrInvalid", err)
	}

	recipients := []age.Recipient{id.Recipient(), newIdentity(t).Recipient(), newIdentity(t).Recipient()}
	data = encryptTar(t, entries, recipients...)
	if _, err := Read(bytes.NewReader(data), id, trusted, nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "3 recipient stanzas") {
		t.Errorf("three recipients: Read error = %v, want ErrInvalid", err)
	}
}

func TestWriterRejects(t *testing.T) {
	a, b := newIdentity(t).Recipient(), newIdentity(t).Recipient()
	for _, tc := range []struct {
		name       string
		signer     ed25519.PrivateKey
		recipients []*age.HybridRecipient
		want       string
	}{
		{"no recipients", testSigner, nil, "need 1 to 2 recipients, got 0"},
		{"three recipients", testSigner, []*age.HybridRecipient{a, b, newIdentity(t).Recipient()}, "need 1 to 2 recipients, got 3"},
		{"duplicate recipient", testSigner, []*age.HybridRecipient{a, a}, "duplicate recipient"},
		{"nil recipient", testSigner, []*age.HybridRecipient{a, nil}, "nil recipient"},
		{"nil signer", nil, []*age.HybridRecipient{a}, "signer key is 0 bytes"},
	} {
		if _, err := NewWriter(io.Discard, tc.signer, tc.recipients...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: NewWriter error = %v, want %q", tc.name, err, tc.want)
		}
	}

	good := newTestItem("IMG.jpg", []byte("abc"))
	for _, tc := range []struct {
		name   string
		modify func(*Item)
		r      io.Reader
		want   string
		// written means that Add fails only after writing part of the item,
		// so the writer can't be used any more.
		written bool
	}{
		{"empty name", func(it *Item) { it.Name = "" }, nil, "empty name", false},
		{"dot name", func(it *Item) { it.Name = ".." }, nil, "is reserved", false},
		{"slash in name", func(it *Item) { it.Name = "a/b.jpg" }, nil, "path separator", false},
		{"backslash in name", func(it *Item) { it.Name = `a\b.jpg` }, nil, "path separator", false},
		{"control character in name", func(it *Item) { it.Name = "a\nb.jpg" }, nil, "control character", false},
		{"C1 control character in name", func(it *Item) { it.Name = "a\u0085b.jpg" }, nil, "control character", false},
		{"invalid UTF-8 name", func(it *Item) { it.Name = "a\xffb.jpg" }, nil, "not valid UTF-8", false},
		{"long name", func(it *Item) { it.Name = strings.Repeat("a", 256) }, nil, "longer than 255 bytes", false},
		// U+0344 is 2 bytes and becomes 4 bytes in NFC.
		{"long name in NFC", func(it *Item) { it.Name = strings.Repeat("̈́", 100) }, nil, "longer than 255 bytes", false},
		{"no modified time", func(it *Item) { it.Modified = time.Time{} }, nil, "modified time not set", false},
		{"modified time after 9999", func(it *Item) { it.Modified = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, nil, "year outside of range", false},
		{"no source ID", func(it *Item) { it.Source.ID = "" }, nil, "source ID not set", false},
		{"no source key", func(it *Item) { it.Source.Key = "" }, nil, "source key not set", false},
		{"negative size", func(it *Item) { it.Size = -1 }, nil, "negative size", false},
		{"invalid UTF-8 MIME type", func(it *Item) { it.MimeType = "image/\xff" }, nil, `MIME type "image/\xff" is not valid UTF-8`, false},
		{"invalid UTF-8 source ID", func(it *Item) { it.Source.ID = "a\xffb" }, nil, `source ID "a\xffb" is not valid UTF-8`, false},
		{"invalid UTF-8 source key", func(it *Item) { it.Source.Key = "Takeout/a\xffb.heic" }, nil, `source key "Takeout/a\xffb.heic" is not valid UTF-8`, false},
		{"invalid UTF-8 metadata key", func(it *Item) { it.Source.Metadata = map[string]string{"a\xff": "v"} }, nil, `source metadata key "a\xff" is not valid UTF-8`, false},
		{"invalid UTF-8 metadata value", func(it *Item) { it.Source.Metadata = map[string]string{"k": "v\xff"} }, nil, `source metadata "k" value "v\xff" is not valid UTF-8`, false},
		{"huge sidecar", func(it *Item) { it.Source.Metadata = map[string]string{"x": strings.Repeat("x", maxSidecarBytes)} }, nil, "sidecar is larger than", false},
		{"short content", nil, strings.NewReader("ab"), "content is 2 bytes, expected 3", true},
		{"long content", nil, strings.NewReader("abcd"), "content is longer than 3 bytes", true},
		{"read error", nil, iotest.ErrReader(errors.New("disk on fire")), "disk on fire", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := newIdentity(t)
			var buf bytes.Buffer
			w, err := NewWriter(&buf, testSigner, id.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			it := good.Item
			if tc.modify != nil {
				tc.modify(&it)
				if err := it.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("Validate error = %v, want %q", err, tc.want)
				}
			}
			r := tc.r
			if r == nil {
				r = bytes.NewReader(good.content)
			}
			err = w.Add(it, r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Add error = %v, want %q", err, tc.want)
			}
			if tc.written {
				if err2 := w.Add(good.Item, bytes.NewReader(good.content)); err2 != err {
					t.Errorf("Add after a failure = %v, want the first error", err2)
				}
				if _, err2 := w.Close(); err2 != err {
					t.Errorf("Close after a failure = %v, want the first error", err2)
				}
				return
			}
			// Nothing was written, so the pack can go on.
			if err := w.Add(good.Item, bytes.NewReader(good.content)); err != nil {
				t.Fatalf("Add after a rejected item: %v", err)
			}
			if _, err := w.Close(); err != nil {
				t.Fatal(err)
			}
			got, _, err := readPack(buf.Bytes(), id)
			if err != nil {
				t.Fatal(err)
			}
			checkItems(t, got, []testItem{good})
		})
	}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate of a good item: %v", err)
	}
}

func TestWriterRefusesManifestOverflow(t *testing.T) {
	id := newIdentity(t)
	items := testItems()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testSigner, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items[:2] {
		if err := w.Add(it.Item, bytes.NewReader(it.content)); err != nil {
			t.Fatal(err)
		}
	}
	defer func(old int64) { maxManifestSize = old }(maxManifestSize)
	maxManifestSize = w.manifestSize

	err = w.Add(items[2].Item, bytes.NewReader(items[2].content))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("larger than its %d byte limit", maxManifestSize)) {
		t.Fatalf("Add error = %v, want a manifest size error", err)
	}
	if _, err := w.Close(); err != nil {
		t.Fatalf("Close after a refused item: %v", err)
	}
	got, _, err := readPack(buf.Bytes(), id)
	if err != nil {
		t.Fatal(err)
	}
	checkItems(t, got, items[:2])
}

// TestManifestSizeBound checks that the writer's bound of the manifest size
// is never smaller than the manifest, even for names that JSON escapes.
func TestManifestSizeBound(t *testing.T) {
	var items []testItem
	for _, name := range []string{"a", strings.Repeat(`"`, 255), strings.Repeat("\u2028", 85), strings.Repeat("<&>", 85), strings.Repeat("å", 127)} {
		it := newTestItem(name, nil)
		it.Size = 1<<63 - 1
		items = append(items, it)
	}
	w, err := NewWriter(io.Discard, testSigner, newIdentity(t).Recipient())
	if err != nil {
		t.Fatal(err)
	}
	for i, it := range items {
		// Record the members without writing their content.
		w.manifest.Members = append(w.manifest.Members,
			Member{Path: sidecarPath(i + 1), Size: 1 << 20, SHA256: strings.Repeat("a", 64)},
			Member{Path: originalPath(i+1, it.Name), Size: it.Size, SHA256: strings.Repeat("b", 64)})
		w.manifestSize += memberSizeBound(sidecarPath(i+1)) + memberSizeBound(originalPath(i+1, it.Name))
		m, err := marshalJSON(w.manifest)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(m)) > w.manifestSize {
			t.Fatalf("after %d items the manifest is %d bytes, more than the bound %d", i+1, len(m), w.manifestSize)
		}
	}
}

func TestObjectName(t *testing.T) {
	if got := ObjectName("0123456789abcdef0123456789abcdef"); got != "packs/0123456789abcdef0123456789abcdef.age" {
		t.Errorf("ObjectName = %q", got)
	}
}

func regexpReplace(s, pattern, repl string) string {
	return regexp.MustCompile(pattern).ReplaceAllString(s, repl)
}
