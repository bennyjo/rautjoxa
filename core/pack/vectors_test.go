package pack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// The checked-in vectors in testdata/v1 were written by TestWriteVectors and
// must never change: every later version of this package has to read them.
// They are also what CI restores with the stock age and tar tools.
const vectorDir = "testdata/v1"

var vectorsOut = flag.String("vectors-out", "", "write a fresh set of v1 test vectors to this `directory`")

// vectorHashes pins the SHA-256 of every file in testdata/v1, so that
// deleting and writing the vectors again fails a test.
var vectorHashes = map[string]string{
	"edge.age":                          "b932aead570e2ed9242ead857cc68a9f935ae6881673e162a73ee498358d426b",
	"empty.age":                         "8181c70f13b2e276ce3b22ade402fec9e1924d3fd16cffe514b39bdf08caee0a",
	"key1.txt":                          "75b1bd8f514c6492fa5cfded1b4d69da8fac6ff730577f76549d4c3b02e020f3",
	"key2.txt":                          "b6be5c159d99ee6b669403f0a7868bf32dd203f2008f172aa402f63f44698baf",
	"one-recipient.age":                 "4c17d3758612dff4e5deeda0a840a17866eac838aafcd041462b51a39b227633",
	"originals/IMG_20261030_101500.jpg": "5fdc259b92615d60cc8e5e98c6f65a363cb875a9cb9aa4eceb140d18b883fde9",
	"originals/Sommar på ön.heic":       "844dc1546e2fbecf0d2308b9ce9dd725aac8cb9d66b2bcb0f60f1aeec8b15ff4",
	"originals/VID_20261030_101600.mp4": "54a163c32f8cd874507cab2b4585a868b7ecfc3b1fc02724631b0dde60bbd5e0",
	"originals/empty.png":               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"signer.pub":                        "8f79b15462aeb809b88ca14ff870d86dee7c65bdd1415dcebb2b25facdd15602",
	"tolerated.age":                     "b51aa0de40fc4c8b25cc74f26b6f60eb9f92ade472366d03769e591076fec60b",
	"two-recipients.age":                "9ae55d82be943310160ec361aead0cfffbc30c1afc8e524607f2c6f82aa53872",
}

// vectorPacks lists each vector pack, the keys that must open it, and the
// items it holds.
var vectorPacks = []struct {
	file  string
	keys  []string
	items func(t *testing.T) []testItem
}{
	// Packs from the version 1 writer.
	{"one-recipient.age", []string{"key1.txt"}, vectorTestItems},
	{"two-recipients.age", []string{"key1.txt", "key2.txt"}, vectorTestItems},
	{"empty.age", []string{"key1.txt"}, func(*testing.T) []testItem { return nil }},
	{"edge.age", []string{"key1.txt"}, func(*testing.T) []testItem { return storedItems(edgeItems()) }},
	// A pack that a version 1 writer must not write but a reader must accept.
	{"tolerated.age", []string{"key1.txt"}, func(*testing.T) []testItem { return toleratedItems() }},
}

// vectorItems describes the files in testdata/v1/originals, in pack order.
func vectorItems() []Item {
	media := func(name, mime, id, takenMillis string) Item {
		return Item{
			Name:     name,
			Modified: time.Date(2026, 10, 30, 10, 15, 0, 250_000_000, time.UTC),
			MimeType: mime,
			Source: Source{
				ID:  "android.media",
				Key: "content://media/external/images/media/" + id,
				Metadata: map[string]string{
					"bucket_display_name": "Camera",
					"datetaken":           takenMillis,
					"relative_path":       "DCIM/Camera/",
				},
			},
		}
	}
	return []Item{
		media("IMG_20261030_101500.jpg", "image/jpeg", "1001", "1793355300000"),
		media("VID_20261030_101600.mp4", "video/mp4", "1002", "1793355360000"),
		{
			Name:     "Sommar på ön.heic",
			Modified: time.Date(2019, 7, 14, 18, 30, 5, 0, time.UTC),
			MimeType: "image/heic",
			Source: Source{
				ID:       "google.takeout",
				Key:      "Takeout/Google Photos/Sommar 2019/Sommar på ön.heic",
				Metadata: map[string]string{"photoTakenTime": "1563129005"},
			},
		},
		{
			Name:     "empty.png",
			Modified: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			MimeType: "",
			Source:   Source{ID: "test.empty", Key: "empty"},
		},
	}
}

func vectorTestItems(t *testing.T) []testItem {
	t.Helper()
	var items []testItem
	for _, it := range vectorItems() {
		content, err := os.ReadFile(filepath.Join(vectorDir, "originals", it.Name))
		if err != nil {
			t.Fatal(err)
		}
		it.Size = int64(len(content))
		items = append(items, testItem{Item: it, content: content})
	}
	return items
}

// edgeNames are file names that a version 1 writer may write, each with
// the name the writer stores, which differs only for names not in NFC.
var edgeNames = []struct{ name, stored string }{
	{strings.Repeat("a", 251) + ".jpg", ""},
	{strings.Repeat("å", 125) + ".jpg", ""},
	{"Sommar på ön.heic", "Sommar på ön.heic"},
	{"Sommar på ön.heic", ""},
	{"Ångström.jpg", "Ångström.jpg"},
	{"line\u2028sep.jpg", ""},
	{`quote"s.jpg`, ""},
	{"colon:star*q?.jpg", ""},
	{" leading space.jpg", ""},
	{"trailing dot.", ""},
	{"rtl\u202egpj.exe", ""},
	{"zero\u200bwidth.jpg", ""},
	{"emoji 📷.jpg", ""},
	{"-rf.jpg", ""},
	{"CON", ""},
	{"PaxHeaders.0", ""},
	{"日本語", ""},
	// An ASCII path over 100 bytes, which the writer splits between the
	// ustar prefix and name fields. That needs a whole-second time.
	{prefixSplitName, ""},
}

var prefixSplitName = strings.Repeat("a", 90) + ".jpg"

// edgeItems returns items with edge-case names, times, and metadata.
func edgeItems() []testItem {
	times := []time.Time{
		time.Date(1901, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1969, 12, 31, 23, 59, 59, 500_000_000, time.UTC),
		time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 30, 10, 15, 0, 123_456_789, time.UTC),
	}
	metadata := []map[string]string{
		nil,
		{"": ""},
		{"ключ": "värde ✓", `quote"`: "line\u2028sep", "html": "<b>&</b>"},
	}
	var items []testItem
	for i, n := range edgeNames {
		content := fmt.Appendf(nil, "content of edge item %d\n", i+1)
		if i == 3 {
			content = nil
		}
		modified := times[i%len(times)]
		if n.name == prefixSplitName {
			modified = time.Date(2026, 10, 30, 10, 15, 0, 0, time.UTC)
		}
		it := testItem{
			Item: Item{
				Name:     n.name,
				Size:     int64(len(content)),
				Modified: modified,
				MimeType: []string{"", "image/jpeg"}[i%2],
				Source: Source{
					ID:       "test.edge",
					Key:      fmt.Sprintf("edge/%d/%s", i+1, n.name),
					Metadata: metadata[i%len(metadata)],
				},
			},
			content: content,
		}
		items = append(items, it)
	}
	return items
}

// storedItems returns items as the writer stores them.
func storedItems(items []testItem) []testItem {
	for i := range items {
		if s := edgeNames[i].stored; s != "" {
			items[i].Name = s
		}
	}
	return items
}

// toleratedItems are the items of tolerated.age.
func toleratedItems() []testItem {
	return []testItem{
		{
			Item: Item{
				Name:     "Sommar på ön.heic",
				Size:     11,
				Modified: time.Date(2026, 10, 30, 10, 15, 0, 250_000_000, time.UTC),
				MimeType: "image/heic",
				Source: Source{
					ID:       "other.source",
					Key:      "/Sommar på ön.heic",
					Metadata: map[string]string{"z": "last", "a": "first"},
				},
			},
			content: []byte("NFD content"),
		},
		{
			Item: Item{
				Name:     "empty.png",
				Modified: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
				Source:   Source{ID: "other.source", Key: "empty", Metadata: map[string]string{}},
			},
		},
	}
}

// writeTolerated writes tolerated.age: a pack that no version 1 writer may
// write, because its first name isn't in NFC and zero bytes follow the end of
// the tar archive, but that every reader must accept. It also uses the
// freedom the format gives every writer: JSON in any layout and key order,
// with escapes. Its tar headers are in the one layout the format allows.
func writeTolerated(t *testing.T, signer ed25519.PrivateKey, recipient age.Recipient) []byte {
	t.Helper()
	items := toleratedItems()
	sidecars := []string{
		`{"source":{"metadata":{"z":"last","a":"first"},"key":"\/Sommar på ön.heic","id":"other.source"},` +
			`"mime_type":"image\/heic","modified":"2026-10-30T10:15:00.250Z","size":11,` +
			`"path":"items/000001/Sommar på ön.heic"}`,
		"{\n\t\"path\" : \"items/000002/empty.png\" ,\n\t\"size\" : 0,\n\t\"modified\" : \"2026-01-02T03:04:05Z\",\r\n" +
			"\t\"mime_type\" : \"\",\n\t\"source\" : { \"id\" : \"other.source\", \"key\" : \"empty\", \"metadata\" : { } }\n}\n",
	}
	entry := func(name string, modified time.Time, body []byte) tarEntry {
		return tarEntry{memberHeader(name, int64(len(body)), modified), body}
	}
	var entries []tarEntry
	var members []string
	add := func(e tarEntry) {
		entries = append(entries, e)
		sum := sha256.Sum256(e.body)
		path, err := json.Marshal(e.hdr.Name)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, fmt.Sprintf(`{"sha256":"%x","size":%d,"path":%s}`, sum, len(e.body), path))
	}
	for i, it := range items {
		add(entry(sidecarPath(i+1), it.Modified, []byte(sidecars[i])))
		add(entry(originalPath(i+1, it.Name), it.Modified, it.content))
	}
	manifest := []byte(fmt.Sprintf(`{"members":[%s],"signer":"%x","writer":"example-writer/1.0.0+build.5",`+
		`"created":"2026-10-31T12:00:00Z","id":"0123456789abcdef0123456789abcdef","version":1,"format":"rautjoxa-pack"}`,
		strings.Join(members, ","), signer.Public().(ed25519.PublicKey)))
	created := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	entries = append(entries, entry(manifestPath, created, manifest), entry(signaturePath, created, ed25519.Sign(signer, manifest)))

	// Pad with zeros to a whole 10240-byte record, as tar tools do.
	plaintext := tarBytes(t, entries)
	plaintext = append(plaintext, make([]byte, 10240-len(plaintext)%10240)...)
	return encrypt(t, plaintext, recipient)
}

func readIdentity(t *testing.T, path string) age.Identity {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("%s holds %d identities, want 1", path, len(ids))
	}
	return ids[0]
}

func readSignerKey(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(strings.TrimSuffix(string(data), "\n"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatalf("%s doesn't hold an Ed25519 public key in hexadecimal: %v", path, err)
	}
	return key
}

func TestVectorsV1(t *testing.T) {
	signer := readSignerKey(t, filepath.Join(vectorDir, "signer.pub"))
	for _, v := range vectorPacks {
		data, err := os.ReadFile(filepath.Join(vectorDir, v.file))
		if err != nil {
			t.Fatal(err)
		}
		want := v.items(t)
		for _, key := range v.keys {
			t.Run(v.file+"/"+key, func(t *testing.T) {
				id := readIdentity(t, filepath.Join(vectorDir, key))
				var got []testItem
				m, err := Read(bytes.NewReader(data), id, []ed25519.PublicKey{signer}, func(it Item, r io.Reader) error {
					content, err := io.ReadAll(r)
					got = append(got, testItem{Item: it, content: content})
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				checkItems(t, got, want)
				wantWriter := "rautjoxa-core/0.1.0"
				if v.file == "tolerated.age" {
					wantWriter = "example-writer/1.0.0+build.5"
				}
				if m.Version != 1 || len(m.Members) != 2*len(want) || m.Signer != hex.EncodeToString(signer) || m.Writer != wantWriter {
					t.Errorf("manifest = %+v, want writer %q", m, wantWriter)
				}
			})
		}
	}

	data, err := os.ReadFile(filepath.Join(vectorDir, vectorPacks[0].file))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(data), newIdentity(t), nil, nil); !errors.Is(err, ErrWrongKey) {
		t.Errorf("vector with an unrelated key: Read error = %v, want ErrWrongKey", err)
	}
	id := readIdentity(t, filepath.Join(vectorDir, vectorPacks[0].keys[0]))
	if _, err := Read(bytes.NewReader(data), id, trusted, nil); !errors.Is(err, ErrUntrustedSigner) {
		t.Errorf("vector with an unrelated signer: Read error = %v, want ErrUntrustedSigner", err)
	}
}

func TestVectorFilesPinned(t *testing.T) {
	seen := make(map[string]bool)
	err := filepath.WalkDir(vectorDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(vectorDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		seen[rel] = true
		want, ok := vectorHashes[rel]
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); !ok {
			t.Errorf("%s isn't pinned in vectorHashes; its SHA-256 is %s", rel, got)
		} else if got != want {
			t.Errorf("%s has SHA-256 %s, pinned %s; the vectors must never change", rel, got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range vectorHashes {
		if !seen[rel] {
			t.Errorf("pinned vector file %s is missing", rel)
		}
	}
}

// TestWriteVectors writes a fresh set of vectors when -vectors-out is set:
// two keys, a signer key, the vector packs, and a copy of the originals.
// Existing files are never overwritten. CI uses it to restore packs from the
// current writer with the stock tools.
func TestWriteVectors(t *testing.T) {
	if *vectorsOut == "" {
		t.Skip("set -vectors-out to write test vectors")
	}
	dir := *vectorsOut
	if err := os.MkdirAll(filepath.Join(dir, "originals"), 0o755); err != nil {
		t.Fatal(err)
	}
	create := func(name string, data []byte) {
		t.Helper()
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}

	key1, key2 := newIdentity(t), newIdentity(t)
	for name, id := range map[string]*age.HybridIdentity{"key1.txt": key1, "key2.txt": key2} {
		create(name, fmt.Appendf(nil,
			"# Test key from the Rautjoxa pack format test vectors. It is public:\n"+
				"# never use it to protect real data.\n# public key: %s\n%s\n",
			id.Recipient(), id))
	}
	signerPub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	create("signer.pub", fmt.Appendf(nil, "%x\n", signerPub))

	items := vectorTestItems(t)
	one, _ := writePackSigned(t, signer, items, key1.Recipient())
	create("one-recipient.age", one)
	two, _ := writePackSigned(t, signer, items, key1.Recipient(), key2.Recipient())
	create("two-recipients.age", two)
	empty, _ := writePackSigned(t, signer, nil, key1.Recipient())
	create("empty.age", empty)
	edge, _ := writePackSigned(t, signer, edgeItems(), key1.Recipient())
	create("edge.age", edge)
	create("tolerated.age", writeTolerated(t, signer, key1.Recipient()))

	if same, err := sameDir(dir, vectorDir); err != nil {
		t.Fatal(err)
	} else if !same {
		for _, it := range items {
			create(filepath.Join("originals", it.Name), it.content)
		}
	}
}

var bigOut = flag.String("big-out", "", "write a pack with an 8 GiB item to this `file`, such as a FIFO")

// TestWriteBigPack writes a pack with an item of 8 GiB, which needs a pax size
// record, when -big-out is set. It is encrypted to testdata/v1/key1.txt and
// signed by a fresh key whose public key it writes to signer.pub next to the
// pack, before the pack. CI streams the pack through a FIFO into age and the
// stock tar tools, so it never stores the pack.
func TestWriteBigPack(t *testing.T) {
	if *bigOut == "" {
		t.Skip("set -big-out to write a pack with a big item")
	}
	key := readIdentity(t, filepath.Join(vectorDir, "key1.txt")).(*age.HybridIdentity)
	signerPub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(*bigOut), "signer.pub"), fmt.Appendf(nil, "%x\n", signerPub), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(*bigOut, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := NewWriter(f, signer, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	modified := time.Date(2026, 10, 30, 10, 15, 0, 0, time.UTC)
	for _, it := range []struct {
		name string
		size int64
	}{{"before.bin", 7}, {"big.bin", 1 << 33}, {"after.bin", 6}} {
		item := Item{Name: it.name, Size: it.size, Modified: modified, Source: Source{ID: "test.big", Key: it.name}}
		if err := w.Add(item, io.LimitReader(zeros{}, it.size)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// zeros reads as an endless run of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func sameDir(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}
