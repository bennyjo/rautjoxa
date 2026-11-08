package pack

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/text/unicode/norm"
)

// Writer writes one pack. Create it with NewWriter, call Add for each item,
// then Close. If Add rejects an item before writing any of it, the writer
// stays usable. After any other error the pack is incomplete and must be
// discarded.
type Writer struct {
	enc      io.WriteCloser
	tw       *tar.Writer
	signer   ed25519.PrivateKey
	manifest Manifest
	// manifestSize is an upper bound of the size of manifest.json.
	manifestSize int64
	err          error
}

// NewWriter starts a pack written to dst, signed by signer, and encrypted to
// the given post-quantum recipients: the owner and, optionally, a successor.
// signer is the writing device's Ed25519 key.
func NewWriter(dst io.Writer, signer ed25519.PrivateKey, recipients ...*age.HybridRecipient) (*Writer, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("pack: signer key is %d bytes, expected %d", len(signer), ed25519.PrivateKeySize)
	}
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return nil, fmt.Errorf("pack: need 1 to %d recipients, got %d", MaxRecipients, len(recipients))
	}
	ageRecipients := make([]age.Recipient, len(recipients))
	seen := make(map[string]bool)
	for i, r := range recipients {
		if r == nil {
			return nil, errors.New("pack: nil recipient")
		}
		if seen[r.String()] {
			return nil, errors.New("pack: duplicate recipient")
		}
		seen[r.String()] = true
		ageRecipients[i] = r
	}
	id, err := newPackID()
	if err != nil {
		return nil, err
	}
	manifest := Manifest{
		Format:  formatName,
		Version: Version,
		ID:      id,
		Created: time.Now().UTC().Truncate(time.Second),
		Writer:  WriterVersion,
		Signer:  hex.EncodeToString(signer.Public().(ed25519.PublicKey)),
		Members: []Member{},
	}
	empty, err := marshalJSON(manifest)
	if err != nil {
		return nil, fmt.Errorf("pack: manifest: %w", err)
	}
	enc, err := age.Encrypt(dst, ageRecipients...)
	if err != nil {
		return nil, fmt.Errorf("pack: start encryption: %w", err)
	}
	return &Writer{
		enc:          enc,
		tw:           tar.NewWriter(enc),
		signer:       signer,
		manifest:     manifest,
		manifestSize: int64(len(empty)),
	}, nil
}

// ID returns the pack ID, which also names the stored object (see ObjectName).
func (w *Writer) ID() string {
	return w.manifest.ID
}

// Add writes one item: its sidecar, then exactly it.Size bytes read from r.
// The item's name is stored in NFC. Add fails if r holds fewer or more bytes
// than it.Size.
//
// If the item fails Validate, or the pack can't hold another item, Add
// returns an error without writing anything, and the writer stays usable.
func (w *Writer) Add(it Item, r io.Reader) error {
	if w.err != nil {
		return w.err
	}
	n := len(w.manifest.Members)/2 + 1
	if n > MaxItems {
		return fmt.Errorf("pack: the pack already holds %d items, the most it can hold", MaxItems)
	}
	stored, sc, err := it.prepare(n)
	if err != nil {
		return fmt.Errorf("pack: item %d: %w", n, err)
	}
	path := originalPath(n, stored.Name)
	grow := memberSizeBound(sidecarPath(n)) + memberSizeBound(path)
	if w.manifestSize+grow > maxManifestSize {
		return fmt.Errorf("pack: item %d would make manifest.json larger than its %d byte limit; start a new pack", n, maxManifestSize)
	}
	w.manifestSize += grow

	if w.err = w.writeMember(sidecarPath(n), stored.Modified, int64(len(sc)), bytes.NewReader(sc)); w.err != nil {
		return w.err
	}
	if w.err = w.writeMember(path, stored.Modified, stored.Size, r); w.err != nil {
		return w.err
	}
	var extra [1]byte
	switch k, err := io.ReadFull(r, extra[:]); {
	case k > 0:
		w.err = fmt.Errorf("pack: %s: content is longer than %d bytes", path, stored.Size)
	case err != io.EOF:
		w.err = fmt.Errorf("pack: %s: %w", path, err)
	}
	return w.err
}

// prepare applies the writer's rules to it as item n. It returns the item as
// it will be stored, with its name in NFC, and the item's sidecar.
func (it Item) prepare(n int) (Item, []byte, error) {
	it.Name = norm.NFC.String(it.Name)
	if err := it.accept(); err != nil {
		return Item{}, nil, err
	}
	if it.Modified.IsZero() {
		return Item{}, nil, errors.New("modified time not set")
	}
	it.Modified = it.Modified.UTC().Round(0)
	it.Source.Metadata = maps.Clone(it.Source.Metadata)
	if it.Source.Metadata == nil {
		it.Source.Metadata = map[string]string{}
	}
	sc, err := marshalJSON(sidecar{
		Path:     originalPath(n, it.Name),
		Size:     it.Size,
		Modified: it.Modified,
		MimeType: it.MimeType,
		Source:   it.Source,
	})
	if err != nil {
		return Item{}, nil, fmt.Errorf("sidecar: %w", err)
	}
	if len(sc) > maxSidecarBytes {
		return Item{}, nil, fmt.Errorf("sidecar is larger than %d bytes", maxSidecarBytes)
	}
	return it, sc, nil
}

// memberSizeBound returns an upper bound of the bytes that the record of the
// member at path adds to manifest.json.
func memberSizeBound(path string) int64 {
	b, _ := json.Marshal(Member{Path: path, Size: -1 << 63, SHA256: strings.Repeat("0", 64)})
	// Indentation and separators add 35 bytes to the compact form, which
	// already escapes at least as much as marshalJSON.
	return int64(len(b)) + 35
}

// writeMember writes one regular tar member of the given size from r and
// records it in the manifest.
func (w *Writer) writeMember(path string, modified time.Time, size int64, r io.Reader) error {
	h := sha256.New()
	if err := w.writeFile(path, modified, size, io.TeeReader(r, h)); err != nil {
		return err
	}
	w.manifest.Members = append(w.manifest.Members, Member{
		Path:   path,
		Size:   size,
		SHA256: hex.EncodeToString(h.Sum(nil)),
	})
	return nil
}

// memberHeader returns the tar header of a member. The bytes that archive/tar
// writes for it are the only header layout of the format: the writer writes
// them and the reader accepts nothing else. TestHeaderLayout and the test
// vectors fail if archive/tar ever writes other bytes.
func memberHeader(path string, size int64, modified time.Time) *tar.Header {
	return &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     path,
		Size:     size,
		Mode:     0o644,
		ModTime:  modified,
		Format:   tar.FormatPAX,
	}
}

// writeFile writes one regular tar member of the given size from r.
func (w *Writer) writeFile(path string, modified time.Time, size int64, r io.Reader) error {
	if err := w.tw.WriteHeader(memberHeader(path, size, modified)); err != nil {
		return fmt.Errorf("pack: write %s: %w", path, err)
	}
	copied, err := io.CopyN(w.tw, r, size)
	if err == io.EOF {
		return fmt.Errorf("pack: %s: content is %d bytes, expected %d", path, copied, size)
	}
	if err != nil {
		return fmt.Errorf("pack: %s: %w", path, err)
	}
	return nil
}

// Close writes and signs the manifest, finishes the tar archive and the
// encryption, and returns the manifest. It doesn't close the underlying
// writer.
func (w *Writer) Close() (*Manifest, error) {
	if w.err != nil {
		return nil, w.err
	}
	w.err = errors.New("pack: writer is closed")
	m, err := marshalJSON(w.manifest)
	if err != nil {
		return nil, fmt.Errorf("pack: manifest: %w", err)
	}
	sig := ed25519.Sign(w.signer, m)
	if err := w.writeFile(manifestPath, w.manifest.Created, int64(len(m)), bytes.NewReader(m)); err != nil {
		return nil, err
	}
	if err := w.writeFile(signaturePath, w.manifest.Created, int64(len(sig)), bytes.NewReader(sig)); err != nil {
		return nil, err
	}
	if err := w.tw.Close(); err != nil {
		return nil, fmt.Errorf("pack: finish tar: %w", err)
	}
	if err := w.enc.Close(); err != nil {
		return nil, fmt.Errorf("pack: finish encryption: %w", err)
	}
	manifest := w.manifest
	return &manifest, nil
}

// marshalJSON encodes v as indented JSON with a trailing newline, without
// escaping HTML characters, so extracted files read well.
func marshalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
