// Package pack writes and reads Rautjoxa archive packs, format version 1.
//
// A pack is a PAX tar archive encrypted with age to one or two post-quantum
// recipients. For every item the tar holds a JSON sidecar followed by the
// item's original bytes. It ends with a manifest.json that records the size
// and SHA-256 of every other member, and a manifest.sig that holds the
// writing device's Ed25519 signature of the manifest. The format is specified
// in docs/format.md at the repository root. Packs are stored under write-once
// retention, so this package must keep reading every pack it has ever
// written: any change to the layout needs a new format version.
package pack

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Version is the pack format version this package writes.
const Version = 1

// WriterVersion names this writer and its version. Every pack records it in
// its manifest, so that the packs a faulty writer wrote can be found later.
// Change it whenever what the writer writes changes.
const WriterVersion = "rautjoxa-core/0.1.0"

const (
	formatName    = "rautjoxa-pack"
	manifestPath  = "manifest.json"
	signaturePath = "manifest.sig"
	pqStanzaType  = "mlkem768x25519"

	// MaxItems is the largest number of items in one pack. Item numbers are
	// six decimal digits.
	MaxItems = 999_999

	// MaxRecipients is the largest number of recipients of one pack: the
	// owner and, optionally, a successor.
	MaxRecipients = 2

	maxNameBytes    = 255
	maxSidecarBytes = 1 << 20
	maxWriterBytes  = 128
)

// maxManifestSize is the largest manifest.json in bytes, 256 MiB. It is a
// variable only so that tests can lower it.
var maxManifestSize int64 = 1 << 28

var (
	// ErrWrongKey means that no recipient stanza of the pack opens with the
	// given identity. A damaged pack header also produces this error, because
	// age can't tell the two apart.
	ErrWrongKey = errors.New("pack: no recipient matches the identity (wrong key or damaged header)")

	// ErrInvalid means that the pack is damaged, truncated, or doesn't follow
	// the format. The wrapping error says what is wrong.
	ErrInvalid = errors.New("pack: invalid")

	// ErrUntrustedSigner means that the pack is intact and correctly signed,
	// but by a key that isn't one of the signers the caller trusts.
	ErrUntrustedSigner = errors.New("pack: signed by an untrusted key")
)

var (
	packIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	signerPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	writerPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._+-]+$`)
)

// Item describes one archived item. It is stored in the item's sidecar.
type Item struct {
	// Name is the file name of the original, a single path element. The
	// writer stores it in Unicode Normalization Form C (NFC). The reader
	// returns it as stored, in whatever form the writer used.
	Name string
	// Size is the length of the original in bytes.
	Size int64
	// Modified is when the original was last modified at its source.
	Modified time.Time
	// MimeType is the media type the source reports, or empty if unknown.
	MimeType string
	// Source identifies where the item came from.
	Source Source
}

// Source is the source-neutral record of where an item came from. Metadata
// is stored as the source reported it.
type Source struct {
	// ID is the stable ID of the source plugin, such as "android.media".
	ID string `json:"id"`
	// Key is the item's stable key within that source.
	Key string `json:"key"`
	// Metadata is the source's own metadata for the item.
	Metadata map[string]string `json:"metadata"`
}

// Manifest is the content of a pack's manifest.json.
type Manifest struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	// Writer names the writer that wrote the pack and its version, such as
	// "rautjoxa-core/0.1.0".
	Writer string `json:"writer"`
	// Signer is the Ed25519 public key that signed the manifest, as 64
	// lowercase hexadecimal characters.
	Signer string `json:"signer"`
	// Members lists every tar member except manifest.json and manifest.sig,
	// in tar order.
	Members []Member `json:"members"`
}

// Member is one tar member recorded in the manifest.
type Member struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// sidecar is the JSON form of an item's sidecar.
type sidecar struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	MimeType string    `json:"mime_type"`
	Source   Source    `json:"source"`
}

// ObjectName returns the storage object name of the pack with the given ID.
func ObjectName(id string) string {
	return "packs/" + id + ".age"
}

func newPackID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pack: generate ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func sidecarPath(n int) string {
	return fmt.Sprintf("items/%06d.json", n)
}

func originalPath(n int, name string) string {
	return fmt.Sprintf("items/%06d/%s", n, name)
}

// The reader's acceptance rules, acceptName and Item.accept, are frozen with
// format version 1: a pack they accept today must stay accepted forever, so
// never make them stricter. Rules for what the writer writes, which may get
// stricter over time, belong in Item.Validate.

// acceptName reports whether name is a valid file name of an original.
func acceptName(name string) error {
	switch {
	case name == "":
		return errors.New("empty name")
	case len(name) > maxNameBytes:
		return fmt.Errorf("name longer than %d bytes", maxNameBytes)
	case !utf8.ValidString(name):
		return errors.New("name is not valid UTF-8")
	case name == "." || name == "..":
		return fmt.Errorf("name %q is reserved", name)
	case strings.ContainsAny(name, `/\`):
		return fmt.Errorf("name %q contains a path separator", name)
	case strings.ContainsFunc(name, unicode.IsControl):
		// unicode.IsControl is exactly U+0000 to U+001F and U+007F to U+009F.
		return fmt.Errorf("name %q contains a control character", name)
	}
	return nil
}

// accept reports whether it is a valid item of a version 1 pack.
func (it Item) accept() error {
	if err := acceptName(it.Name); err != nil {
		return err
	}
	if it.Size < 0 {
		return fmt.Errorf("negative size %d", it.Size)
	}
	if it.Source.ID == "" {
		return errors.New("source ID not set")
	}
	if it.Source.Key == "" {
		return errors.New("source key not set")
	}
	for field, v := range map[string]string{"MIME type": it.MimeType, "source ID": it.Source.ID, "source key": it.Source.Key} {
		if !utf8.ValidString(v) {
			return fmt.Errorf("%s %q is not valid UTF-8", field, v)
		}
	}
	for k, v := range it.Source.Metadata {
		if !utf8.ValidString(k) {
			return fmt.Errorf("source metadata key %q is not valid UTF-8", k)
		}
		if !utf8.ValidString(v) {
			return fmt.Errorf("source metadata %q value %q is not valid UTF-8", k, v)
		}
	}
	return nil
}

// Validate reports whether Writer.Add accepts it, apart from the pack's
// limits on items and manifest size. Add checks the item's name after
// converting it to NFC. These rules may get stricter in later versions; the
// reader never applies them.
func (it Item) Validate() error {
	if _, _, err := it.prepare(1); err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	return nil
}
