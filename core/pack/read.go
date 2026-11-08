package pack

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"filippo.io/age"
)

const blockSize = 512

// maxRawHeaders limits the bytes kept while reading one member's headers, so
// that a long run of pax extended headers can't use up memory. archive/tar
// limits one such header to 1 MiB.
const maxRawHeaders = 2 << 20

// Read decrypts the pack read from src with identity and checks it against
// the format, its manifest, and the manifest's signature. For every item in
// order it calls fn, if fn is not nil, with the item's metadata and a reader
// of the item's original bytes. The reader is valid only until fn returns,
// and fn doesn't need to read it to the end.
//
// signers lists the Ed25519 public keys of the devices whose packs the caller
// trusts. A nil or empty list trusts no key. To accept a pack signed by any
// key, use ReadAnySigner.
//
// age authenticates the bytes before fn sees them, but sizes, hashes, and the
// signature are checked only after the last item. Treat what fn received as
// unverified until Read returns a nil error.
//
// Read returns an error wrapping ErrWrongKey if identity can't open the pack,
// ErrInvalid if the pack is damaged or malformed, ErrUntrustedSigner if it
// is signed by a key not in signers, or the error fn returned. If reading src
// fails, Read returns an error that wraps the error src returned and says
// nothing about the state of the pack.
func Read(src io.Reader, identity age.Identity, signers []ed25519.PublicKey, fn func(Item, io.Reader) error) (*Manifest, error) {
	return readTrusted(src, identity, func(key ed25519.PublicKey) bool {
		return slices.ContainsFunc(signers, func(k ed25519.PublicKey) bool { return k.Equal(key) })
	}, fn)
}

// ReadAnySigner is Read without a trust policy: it accepts a pack signed by
// any key. It still checks the signature, which then proves that the pack is
// unchanged since it was signed, but not who signed it. Use it only where
// the caller decides about Manifest.Signer itself, such as when it shows the
// signer to a person who restores the pack.
func ReadAnySigner(src io.Reader, identity age.Identity, fn func(Item, io.Reader) error) (*Manifest, error) {
	return readTrusted(src, identity, func(ed25519.PublicKey) bool { return true }, fn)
}

// readTrusted reads a pack and accepts its signer if trusted returns true.
func readTrusted(src io.Reader, identity age.Identity, trusted func(ed25519.PublicKey) bool, fn func(Item, io.Reader) error) (*Manifest, error) {
	if identity == nil {
		return nil, errors.New("pack: nil identity")
	}
	source := &sourceReader{r: src}
	m, err := read(source, identity, trusted, fn)
	var cbErr callbackError
	switch {
	case err == nil:
		return m, nil
	case errors.As(err, &cbErr):
		return nil, cbErr.err
	case source.err != nil:
		return nil, fmt.Errorf("pack: read: %w", source.err)
	}
	return nil, err
}

func read(src io.Reader, identity age.Identity, trusted func(ed25519.PublicKey) bool, fn func(Item, io.Reader) error) (*Manifest, error) {
	plaintext, err := age.Decrypt(src, pqOnly{identity})
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		switch {
		case errors.As(err, &noMatch):
			return nil, ErrWrongKey
		case errors.Is(err, ErrInvalid):
			return nil, err
		}
		return nil, invalidf("decrypt: %v", err)
	}

	body := &countingReader{r: plaintext}
	tr := tar.NewReader(body)
	var members []Member
	var manifest *Manifest
	var manifestData []byte
	for n := 1; manifest == nil; n++ {
		hdr, err := nextMember(tr, body)
		if err == io.EOF {
			return nil, invalidf("member %q is missing", manifestPath)
		}
		if err != nil {
			return nil, err
		}
		switch hdr.Name {
		case manifestPath:
			if manifestData, _, err = readJSONMember(tr, hdr, maxManifestSize); err != nil {
				return nil, err
			}
			if manifest, err = parseManifest(manifestData); err != nil {
				return nil, err
			}
			continue
		case sidecarPath(n):
		default:
			return nil, invalidf("unexpected member %q, expected %q or %q", hdr.Name, sidecarPath(n), manifestPath)
		}
		if n > MaxItems {
			return nil, invalidf("more than %d items", MaxItems)
		}

		data, scMember, err := readJSONMember(tr, hdr, maxSidecarBytes)
		if err != nil {
			return nil, err
		}
		it, err := parseSidecar(n, data)
		if err != nil {
			return nil, err
		}
		members = append(members, scMember)

		path := originalPath(n, it.Name)
		hdr, err = nextMember(tr, body)
		if err == io.EOF {
			return nil, invalidf("member %q is missing", path)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name != path {
			return nil, invalidf("member %q is missing, found %q", path, hdr.Name)
		}
		if hdr.Size != it.Size {
			return nil, invalidf("member %q is %d bytes, its sidecar says %d", path, hdr.Size, it.Size)
		}
		h := sha256.New()
		if fn != nil {
			content := &contentReader{r: io.TeeReader(tr, h)}
			if err := fn(it, content); err != nil {
				if content.err != nil {
					return nil, invalidf("read %s: %v", path, content.err)
				}
				return nil, callbackError{err}
			}
		}
		if _, err := io.Copy(h, tr); err != nil {
			return nil, invalidf("read %s: %v", path, err)
		}
		members = append(members, Member{Path: path, Size: hdr.Size, SHA256: hex.EncodeToString(h.Sum(nil))})
	}

	hdr, err := nextMember(tr, body)
	if err == io.EOF {
		return nil, invalidf("member %q is missing", signaturePath)
	}
	if err != nil {
		return nil, err
	}
	if hdr.Name != signaturePath {
		return nil, invalidf("unexpected member %q after %q, expected %q", hdr.Name, manifestPath, signaturePath)
	}
	if hdr.Size != ed25519.SignatureSize {
		return nil, invalidf("member %q is %d bytes, expected %d", signaturePath, hdr.Size, ed25519.SignatureSize)
	}
	sig, err := io.ReadAll(tr)
	if err != nil {
		return nil, invalidf("read %s: %v", signaturePath, err)
	}

	end := body.n
	if hdr, err := nextMember(tr, body); err == nil {
		return nil, invalidf("unexpected member %q after %q", hdr.Name, signaturePath)
	} else if err != io.EOF {
		return nil, err
	}
	// The tar reader also stops at the end of its input, so check that it
	// read the two zero blocks that end the archive.
	if body.n != (end+blockSize-1)/blockSize*blockSize+2*blockSize {
		return nil, invalidf("the tar archive doesn't end with two zero blocks")
	}
	// Reading to the end also makes age authenticate the final chunk.
	if err := checkZeros(body); err != nil {
		return nil, err
	}
	if err := checkMembers(manifest.Members, members); err != nil {
		return nil, err
	}

	signer, _ := hex.DecodeString(manifest.Signer)
	if !ed25519.Verify(signer, manifestData, sig) {
		return nil, invalidf("%s doesn't verify with the signer key in %s", signaturePath, manifestPath)
	}
	if !trusted(signer) {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedSigner, manifest.Signer)
	}
	return manifest, nil
}

// pqOnly enforces the recipient rule before age tries the identity: one or
// two stanzas, all post-quantum.
type pqOnly struct{ age.Identity }

func (p pqOnly) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) == 0 || len(stanzas) > MaxRecipients {
		return nil, invalidf("%d recipient stanzas, expected 1 to %d", len(stanzas), MaxRecipients)
	}
	for _, s := range stanzas {
		if s.Type != pqStanzaType {
			return nil, invalidf("recipient stanza type %q is not %q", s.Type, pqStanzaType)
		}
	}
	return p.Identity.Unwrap(stanzas)
}

// sourceReader remembers the first error of the pack's source, so that Read
// can tell a failure to read the pack from damage to the pack.
type sourceReader struct {
	r   io.Reader
	err error
}

func (s *sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF && s.err == nil {
		s.err = err
	}
	return n, err
}

// contentReader remembers a read error, so that Read can report damage to
// the pack even when fn returns that error wrapped or replaced.
type contentReader struct {
	r   io.Reader
	err error
}

func (c *contentReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil && err != io.EOF {
		c.err = err
	}
	return n, err
}

// countingReader counts the bytes read through it and, while recording, keeps
// them, so that nextMember can check the raw header blocks.
type countingReader struct {
	r         io.Reader
	n         int64
	recording bool
	raw       []byte
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.recording {
		c.raw = append(c.raw, p[:n]...)
		if len(c.raw) > maxRawHeaders {
			return n, invalidf("more than one tar extended header for a member")
		}
	}
	return n, err
}

// callbackError carries an error returned by Read's callback.
type callbackError struct{ err error }

func (e callbackError) Error() string { return e.err.Error() }

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// checkZeros reads r to the end and reports an error if it holds anything
// but zero bytes.
func checkZeros(r io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if slices.ContainsFunc(buf[:n], func(b byte) bool { return b != 0 }) {
			return invalidf("data after the end of the tar archive")
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return invalidf("decrypt: %v", err)
		}
	}
}

// nextMember returns the next tar header, io.EOF at the end of the archive,
// or an ErrInvalid error. A member's headers and the padding before them must
// be exactly what the writer writes for the member's name, size, and time.
// body must be the reader beneath tr, and the current member must be read to
// its end.
func nextMember(tr *tar.Reader, body *countingReader) (*tar.Header, error) {
	padding := int(-body.n & (blockSize - 1))
	body.recording, body.raw = true, body.raw[:0]
	hdr, err := tr.Next()
	body.recording = false
	if len(bytes.Trim(body.raw[:min(padding, len(body.raw))], "\x00")) != 0 {
		return nil, invalidf("the padding of a tar member isn't zero bytes")
	}
	if err == io.EOF {
		return nil, io.EOF
	}
	if err != nil {
		return nil, invalidf("read tar: %v", err)
	}
	var want bytes.Buffer
	if err := tar.NewWriter(&want).WriteHeader(memberHeader(hdr.Name, hdr.Size, hdr.ModTime)); err != nil || !bytes.Equal(want.Bytes(), body.raw[padding:]) {
		return nil, invalidf("member %q has a tar header that isn't in the layout of the format", hdr.Name)
	}
	return hdr, nil
}

// readJSONMember reads the current member, which must be at most limit
// bytes, and returns its bytes and manifest record.
func readJSONMember(tr *tar.Reader, hdr *tar.Header, limit int64) ([]byte, Member, error) {
	if hdr.Size > limit {
		return nil, Member{}, invalidf("member %q is %d bytes, the limit is %d", hdr.Name, hdr.Size, limit)
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, Member{}, invalidf("read %s: %v", hdr.Name, err)
	}
	sum := sha256.Sum256(data)
	return data, Member{Path: hdr.Name, Size: hdr.Size, SHA256: hex.EncodeToString(sum[:])}, nil
}

// decodeJSON checks that data has shape s and decodes it into v.
func decodeJSON(data []byte, s *shape, v any) error {
	if err := checkJSON(data, s); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func parseSidecar(n int, data []byte) (Item, error) {
	var sc sidecar
	if err := decodeJSON(data, sidecarShape, &sc); err != nil {
		return Item{}, invalidf("sidecar %s: %v", sidecarPath(n), err)
	}
	dir := originalPath(n, "")
	name, ok := strings.CutPrefix(sc.Path, dir)
	if !ok {
		return Item{}, invalidf("sidecar %s: path %q is not in %q", sidecarPath(n), sc.Path, dir)
	}
	it := Item{
		Name:     name,
		Size:     sc.Size,
		Modified: sc.Modified,
		MimeType: sc.MimeType,
		Source:   sc.Source,
	}
	if err := it.accept(); err != nil {
		return Item{}, invalidf("sidecar %s: %v", sidecarPath(n), err)
	}
	return it, nil
}

func parseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := decodeJSON(data, manifestShape, &m); err != nil {
		return nil, invalidf("%s: %v", manifestPath, err)
	}
	switch {
	case m.Format != formatName:
		return nil, invalidf("%s: format %q, expected %q", manifestPath, m.Format, formatName)
	case m.Version != Version:
		return nil, invalidf("%s: version %d, expected %d", manifestPath, m.Version, Version)
	case !packIDPattern.MatchString(m.ID):
		return nil, invalidf("%s: malformed pack ID %q", manifestPath, m.ID)
	case len(m.Writer) > maxWriterBytes || !writerPattern.MatchString(m.Writer):
		return nil, invalidf("%s: malformed writer %q", manifestPath, m.Writer)
	case !signerPattern.MatchString(m.Signer):
		return nil, invalidf("%s: malformed signer key %q", manifestPath, m.Signer)
	}
	return &m, nil
}

// checkMembers compares the members the manifest lists with the members
// found in the tar archive.
func checkMembers(listed, found []Member) error {
	want := make(map[string]Member, len(listed))
	for _, m := range listed {
		if _, dup := want[m.Path]; dup {
			return invalidf("%s lists %q twice", manifestPath, m.Path)
		}
		want[m.Path] = m
	}
	for _, got := range found {
		m, ok := want[got.Path]
		switch {
		case !ok:
			return invalidf("member %q is not in %s", got.Path, manifestPath)
		case m.Size != got.Size:
			return invalidf("member %q is %d bytes, %s says %d", got.Path, got.Size, manifestPath, m.Size)
		case m.SHA256 != got.SHA256:
			return invalidf("member %q has SHA-256 %s, %s says %s", got.Path, got.SHA256, manifestPath, m.SHA256)
		}
		delete(want, got.Path)
	}
	for _, m := range listed {
		if _, missing := want[m.Path]; missing {
			return invalidf("member %q is in %s but missing from the pack", m.Path, manifestPath)
		}
	}
	for i := range listed {
		if listed[i].Path != found[i].Path {
			return invalidf("%s lists members out of order", manifestPath)
		}
	}
	return nil
}
