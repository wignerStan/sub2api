// Package service — sidecar E2EE record framing.
//
// Mirrors rustsidecar/src/e2ee.rs byte-for-byte so the Go host and the Rust
// sidecar/plugin can seal/open each other's streams:
//
//	record = [0xE2][version=1][len u32 BE][nonce 12B][ciphertext+16B tag]
//	len covers nonce+ciphertext+tag; AEAD = AES-256-GCM; AAD = "sub2api-e2ee".
//
// Keys:
//   - loopback hop:  HKDF-SHA256(x-s2s-token, salt, "loopback-channel")
//   - plugin channel: HKDF-SHA256(SHA256(plugin binary), salt, "forward-channel")
package service

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

const (
	sidecarE2EEMagic   = 0xE2
	sidecarE2EEVersion = 1
	sidecarE2EENonce   = 12
	sidecarE2EETag     = 16
	sidecarE2EEHeader       = 2 + 4
	sidecarE2EESalt         = "sub2api-e2ee-v1"
	sidecarE2EEAAD          = "sub2api-e2ee"
	maxSidecarRecordPayload = 64 * 1024 * 1024 // 64 MB guard against unbounded memory allocation
)

var (
	errSidecarE2EEShort     = errors.New("e2ee record too short")
	errSidecarE2EEHeader    = errors.New("unsupported e2ee record header")
	errSidecarE2EETooLarge  = errors.New("e2ee record payload too large")
	errSidecarE2EETrunc     = errors.New("e2ee record truncated")
	errSidecarE2EEAuth      = errors.New("e2ee record authentication failed")
	errSidecarE2EEKeyInfo   = errors.New("invalid e2ee key info")
)

func sidecarE2EEDerive(ikm []byte, info string) ([32]byte, error) {
	var out [32]byte
	if info == "" {
		return out, errSidecarE2EEKeyInfo
	}
	reader := hkdf.New(sha256.New, ikm, []byte(sidecarE2EESalt), []byte(info))
	if _, err := io.ReadFull(reader, out[:]); err != nil {
		return out, fmt.Errorf("hkdf expand: %w", err)
	}
	return out, nil
}

// DeriveSidecarLoopbackKey derives the loopback hop key from the shared token.
func DeriveSidecarLoopbackKey(token string) ([32]byte, error) {
	return sidecarE2EEDerive([]byte(token), "loopback-channel")
}

// DeriveSidecarBinaryKey derives the plugin-channel key from the plugin binary.
func DeriveSidecarBinaryKey(binaryPath string) ([32]byte, error) {
	bin, err := os.ReadFile(binaryPath)
	if err != nil {
		return [32]byte{}, fmt.Errorf("read plugin binary: %w", err)
	}
	sum := sha256.Sum256(bin)
	return sidecarE2EEDerive(sum[:], "forward-channel")
}

func sidecarE2EECipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealSidecarRecord seals plaintext into one framed record with a random nonce.
func SealSidecarRecord(key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := sidecarE2EECipher(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, sidecarE2EENonce)
	if _, err := crand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, []byte(sidecarE2EEAAD))
	out := make([]byte, 0, sidecarE2EEHeader+len(nonce)+len(sealed))
	out = append(out, sidecarE2EEMagic, sidecarE2EEVersion)
	var lenBE [4]byte
	binary.BigEndian.PutUint32(lenBE[:], uint32(len(nonce)+len(sealed)))
	out = append(out, lenBE[:]...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// OpenSidecarRecord opens one complete framed record.
func OpenSidecarRecord(key [32]byte, record []byte) ([]byte, error) {
	if len(record) < sidecarE2EEHeader+sidecarE2EENonce+sidecarE2EETag {
		return nil, errSidecarE2EEShort
	}
	if record[0] != sidecarE2EEMagic || record[1] != sidecarE2EEVersion {
		return nil, errSidecarE2EEHeader
	}
	payloadLen := binary.BigEndian.Uint32(record[2:6])
	if payloadLen > maxSidecarRecordPayload {
		return nil, errSidecarE2EETooLarge
	}
	if uint32(len(record)-sidecarE2EEHeader) < payloadLen {
		return nil, errSidecarE2EETrunc
	}
	aead, err := sidecarE2EECipher(key[:])
	if err != nil {
		return nil, err
	}
	nonce := record[sidecarE2EEHeader : sidecarE2EEHeader+sidecarE2EENonce]
	sealed := record[sidecarE2EEHeader+sidecarE2EENonce : sidecarE2EEHeader+payloadLen]
	plain, err := aead.Open(nil, nonce, sealed, []byte(sidecarE2EEAAD))
	if err != nil {
		return nil, errSidecarE2EEAuth
	}
	return plain, nil
}

// SidecarRecordDecoder reassembles sealed streams split at arbitrary boundaries.
type SidecarRecordDecoder struct {
	buf []byte
}

func NewSidecarRecordDecoder() *SidecarRecordDecoder { return &SidecarRecordDecoder{} }

// Pending reports the number of buffered unconsumed bytes.
func (d *SidecarRecordDecoder) Pending() int {
	if d == nil {
		return 0
	}
	return len(d.buf)
}

// Push feeds sealed bytes and returns every complete record's plaintext.
func (d *SidecarRecordDecoder) Push(key [32]byte, sealed []byte) ([]byte, error) {
	d.buf = append(d.buf, sealed...)
	var out []byte
	for {
		if len(d.buf) < sidecarE2EEHeader {
			return out, nil
		}
		if d.buf[0] != sidecarE2EEMagic || d.buf[1] != sidecarE2EEVersion {
			return out, errSidecarE2EEHeader
		}
		payloadLen := binary.BigEndian.Uint32(d.buf[2:6])
		if payloadLen > maxSidecarRecordPayload {
			return out, errSidecarE2EETooLarge
		}
		total := sidecarE2EEHeader + int(payloadLen)
		if len(d.buf) < total {
			return out, nil
		}
		plain, err := OpenSidecarRecord(key, d.buf[:total])
		if err != nil {
			return out, err
		}
		out = append(out, plain...)
		d.buf = d.buf[total:]
		if len(d.buf) == 0 {
			d.buf = nil
		}
	}
}

// SealSidecarChunk seals one chunk as a single record (1:1 mapping).
func SealSidecarChunk(key [32]byte, plain []byte) ([]byte, error) {
	return SealSidecarRecord(key, plain)
}

// OpenSidecarChunk opens a single sealed record.
func OpenSidecarChunk(key [32]byte, sealed []byte) ([]byte, error) {
	return OpenSidecarRecord(key, sealed)
}

// sealReadCloser streams an io.ReadCloser as sealed records.
type sealReadCloser struct {
	inner   io.ReadCloser
	key     [32]byte
	pending []byte
	eof     bool
}

func newSealReadCloser(inner io.ReadCloser, key [32]byte) io.ReadCloser {
	return &sealReadCloser{inner: inner, key: key}
}

func (s *sealReadCloser) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		if s.eof {
			return 0, io.EOF
		}
		chunk := make([]byte, 32*1024)
		n, err := s.inner.Read(chunk)
		if n > 0 {
			sealed, sealErr := SealSidecarRecord(s.key, chunk[:n])
			if sealErr != nil {
				return 0, sealErr
			}
			s.pending = sealed
		}
		if err == io.EOF {
			s.eof = true
			if n == 0 {
				return 0, io.EOF
			}
		} else if err != nil {
			return 0, err
		}
	}
	copied := copy(p, s.pending)
	s.pending = s.pending[copied:]
	return copied, nil
}

func (s *sealReadCloser) Close() error { return s.inner.Close() }

// openReadCloser decrypts a stream of sealed records.
type openReadCloser struct {
	inner   io.ReadCloser
	key     [32]byte
	decoder *SidecarRecordDecoder
	pending []byte
	eof     bool
}

func newOpenReadCloser(inner io.ReadCloser, key [32]byte) io.ReadCloser {
	return &openReadCloser{inner: inner, key: key, decoder: NewSidecarRecordDecoder()}
}

func (o *openReadCloser) Read(p []byte) (int, error) {
	for len(o.pending) == 0 {
		if o.eof {
			if o.decoder.Pending() > 0 {
				return 0, errSidecarE2EETrunc
			}
			return 0, io.EOF
		}
		chunk := make([]byte, 32*1024)
		n, err := o.inner.Read(chunk)
		if n > 0 {
			plain, decErr := o.decoder.Push(o.key, chunk[:n])
			if decErr != nil {
				return 0, decErr
			}
			o.pending = plain
		}
		if err == io.EOF {
			o.eof = true
			if n == 0 {
				if len(o.pending) == 0 {
					if o.decoder.Pending() > 0 {
						return 0, errSidecarE2EETrunc
					}
					return 0, io.EOF
				}
				break
			}
		} else if err != nil {
			return 0, err
		}
	}
	copied := copy(p, o.pending)
	o.pending = o.pending[copied:]
	return copied, nil
}

func (o *openReadCloser) Close() error { return o.inner.Close() }
