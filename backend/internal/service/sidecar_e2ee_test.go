package service

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

func sidecarE2EETestKey() [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestSidecarE2EERoundtripAndTamper(t *testing.T) {
	key := sidecarE2EETestKey()
	pt := []byte("hello e2ee payload")
	rec, err := SealSidecarRecord(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	if rec[0] != sidecarE2EEMagic || rec[1] != sidecarE2EEVersion {
		t.Fatalf("bad record header: %x %x", rec[0], rec[1])
	}
	got, err := OpenSidecarRecord(key, rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
	bad := append([]byte(nil), rec...)
	bad[len(bad)-1] ^= 0x01
	if _, err := OpenSidecarRecord(key, bad); err == nil {
		t.Fatal("tampered record must fail")
	}
	wrongKey := sidecarE2EETestKey()
	wrongKey[0] ^= 0xFF
	if _, err := OpenSidecarRecord(wrongKey, rec); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestSidecarE2EEDeterministicSeal(t *testing.T) {
	key := sidecarE2EETestKey()
	nonce := bytes.Repeat([]byte{7}, sidecarE2EENonce)

	// Seal with a fixed nonce by inlining the framing (mirrors Rust
	// deterministic_seal_with_fixed_nonce).
	aead, err := sidecarE2EECipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	seal := func(pt []byte) []byte {
		sealed := aead.Seal(nil, nonce, pt, []byte(sidecarE2EEAAD))
		out := []byte{sidecarE2EEMagic, sidecarE2EEVersion}
		var lenBE [4]byte
		binary.BigEndian.PutUint32(lenBE[:], uint32(len(nonce)+len(sealed)))
		out = append(out, lenBE[:]...)
		out = append(out, nonce...)
		out = append(out, sealed...)
		return out
	}
	if !bytes.Equal(seal([]byte("vector")), seal([]byte("vector"))) {
		t.Fatal("same key/nonce/pt must produce identical records")
	}
	if bytes.Equal(seal([]byte("vector")), seal([]byte("other"))) {
		t.Fatal("different pt must differ")
	}
}

func TestSidecarE2EEDerivation(t *testing.T) {
	a, err := DeriveSidecarLoopbackKey("tok")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSidecarLoopbackKey("tok")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("derivation must be deterministic")
	}
	c, _ := DeriveSidecarLoopbackKey("other")
	if a == c {
		t.Fatal("different tokens must derive different keys")
	}
	d, _ := sidecarE2EEDerive([]byte("ikm"), "forward-channel")
	if a == d {
		t.Fatal("different info must derive different keys")
	}
}

func TestSidecarRecordDecoderSplitsAndCoalesces(t *testing.T) {
	key := sidecarE2EETestKey()
	var all []byte
	for _, part := range [][]byte{[]byte("first-"), []byte("second"), []byte("!")} {
		rec, err := SealSidecarRecord(key, part)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, rec...)
	}
	for _, split := range []int{1, 6, 7, 14, 20, len(all) - 1} {
		dec := NewSidecarRecordDecoder()
		got, err := dec.Push(key, all[:split])
		if err != nil {
			t.Fatal(err)
		}
		more, err := dec.Push(key, all[split:])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, more...)
		if string(got) != "first-second!" {
			t.Fatalf("split %d: got %q", split, got)
		}
	}

	dec := NewSidecarRecordDecoder()
	var got []byte
	for i := 0; i < len(all); i++ {
		part, err := dec.Push(key, all[i:i+1])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, part...)
	}
	if string(got) != "first-second!" {
		t.Fatalf("byte-at-a-time: got %q", got)
	}
}

func TestSidecarE2EEStreams(t *testing.T) {
	key := sidecarE2EETestKey()
	payload := bytes.Repeat([]byte("payload-"), 5000) // ~40KB, multiple chunks

	sealed := newSealReadCloser(io.NopCloser(bytes.NewReader(payload)), key)
	plain, err := io.ReadAll(newOpenReadCloser(sealed, key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("stream roundtrip mismatch: %d vs %d bytes", len(plain), len(payload))
	}

	// Truncated stream must surface a decode error, not silent EOF.
	truncated := newSealReadCloser(io.NopCloser(bytes.NewReader(payload)), key)
	truncatedBytes, _ := io.ReadAll(truncated)
	broken := newOpenReadCloser(io.NopCloser(bytes.NewReader(truncatedBytes[:len(truncatedBytes)-8])), key)
	if _, err := io.ReadAll(broken); err == nil {
		t.Fatal("truncated sealed stream must error")
	}
	_ = rand.Reader
}

func TestSidecarE2EEPayloadLimit(t *testing.T) {
	key := sidecarE2EETestKey()
	// Fake a record header advertising 128 MB payload (> maxSidecarRecordPayload 64 MB)
	fake := []byte{sidecarE2EEMagic, sidecarE2EEVersion}
	var lenBE [4]byte
	binary.BigEndian.PutUint32(lenBE[:], 128*1024*1024)
	fake = append(fake, lenBE[:]...)
	fake = append(fake, bytes.Repeat([]byte{0}, 32)...)

	if _, err := OpenSidecarRecord(key, fake); err != errSidecarE2EETooLarge {
		t.Fatalf("expected errSidecarE2EETooLarge, got %v", err)
	}

	dec := NewSidecarRecordDecoder()
	if _, err := dec.Push(key, fake); err != errSidecarE2EETooLarge {
		t.Fatalf("decoder: expected errSidecarE2EETooLarge, got %v", err)
	}
}
