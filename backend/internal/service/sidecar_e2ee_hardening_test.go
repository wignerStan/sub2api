package service

import (
	"encoding/binary"
	"testing"
)

func TestSidecarE2EERejectsImpossiblePayloadLengthWithoutPanicking(t *testing.T) {
	key := sidecarE2EETestKey()
	record, err := SealSidecarRecord(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(record[2:6], 0)

	if _, err := OpenSidecarRecord(key, record); err != errSidecarE2EEPayloadShort {
		t.Fatalf("expected errSidecarE2EEPayloadShort, got %v", err)
	}

	decoder := NewSidecarRecordDecoder()
	if _, err := decoder.Push(key, record); err != errSidecarE2EEPayloadShort {
		t.Fatalf("decoder: expected errSidecarE2EEPayloadShort, got %v", err)
	}
}

func TestSidecarE2EERejectsTrailingBytesForSingleRecord(t *testing.T) {
	key := sidecarE2EETestKey()
	record, err := SealSidecarRecord(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	record = append(record, 0)

	if _, err := OpenSidecarRecord(key, record); err != errSidecarE2EETrailing {
		t.Fatalf("expected errSidecarE2EETrailing, got %v", err)
	}
}
