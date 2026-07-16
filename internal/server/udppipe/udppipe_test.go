// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package udppipe

import (
	"bytes"
	"testing"
)

// oneByteReader returns at most one byte per Read, modelling a byte-stream
// transport (libp2p/QUIC/TCP) that delivers a length-prefixed frame in several
// partial reads. Writes are discarded.
type oneByteReader struct{ data []byte }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, bytes.ErrTooLarge // any non-nil EOF-ish error ends the stream
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}
func (r *oneByteReader) Write(p []byte) (int, error) { return len(p), nil }
func (r *oneByteReader) Close() error                { return nil }

func frame(p []byte) []byte {
	return append([]byte{byte(len(p) >> 8), byte(len(p))}, p...)
}

// TestLenPrefixPipe_RecvHandlesPartialReads locks the fix for the framing bug:
// Recv must use io.ReadFull, not a single Read. With a partial-read transport a
// naive Read returns fewer bytes than the length prefix promises and desyncs
// every subsequent frame. This feeds two frames one byte at a time and requires
// both to reassemble intact.
func TestLenPrefixPipe_RecvHandlesPartialReads(t *testing.T) {
	d1 := bytes.Repeat([]byte("A"), 900) // multi-hundred-byte payload
	d2 := []byte("small-\x00\x01\x02")   // includes NUL/binary bytes

	var wire bytes.Buffer
	wire.Write(frame(d1))
	wire.Write(frame(d2))

	pipe := NewLenPrefixPipe(&oneByteReader{data: wire.Bytes()}, DefaultMTU)

	got1, err := pipe.Recv()
	if err != nil {
		t.Fatalf("Recv #1: %v", err)
	}
	if !bytes.Equal(got1, d1) {
		t.Fatalf("frame #1 corrupted: got %d bytes, want %d", len(got1), len(d1))
	}

	got2, err := pipe.Recv()
	if err != nil {
		t.Fatalf("Recv #2: %v", err)
	}
	if !bytes.Equal(got2, d2) {
		t.Fatalf("frame #2 corrupted: got %q, want %q", got2, d2)
	}
}

// TestLenPrefixPipe_RoundTrip is a straightforward Send->Recv sanity check over
// an in-memory pipe.
func TestLenPrefixPipe_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	rw := &rwBuf{Buffer: &buf}
	pipe := NewLenPrefixPipe(rw, DefaultMTU)

	msgs := [][]byte{[]byte("one"), []byte(""), bytes.Repeat([]byte{0x7f}, 1400)}
	for _, m := range msgs {
		if err := pipe.Send(m); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	for i, want := range msgs {
		got, err := pipe.Recv()
		if err != nil {
			t.Fatalf("Recv #%d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round-trip #%d: got %d bytes want %d", i, len(got), len(want))
		}
	}
}

type rwBuf struct{ *bytes.Buffer }

func (b *rwBuf) Close() error { return nil }

// TestLenPrefixPipe_RejectsOversizeFrame verifies that a frame whose declared
// length exceeds the MTU is rejected (error) rather than silently truncated —
// truncation would leave the remaining payload in the stream and desync every
// subsequent frame, which a hostile peer could exploit to wedge the tunnel.
func TestLenPrefixPipe_RejectsOversizeFrame(t *testing.T) {
	// Declare length 2000 with MTU 1400.
	oversize := append([]byte{byte(2000 >> 8), byte(2000 & 0xff)}, bytes.Repeat([]byte("X"), 2000)...)
	pipe := NewLenPrefixPipe(&oneByteReader{data: oversize}, DefaultMTU)
	if _, err := pipe.Recv(); err == nil {
		t.Fatal("Recv accepted an oversized frame; expected a protocol error")
	}
}

// TestNewLenPrefixPipe_ClampsMTU verifies the MTU is clamped to the 16-bit
// framing limit so a payload length cannot silently wrap the 2-byte prefix.
func TestNewLenPrefixPipe_ClampsMTU(t *testing.T) {
	var buf bytes.Buffer
	rw := &rwBuf{Buffer: &buf}
	pipe := NewLenPrefixPipe(rw, 70000) // > 65535
	// Sending 66000 bytes must be clamped to <= 65535 so the length prefix is
	// exact and Recv reassembles the same number of bytes it framed.
	if err := pipe.Send(bytes.Repeat([]byte{0x41}, 66000)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := pipe.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(got) > 65535 {
		t.Fatalf("frame length %d exceeds 16-bit limit", len(got))
	}
}
