// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestTURN_PublicTURNServersNotEmpty(t *testing.T) {
	if len(PublicTURNServers) == 0 {
		t.Fatal("PublicTURNServers is empty")
	}

	// At least one should support TLS (TCP/443 is the key property that
	// makes TURN relay indistinguishable from HTTPS).
	hasTLS := false
	for _, srv := range PublicTURNServers {
		if srv.UseTLS {
			hasTLS = true
			break
		}
	}
	if !hasTLS {
		t.Error("no TLS-capable TURN servers configured; TCP/443 is critical for portal bypass")
	}
}

func TestTURN_PublicTURNServersHaveValidPorts(t *testing.T) {
	for i, srv := range PublicTURNServers {
		if srv.Port < 1 || srv.Port > 65535 {
			t.Errorf("PublicTURNServers[%d] (%s) has invalid port %d", i, srv.Host, srv.Port)
		}
		if srv.Host == "" {
			t.Errorf("PublicTURNServers[%d] has empty Host", i)
		}
	}
}

func TestTURN_MakeTransactionID_ReturnsTwelveBytes(t *testing.T) {
	txID := makeTransactionID()
	if len(txID) != 12 {
		t.Fatalf("makeTransactionID returned %d bytes, want 12", len(txID))
	}
}

func TestTURN_MakeTransactionID_ProducesDifferentValues(t *testing.T) {
	// Call enough times that collisions are effectively impossible for a
	// working randomness source. (12 bytes = 96 bits of entropy.)
	txID1 := makeTransactionID()
	txID2 := makeTransactionID()
	txID3 := makeTransactionID()

	if txID1 == txID2 && txID2 == txID3 {
		t.Error("makeTransactionID returned identical values across 3 calls")
	}
}

func TestTURN_BuildSTUNMessage_Header(t *testing.T) {
	var txID [12]byte
	for i := range txID {
		txID[i] = byte(i + 1)
	}

	msg := buildSTUNMessage(stunBindingRequest, txID, nil)

	if len(msg) != 20 {
		t.Fatalf("buildSTUNMessage with nil attrs returned %d bytes, want 20", len(msg))
	}

	// Message type at bytes 0-1.
	if got := binary.BigEndian.Uint16(msg[0:2]); got != stunBindingRequest {
		t.Errorf("message type = 0x%04x, want 0x%04x", got, stunBindingRequest)
	}

	// Attribute length at bytes 2-3 (zero for no attrs).
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0 {
		t.Errorf("attribute length = %d, want 0", got)
	}

	// Magic cookie at bytes 4-7.
	if got := binary.BigEndian.Uint32(msg[4:8]); got != stunMagicCookie {
		t.Errorf("magic cookie = 0x%08x, want 0x%08x", got, stunMagicCookie)
	}

	// Transaction ID at bytes 8-19.
	if !bytes.Equal(msg[8:20], txID[:]) {
		t.Errorf("transaction ID mismatch: got %x, want %x", msg[8:20], txID[:])
	}
}

func TestTURN_BuildSTUNMessage_WithAttributes(t *testing.T) {
	var txID [12]byte
	attrs := []byte{0x01, 0x02, 0x03, 0x04}

	msg := buildSTUNMessage(turnAllocateRequest, txID, attrs)

	if len(msg) != 20+len(attrs) {
		t.Fatalf("msg length = %d, want %d", len(msg), 20+len(attrs))
	}

	// Attribute length should match.
	if got := binary.BigEndian.Uint16(msg[2:4]); got != uint16(len(attrs)) {
		t.Errorf("attribute length header = %d, want %d", got, len(attrs))
	}

	// Attributes should be copied verbatim.
	if !bytes.Equal(msg[20:], attrs) {
		t.Errorf("attributes mismatch: got %x, want %x", msg[20:], attrs)
	}
}

func TestTURN_AppendSTUNAttr_TLVEncoding(t *testing.T) {
	// Value of length 4 (already 4-byte aligned; no padding needed).
	value := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	result := appendSTUNAttr(nil, attrUsername, value)

	if len(result) != 8 {
		t.Fatalf("result length = %d, want 8 (4 hdr + 4 value)", len(result))
	}

	// Type at bytes 0-1.
	if got := binary.BigEndian.Uint16(result[0:2]); got != attrUsername {
		t.Errorf("attr type = 0x%04x, want 0x%04x", got, attrUsername)
	}

	// Length at bytes 2-3.
	if got := binary.BigEndian.Uint16(result[2:4]); got != uint16(len(value)) {
		t.Errorf("attr length = %d, want %d", got, len(value))
	}

	// Value at bytes 4-7.
	if !bytes.Equal(result[4:8], value) {
		t.Errorf("attr value mismatch: got %x, want %x", result[4:8], value)
	}
}

func TestTURN_AppendSTUNAttr_Padding(t *testing.T) {
	// Value of length 3 (needs 1 byte of padding to reach 4-byte boundary).
	value := []byte{0x01, 0x02, 0x03}
	result := appendSTUNAttr(nil, attrUsername, value)

	if len(result) != 8 {
		t.Fatalf("result length = %d, want 8 (4 hdr + 3 value + 1 pad)", len(result))
	}

	// Length header should reflect actual value length (3), not padded length.
	if got := binary.BigEndian.Uint16(result[2:4]); got != 3 {
		t.Errorf("attr length header = %d, want 3 (actual value length, not padded)", got)
	}

	// Padding byte should be zero.
	if result[7] != 0 {
		t.Errorf("padding byte = 0x%02x, want 0x00", result[7])
	}
}

func TestTURN_AppendSTUNAttr_AppendsToExistingBuffer(t *testing.T) {
	existing := []byte{0xFF, 0xFE}
	result := appendSTUNAttr(existing, attrSoftware, []byte{0xAB})

	// First 2 bytes should be preserved.
	if result[0] != 0xFF || result[1] != 0xFE {
		t.Errorf("existing bytes not preserved: got %x", result[0:2])
	}

	// Type starts at byte 2.
	if got := binary.BigEndian.Uint16(result[2:4]); got != attrSoftware {
		t.Errorf("attr type at offset 2 = 0x%04x, want 0x%04x", got, attrSoftware)
	}
}

func TestTURN_EncodeXORAddress_IPv4(t *testing.T) {
	var txID [12]byte
	ip := net.ParseIP("192.168.1.1").To4()
	port := 3478

	encoded := encodeXORAddress(ip, port, txID)

	if len(encoded) != 8 {
		t.Fatalf("IPv4 XOR address length = %d, want 8", len(encoded))
	}

	// Byte 0 reserved (0), byte 1 family (0x01 = IPv4).
	if encoded[1] != 0x01 {
		t.Errorf("family byte = 0x%02x, want 0x01 (IPv4)", encoded[1])
	}

	// Port XORed with top half of magic cookie (0x2112).
	gotPort := binary.BigEndian.Uint16(encoded[2:4]) ^ uint16(stunMagicCookie>>16)
	if gotPort != uint16(port) {
		t.Errorf("decoded port = %d, want %d", gotPort, port)
	}

	// IPv4 address XORed with magic cookie.
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, stunMagicCookie)
	for i := 0; i < 4; i++ {
		got := encoded[4+i] ^ cookieBytes[i]
		if got != ip[i] {
			t.Errorf("decoded IP[%d] = %d, want %d", i, got, ip[i])
		}
	}
}

func TestTURN_EncodeXORAddress_DifferentPortsEncodeDifferently(t *testing.T) {
	var txID [12]byte
	ip := net.ParseIP("10.0.0.1").To4()

	enc1 := encodeXORAddress(ip, 1234, txID)
	enc2 := encodeXORAddress(ip, 5678, txID)

	if bytes.Equal(enc1[2:4], enc2[2:4]) {
		t.Error("different ports produced identical XOR encoding")
	}
}

func TestTURN_AddMessageIntegrity_IncreasesSizeBy24(t *testing.T) {
	var txID [12]byte
	baseMsg := buildSTUNMessage(turnAllocateRequest, txID, nil)

	withIntegrity := addMessageIntegrity(baseMsg, []byte("secret-key"))

	// Message-Integrity attribute = 4-byte TLV header + 20-byte HMAC-SHA1 = 24 bytes.
	if len(withIntegrity) != len(baseMsg)+24 {
		t.Errorf("message grew by %d bytes, want 24", len(withIntegrity)-len(baseMsg))
	}

	// The last 4 bytes before HMAC should be the MESSAGE-INTEGRITY attr header.
	// Type: attrMessageIntegrity (0x0008), length: 20.
	attrOffset := len(baseMsg)
	gotType := binary.BigEndian.Uint16(withIntegrity[attrOffset : attrOffset+2])
	gotLen := binary.BigEndian.Uint16(withIntegrity[attrOffset+2 : attrOffset+4])
	if gotType != attrMessageIntegrity {
		t.Errorf("integrity attr type = 0x%04x, want 0x%04x", gotType, attrMessageIntegrity)
	}
	if gotLen != 20 {
		t.Errorf("integrity attr length = %d, want 20 (HMAC-SHA1)", gotLen)
	}
}

func TestTURN_AddMessageIntegrity_UpdatesHeaderLength(t *testing.T) {
	var txID [12]byte
	baseMsg := buildSTUNMessage(turnAllocateRequest, txID, nil)
	originalLen := binary.BigEndian.Uint16(baseMsg[2:4])

	withIntegrity := addMessageIntegrity(baseMsg, []byte("key"))
	newLen := binary.BigEndian.Uint16(withIntegrity[2:4])

	// Length in header should grow by 24 bytes (MESSAGE-INTEGRITY TLV).
	if newLen != originalLen+24 {
		t.Errorf("header length after integrity: %d, want %d", newLen, originalLen+24)
	}
}

func TestTURN_AddMessageIntegrity_DeterministicForSameInputs(t *testing.T) {
	var txID [12]byte
	msg := buildSTUNMessage(turnAllocateRequest, txID, nil)

	result1 := addMessageIntegrity(append([]byte(nil), msg...), []byte("secret"))
	result2 := addMessageIntegrity(append([]byte(nil), msg...), []byte("secret"))

	if !bytes.Equal(result1, result2) {
		t.Error("addMessageIntegrity not deterministic for same inputs")
	}
}

func TestTURN_MagicCookieConstant(t *testing.T) {
	// RFC 5389 §6: magic cookie MUST be 0x2112A442.
	if stunMagicCookie != 0x2112A442 {
		t.Errorf("stunMagicCookie = 0x%08x, want 0x2112A442 (RFC 5389)", stunMagicCookie)
	}
}

func TestTURN_ChannelNumberRange(t *testing.T) {
	// RFC 5766: channel numbers must be in 0x4000-0x7FFF.
	if turnChannelData != 0x4000 {
		t.Errorf("turnChannelData = 0x%04x, want 0x4000 (RFC 5766)", turnChannelData)
	}
}

func TestTURN_StartTURNRelayTunnelRespectsTimeout(t *testing.T) {
	// We can't actually reach TURN servers in CI reliably, but we can verify
	// the function returns (with an error) rather than hanging indefinitely.
	// Use a short timeout and accept either success or failure.
	done := make(chan struct{})
	go func() {
		_, _ = StartTURNRelayTunnel(0, 100) // 100ns timeout forces immediate failure
		close(done)
	}()

	select {
	case <-done:
		// Expected: returned quickly.
	case <-timeAfter(5):
		t.Fatal("StartTURNRelayTunnel did not respect timeout (hung >5s)")
	}
}

// timeAfter returns a channel that fires after seconds, avoiding time package
// at the call site for clarity.
func timeAfter(seconds int) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		t := time.NewTimer(time.Duration(seconds) * time.Second)
		defer t.Stop()
		<-t.C
		close(ch)
	}()
	return ch
}
