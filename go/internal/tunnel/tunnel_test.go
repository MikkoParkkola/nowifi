package tunnel

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Handle.Stop terminates process
// ---------------------------------------------------------------------------

func TestHandle_Stop_TerminatesProcess(t *testing.T) {
	// Start a long-running process we can kill.
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep process: %v", err)
	}

	h := &Handle{
		Process:   cmd,
		LocalPort: 0,
		Method:    "test",
		Active:    true,
	}

	h.Stop()

	if h.Active {
		t.Error("Handle.Active should be false after Stop")
	}
	// Process should be dead; Wait should return an error.
	// (already waited inside Stop, but double-check state)
	if cmd.ProcessState == nil {
		t.Error("ProcessState should be non-nil after Stop")
	}
}

// ---------------------------------------------------------------------------
// Test: Handle.Stop on nil process doesn't panic
// ---------------------------------------------------------------------------

func TestHandle_Stop_NilProcess(t *testing.T) {
	h := &Handle{
		Process: nil,
		Active:  true,
	}

	// Should not panic.
	h.Stop()

	if h.Active {
		t.Error("Handle.Active should be false after Stop with nil process")
	}
}

func TestHandle_Stop_NilInnerProcess(t *testing.T) {
	cmd := &exec.Cmd{} // Process field is nil by default
	h := &Handle{
		Process: cmd,
		Active:  true,
	}

	// Should not panic.
	h.Stop()

	if h.Active {
		t.Error("Handle.Active should be false after Stop with nil inner process")
	}
}

// ---------------------------------------------------------------------------
// Test: VerifySOCKS with mock TCP listener -> true requires full SOCKS5
//       So we test that connection refused -> false.
// ---------------------------------------------------------------------------

func TestVerifySOCKS_ConnectionRefused(t *testing.T) {
	// Use a port that is almost certainly not listening.
	result := VerifySOCKS(59123)
	if result {
		t.Error("VerifySOCKS should return false on connection refused")
	}
}

// ---------------------------------------------------------------------------
// Test: VerifyDirect with mock HTTP server -> true
// ---------------------------------------------------------------------------

func TestVerifyDirect_MockSuccess(t *testing.T) {
	// VerifyDirect hits http://detectportal.firefox.com/canonical.html
	// which we can't mock without overriding DefaultClient. Just verify
	// it doesn't panic and returns a boolean.
	_ = VerifyDirect()
}

// ---------------------------------------------------------------------------
// Test: VerifyCFWorkersProxy with mock HTTP server -> true
// ---------------------------------------------------------------------------

func TestVerifyCFWorkersProxy_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The function appends /https://connectivitycheck.gstatic.com/generate_204
		// to the worker URL, then checks for status 204.
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	result := VerifyCFWorkersProxy(ts.URL)
	if !result {
		t.Error("VerifyCFWorkersProxy should return true when mock returns 204")
	}
}

func TestVerifyCFWorkersProxy_Failure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	result := VerifyCFWorkersProxy(ts.URL)
	if result {
		t.Error("VerifyCFWorkersProxy should return false when mock returns 403")
	}
}

func TestVerifyCFWorkersProxy_BadURL(t *testing.T) {
	result := VerifyCFWorkersProxy("http://127.0.0.1:1")
	if result {
		t.Error("VerifyCFWorkersProxy should return false for unreachable URL")
	}
}

// ---------------------------------------------------------------------------
// Test: portListening
// ---------------------------------------------------------------------------

func TestPortListening_ActiveListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	if !portListening(port) {
		t.Errorf("portListening(%d) = false, want true (listener active)", port)
	}
}

func TestPortListening_NoListener(t *testing.T) {
	// Find a free port by binding then closing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	if portListening(port) {
		t.Errorf("portListening(%d) = true, want false (no listener)", port)
	}
}

// ---------------------------------------------------------------------------
// Test: truncate helper
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello"},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q_%d", tc.input, tc.maxLen), func(t *testing.T) {
			got := truncate(tc.input, tc.maxLen)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: readStderr with nil reader
// ---------------------------------------------------------------------------

func TestReadStderr_Nil(t *testing.T) {
	got := readStderr(nil)
	if got != "" {
		t.Errorf("readStderr(nil) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Test: Handle fields
// ---------------------------------------------------------------------------

func TestHandleFields(t *testing.T) {
	h := &Handle{
		Process:   nil,
		LocalPort: 1080,
		Method:    "chisel",
		Active:    true,
	}

	if h.LocalPort != 1080 {
		t.Errorf("LocalPort = %d, want 1080", h.LocalPort)
	}
	if h.Method != "chisel" {
		t.Errorf("Method = %s, want chisel", h.Method)
	}
	if !h.Active {
		t.Error("Active should be true")
	}
}
