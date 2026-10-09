//go:build ebpf

package ebpf

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// TestEmbeddedObjectParses checks that the compiled BPF object embedded by
// bpf2go is well-formed: the program and both maps are present, the program is
// a tracepoint, and the ring buffer has the expected type. This needs no
// privileges because it only parses the object; it does not load it into the
// kernel.
func TestEmbeddedObjectParses(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}

	prog, ok := spec.Programs["handle_exec"]
	if !ok {
		t.Fatal("program handle_exec not found in spec")
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_exec type = %v, want TracePoint", prog.Type)
	}

	rb, ok := spec.Maps["events"]
	if !ok {
		t.Fatal("map events not found in spec")
	}
	if rb.Type != ebpf.RingBuf {
		t.Errorf("events map type = %v, want RingBuf", rb.Type)
	}

	drops, ok := spec.Maps["dropped"]
	if !ok {
		t.Fatal("map dropped not found in spec")
	}
	if drops.Type != ebpf.PerCPUArray {
		t.Errorf("dropped map type = %v, want PerCPUArray", drops.Type)
	}
}

// TestExecEventLayout guards the size of the record shared with the kernel so a
// change to the C struct that is not mirrored in Go is caught.
func TestExecEventLayout(t *testing.T) {
	// 4 (pid) + 4 (tid) + 4 (uid) + 4 (pad) + 16 (comm) + 256 (filename).
	// binary.Size also confirms the struct is a fixed-size type that the
	// binary.Read decode in Run can handle.
	const want = 288
	if got := binary.Size(bpfExecEvent{}); got != want {
		t.Errorf("sizeof(bpfExecEvent) = %d, want %d", got, want)
	}
}
