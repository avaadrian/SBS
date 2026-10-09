package store

import (
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/api"
)

// TestCommandRedeliveryOnLostAck verifies a "sent" command that is never
// acknowledged (e.g. the heartbeat response was lost) is redelivered after the
// retry window, but is not redelivered within it or after completion.
func TestCommandRedeliveryOnLostAck(t *testing.T) {
	old := commandRetry
	commandRetry = 20 * time.Millisecond
	defer func() { commandRetry = old }()

	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.EnqueueCommand("h1", api.Command{ID: "c1", Type: api.CmdKill, PID: 42, Created: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	// First delivery: returned and marked sent.
	got, err := st.PendingCommands("h1")
	if err != nil || len(got) != 1 {
		t.Fatalf("first delivery: got %d (%v)", len(got), err)
	}
	// Within the window: not redelivered.
	if got, _ := st.PendingCommands("h1"); len(got) != 0 {
		t.Fatalf("redelivered within window: %d", len(got))
	}
	// After the window: redelivered (the ack never came).
	time.Sleep(30 * time.Millisecond)
	if got, _ := st.PendingCommands("h1"); len(got) != 1 {
		t.Fatalf("not redelivered after window: %d", len(got))
	}
	// Once completed: terminal, never redelivered.
	if err := st.CompleteCommand(api.CommandResult{HostID: "h1", CommandID: "c1", OK: true}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if got, _ := st.PendingCommands("h1"); len(got) != 0 {
		t.Fatalf("completed command redelivered: %d", len(got))
	}
}
