package proc

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"github.com/avaadrian/sbs/internal/event"
)

// Constants from linux/connector.h and linux/cn_proc.h.
const (
	netlinkConnector  = 11
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 0x00000002

	nlmsgHdrLen = 16
	cnMsgLen    = 20
)

// Netlink streams exec events from the kernel process connector. It needs
// CAP_NET_ADMIN (root) and sees every exec, unlike polling.
type Netlink struct {
	fd int
}

// OpenNetlink subscribes to process events.
func OpenNetlink() (*Netlink, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8<<20)

	// nlmsghdr + cn_msg + op
	msg := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	le := binary.LittleEndian
	le.PutUint32(msg[0:], uint32(len(msg)))
	le.PutUint16(msg[4:], syscall.NLMSG_DONE)
	le.PutUint32(msg[12:], uint32(os.Getpid()))
	le.PutUint32(msg[16:], cnIdxProc)
	le.PutUint32(msg[20:], cnValProc)
	le.PutUint16(msg[32:], 4)
	le.PutUint32(msg[36:], procCnMcastListen)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink subscribe: %w", err)
	}
	return &Netlink{fd: fd}, nil
}

// Run emits a process event for every exec until ctx is cancelled.
func (n *Netlink) Run(ctx context.Context, out chan<- *event.Event, skip func(pid int) bool) error {
	go func() {
		<-ctx.Done()
		syscall.Close(n.fd)
	}()
	buf := make([]byte, 64<<10)
	le := binary.LittleEndian
	for {
		nr, _, err := syscall.Recvfrom(n.fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err == syscall.EINTR || err == syscall.ENOBUFS {
				continue // ENOBUFS: we fell behind and the kernel dropped events
			}
			return fmt.Errorf("netlink recv: %w", err)
		}
		for off := 0; off+nlmsgHdrLen <= nr; {
			ln := int(le.Uint32(buf[off:]))
			if ln < nlmsgHdrLen || off+ln > nr {
				break
			}
			body := buf[off+nlmsgHdrLen : off+ln]
			off += (ln + 3) &^ 3
			// proc_event starts after cn_msg: what(4) cpu(4) ts(8) then data.
			if len(body) < cnMsgLen+16+8 {
				continue
			}
			ev := body[cnMsgLen:]
			if le.Uint32(ev[0:]) != procEventExec {
				continue
			}
			tgid := int(le.Uint32(ev[20:]))
			if skip != nil && skip(tgid) {
				continue
			}
			if p := Read(tgid); p != nil {
				select {
				case out <- NewEvent(p, "netlink"):
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}
