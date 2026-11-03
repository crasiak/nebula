//go:build linux && !android && !e2e_testing

package udp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These probes inject lifecycle ordering, not syscall results. They qualify
// natural FD reuse using an owned replacement; they do not establish that reuse
// caused the original CI hang. No parallel tests, dup2, or retry-until-red loop.
func TestListenOutLifetime_CloseBeforeListenOut(t *testing.T) {
	for _, batch := range []int{1, 64} {
		t.Run(fmt.Sprintf("batch%d", batch), func(t *testing.T) {
			runListenOutLifetimeProbe(t, batch, false)
		})
	}
}

func TestListenOutLifetime_CloseDuringCallback(t *testing.T) {
	for _, batch := range []int{1, 64} {
		t.Run(fmt.Sprintf("batch%d", batch), func(t *testing.T) {
			runListenOutLifetimeProbe(t, batch, true)
		})
	}
}

func runListenOutLifetimeProbe(t *testing.T, batch int, holdCallback bool) {
	t.Helper()
	newSocket := func() *StdConn {
		t.Helper()
		c, err := NewListener(testLogger(), netip.MustParseAddr("127.0.0.1"), 0, false, batch)
		if err != nil {
			t.Fatalf("probe setup: NewListener: %v", err)
		}
		return c.(*StdConn)
	}

	// Allocate the sender before freeing the target FD, so it cannot take the
	// slot intended for the replacement. All traffic stays on owned loopback UDP.
	sender := newSocket()
	t.Cleanup(func() { _ = sender.Close() })
	original := newSocket()
	originalFD := original.sysFd
	originalCookie, originalCookieErr := unix.GetsockoptUint64(originalFD, unix.SOL_SOCKET, unix.SO_COOKIE)
	var replacement *StdConn
	var calls atomic.Int64
	var abortHeldCallback atomic.Bool
	entered := make(chan struct{}, 1)
	stalePacket := make(chan struct{}, 1)
	resume := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	done := make(chan error, 1)
	started, joined := false, false

	// Keep the replacement FD owned until the reader has joined. shutdown wakes
	// a stale syscall without freeing its descriptor for some unrelated owner.
	// A failed guard is never a pass. If rescue itself fails, abort the test
	// process rather than leave a reader goroutine (or a pod) hanging indefinitely.
	t.Cleanup(func() {
		// If setup/reuse qualification failed while the callback was held, do
		// not let it resume into a syscall on an unqualified descriptor.
		abortHeldCallback.Store(true)
		release()
		if !original.closed.Load() {
			if err := original.Close(); err != nil {
				t.Errorf("cleanup original Close: %v", err)
			}
		}
		if replacement != nil {
			if err := unix.Shutdown(replacement.sysFd, unix.SHUT_RDWR); err != nil && !errors.Is(err, unix.ENOTCONN) {
				t.Errorf("cleanup owned replacement shutdown: %v", err)
			}
		}
		if started && !joined {
			select {
			case err := <-done:
				joined = true
				t.Logf("stage=rescue_join closed=%t fd=%d callbacks=%d err=%v", original.closed.Load(), originalFD, calls.Load(), err)
			case <-time.After(3 * time.Second):
				if replacement != nil {
					_ = replacement.Close()
				}
				panic("lifetime probe rescue failed: reader did not join after owned socket shutdown; nonpass")
			}
		}
		if replacement != nil {
			if err := replacement.Close(); err != nil {
				t.Errorf("cleanup owned replacement Close: %v", err)
			}
		}
	})

	start := func() {
		started = true
		go func() {
			var listenErr error
			defer func() { done <- listenErr }() // also joins cleanup-only Goexit
			listenErr = original.ListenOut(func(netip.AddrPort, []byte) {
				if calls.Add(1) == 1 && holdCallback {
					entered <- struct{}{}
					<-resume
					if abortHeldCallback.Load() {
						runtime.Goexit() // failed setup only; never counted as a pass
					}
					return
				}
				select {
				case stalePacket <- struct{}{}:
				default:
				}
			})
		}()
	}
	send := func(to *StdConn) {
		t.Helper()
		addr, err := to.LocalAddr()
		if err != nil {
			t.Fatalf("probe setup: LocalAddr: %v", err)
		}
		if err := sender.WriteTo([]byte{1}, addr); err != nil {
			t.Fatalf("probe setup: send owned datagram: %v", err)
		}
	}

	if holdCallback {
		start()
		send(original)
		select {
		case <-entered:
			t.Logf("stage=callback_held closed=%t fd=%d callbacks=%d", original.closed.Load(), originalFD, calls.Load())
		case err := <-done:
			joined = true
			t.Fatalf("probe setup: reader exited before real packet callback: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("probe setup guard expired before real packet callback; nonpass, not causal evidence")
		}
	}

	if err := original.Close(); err != nil {
		t.Fatalf("original Close: %v", err)
	}
	// Allocate immediately, before logging or opening anything else. Equality is
	// mandatory: failure to obtain this owned slot is a nonpass qualification
	// failure, not a skipped case and not evidence for or against the hypothesis.
	replacement = newSocket()
	if replacement.sysFd != originalFD {
		t.Fatalf("reuse qualification failed: original_fd=%d replacement_fd=%d; nonpass, no stale-FD conclusion", originalFD, replacement.sysFd)
	}
	replacementCookie, replacementCookieErr := unix.GetsockoptUint64(replacement.sysFd, unix.SOL_SOCKET, unix.SO_COOKIE)
	t.Logf("stage=reuse_qualified closed=%t fd=%d original_cookie=%d original_cookie_err=%v replacement_cookie=%d replacement_cookie_err=%v callbacks=%d",
		original.closed.Load(), originalFD, originalCookie, originalCookieErr, replacementCookie, replacementCookieErr, calls.Load())
	if originalCookieErr == nil && replacementCookieErr == nil && originalCookie == replacementCookie {
		t.Fatal("reuse qualification failed: replacement has original socket cookie")
	}

	// Queue a nonempty datagram while the old reader is either not started or
	// held inside the real packet callback. Only the replacement may consume it.
	send(replacement)
	if holdCallback {
		release()
	} else {
		start()
	}

	select {
	case err := <-done:
		joined = true
		t.Logf("stage=reader_joined closed=%t fd=%d callbacks=%d err=%v", original.closed.Load(), originalFD, calls.Load(), err)
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("closed ListenOut returned %v, want net.ErrClosed", err)
		}
	case <-stalePacket:
		t.Error("stale FD access: closed reader delivered an owned replacement datagram")
		return // cleanup shuts down the replacement and joins the old reader
	case <-time.After(2 * time.Second):
		t.Error("reader completion guard expired; nonpass, not proof of stale FD access")
		return
	}

	wantCalls := int64(0)
	if holdCallback {
		wantCalls = 1
	}
	if got := calls.Load(); got != wantCalls {
		t.Errorf("callbacks=%d, want %d (no replacement datagrams)", got, wantCalls)
	}
	// Verify preservation only after joining, so this read cannot compete with
	// the old reader and accidentally manufacture a green result.
	var packet [2]byte
	n, _, err := unix.Recvfrom(replacement.sysFd, packet[:], unix.MSG_DONTWAIT)
	if err != nil || n != 1 || packet[0] != 1 {
		t.Errorf("replacement datagram not preserved: n=%d err=%v; no payload logged", n, err)
	}
}
