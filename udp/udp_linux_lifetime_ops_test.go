//go:build linux && !android && !e2e_testing

package udp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func newLifetimeOpSocket(t *testing.T, batch int) *StdConn {
	t.Helper()
	c, err := NewListener(testLogger(), netip.MustParseAddr("127.0.0.1"), 0, false, batch)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	sc := c.(*StdConn)
	t.Cleanup(func() {
		if !sc.closed.Load() {
			if err := sc.Close(); err != nil {
				t.Errorf("owned socket Close: %v", err)
			}
		}
	})
	return sc
}

// This kernel-property probe deliberately bypasses the production admission
// methods: the raw blocking syscall must begin AFTER synchronous shutdown has
// returned. The outer reservation keeps this owned FD alive through the join;
// this is not a claim about observing production Close's shutdown ordering.
func TestListenOutLifetime_PostShutdownReceiveKernelProperty(t *testing.T) {
	for _, batch := range []int{1, 64} {
		t.Run(fmt.Sprintf("batch%d", batch), func(t *testing.T) {
			sc := newLifetimeOpSocket(t, batch)
			msgs, _, _ := sc.PrepareRawMessages(batch)
			if err := sc.reserveFD(); err != nil {
				t.Fatal(err)
			}
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			started, joined := false, false
			t.Cleanup(func() {
				if started && !joined {
					err := unix.Shutdown(sc.sysFd, unix.SHUT_RDWR)
					t.Logf("stage=owned_shutdown_rescue fd=%d err=%v", sc.sysFd, err)
					select {
					case got := <-done:
						joined = true
						t.Logf("stage=rescue_join fd=%d n=%d first_len=%d err=%v", sc.sysFd, got.n, msgs[0].Len, got.err)
					case <-time.After(3 * time.Second):
						// The direct syscall has no inner reservation. Release the
						// outer pin and close this owned FD before aborting, so
						// remaining cleanups cannot deadlock waiting on our pin.
						sc.releaseFD()
						_ = sc.Close()
						panic("post-shutdown kernel probe did not join after owned rescue; nonpass")
					}
				}
				sc.releaseFD()
			})

			err := unix.Shutdown(sc.sysFd, unix.SHUT_RDWR)
			t.Logf("stage=shutdown_complete closed=%t fd=%d err=%v", sc.closed.Load(), sc.sysFd, err)
			if err != nil && !errors.Is(err, unix.ENOTCONN) {
				t.Fatalf("owned socket shutdown: %v", err)
			}
			started = true
			go func() {
				var n uintptr
				var errno unix.Errno
				if batch == 1 {
					n, _, errno = unix.Syscall6(unix.SYS_RECVMSG, uintptr(sc.sysFd),
						uintptr(unsafe.Pointer(&msgs[0].Hdr)), 0, 0, 0, 0)
				} else {
					n, _, errno = unix.Syscall6(unix.SYS_RECVMMSG, uintptr(sc.sysFd),
						uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), unix.MSG_WAITFORONE, 0, 0)
				}
				got := result{n: int(n)}
				if errno != 0 {
					got.err = errno
				}
				done <- got
			}()
			select {
			case got := <-done:
				joined = true
				t.Logf("stage=post_shutdown_raw_join closed=%t fd=%d n=%d first_len=%d err=%v", sc.closed.Load(), sc.sysFd, got.n, msgs[0].Len, got.err)
				if got.err != nil {
					t.Fatalf("raw receive after confirmed shutdown: %v", got.err)
				}
				if batch == 1 && got.n != 0 || batch != 1 && (got.n < 0 || got.n > batch) {
					t.Errorf("unexpected empty-socket raw receive result: n=%d", got.n)
				}
				for _, msg := range msgs {
					if msg.Len != 0 {
						t.Error("unexpected datagram length on empty shutdown socket")
						break
					}
				}
			case <-time.After(2 * time.Second):
				t.Error("post-shutdown raw receive guard expired; nonpass, not kernel-property proof")
			}
		})
	}
}

// Pause two admitted operations before their syscalls, not inside a callback.
// Close must deny new admission but retain ownership until both are released.
func TestListenOutLifetime_ReservedOperations(t *testing.T) {
	sc := newLifetimeOpSocket(t, 1)
	cookie, cookieErr := unix.GetsockoptUint64(sc.sysFd, unix.SOL_SOCKET, unix.SO_COOKIE)
	remaining, started, joined := 0, 0, 0
	closed := make(chan error, 2)
	t.Cleanup(func() {
		for remaining > 0 {
			sc.releaseFD()
			remaining--
		}
		for joined < started {
			select {
			case err := <-closed:
				joined++
				if err != nil {
					t.Errorf("Close after reservation release: %v", err)
				}
			case <-time.After(3 * time.Second):
				panic("reserved-operation probe: Close did not join after all reservations released; nonpass")
			}
		}
	})
	for range 2 {
		if err := sc.reserveFD(); err != nil {
			t.Fatalf("reserveFD: %v", err)
		}
		remaining++
	}
	for range 2 {
		started++
		go func() { closed <- sc.Close() }()
	}

	guard := time.NewTimer(2 * time.Second)
	defer guard.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !sc.closed.Load() {
		select {
		case <-tick.C:
		case <-guard.C:
			t.Fatal("closed-transition guard expired; nonpass")
		}
	}
	if err := sc.reserveFD(); !errors.Is(err, net.ErrClosed) {
		if err == nil {
			sc.releaseFD()
		}
		t.Fatalf("new admission after closed transition: %v", err)
	}
	for remaining > 0 {
		select {
		case err := <-closed:
			joined++
			t.Fatalf("Close returned with %d reservations outstanding: %v", remaining, err)
		default:
		}
		// This stands for a previously admitted syscall entering after Close's
		// transition. The original descriptor must still be owned and valid.
		if _, err := unix.Getsockname(sc.sysFd); err != nil {
			t.Fatalf("reserved descriptor released early: %v", err)
		}
		if cookieErr == nil {
			got, err := unix.GetsockoptUint64(sc.sysFd, unix.SOL_SOCKET, unix.SO_COOKIE)
			if err != nil || got != cookie {
				t.Fatalf("reserved socket identity changed: cookie=%d err=%v", got, err)
			}
		}
		sc.releaseFD()
		remaining--
	}
	// Cleanup positively joins both Close callers after the final release.
}

func TestListenOutLifetime_ClosedOperations(t *testing.T) {
	sink := newLifetimeOpSocket(t, 1)
	destination, err := sink.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	original := newLifetimeOpSocket(t, 1)
	fd := original.sysFd
	oldCookie, oldCookieErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	replacement := newLifetimeOpSocket(t, 1)
	if replacement.sysFd != fd {
		t.Fatalf("owned reuse qualification failed: old_fd=%d replacement_fd=%d; nonpass", fd, replacement.sysFd)
	}
	cookie, cookieErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if oldCookieErr == nil && cookieErr == nil && oldCookie == cookie {
		t.Fatal("replacement has original socket cookie")
	}
	t.Logf("stage=closed_operations closed=%t fd=%d old_cookie=%d old_cookie_err=%v replacement_cookie=%d replacement_cookie_err=%v",
		original.closed.Load(), fd, oldCookie, oldCookieErr, cookie, cookieErr)

	options := []int{unix.SO_RCVBUF, unix.SO_SNDBUF, unix.SO_MARK}
	before := make([]int, len(options))
	for i, option := range options {
		before[i], err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
		if err != nil {
			t.Fatal(err)
		}
	}
	wantClosed := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s: got %v, want net.ErrClosed", name, err)
		}
	}
	wantClosed("WriteTo/IPv4", original.WriteTo([]byte{1}, destination))
	// Exercise the other raw send path without requiring an IPv6 interface;
	// even its address points at the owned sink (IPv4-mapped IPv6).
	mapped := netip.AddrPortFrom(netip.AddrFrom16(destination.Addr().As16()), destination.Port())
	wantClosed("writeTo6", original.writeTo6([]byte{1}, mapped))
	wantClosed("SetRecvBuffer", original.SetRecvBuffer(4096))
	wantClosed("SetSendBuffer", original.SetSendBuffer(4096))
	wantClosed("SetSoMark", original.SetSoMark(before[2]^1))
	_, err = original.GetRecvBuffer()
	wantClosed("GetRecvBuffer", err)
	_, err = original.GetSendBuffer()
	wantClosed("GetSendBuffer", err)
	_, err = original.GetSoMark()
	wantClosed("GetSoMark", err)
	_, err = original.LocalAddr()
	wantClosed("LocalAddr", err)
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	for i := range meminfo {
		meminfo[i] = 0xfeed
	}
	wantClosed("getMemInfo", original.getMemInfo(&meminfo))
	for _, value := range meminfo {
		if value != 0xfeed {
			t.Error("closed stats operation modified output")
			break
		}
	}
	NewUDPStatsEmitter([]Conn{original})()
	for range 2 {
		if err := original.Close(); err != nil {
			t.Errorf("idempotent Close: %v", err)
		}
	}
	for i, option := range options {
		got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
		if err != nil || got != before[i] {
			t.Errorf("replacement option %d changed: got=%d want=%d err=%v", option, got, before[i], err)
		}
	}
	if cookieErr == nil {
		got, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil || got != cookie {
			t.Errorf("replacement identity changed: cookie=%d err=%v", got, err)
		}
	}
	var packet [2]byte
	if n, _, err := unix.Recvfrom(sink.sysFd, packet[:], unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) {
		t.Errorf("closed write reached owned sink or unexpected read failure: n=%d err=%v", n, err)
	}
}

func TestListenOutLifetime_CloseFromCallback(t *testing.T) {
	for _, batch := range []int{1, 64} {
		t.Run(fmt.Sprintf("batch%d", batch), func(t *testing.T) {
			sender := newLifetimeOpSocket(t, batch)
			sc := newLifetimeOpSocket(t, batch)
			addr, err := sc.LocalAddr()
			if err != nil {
				t.Fatal(err)
			}
			if err := sender.WriteTo([]byte{1}, addr); err != nil {
				t.Fatalf("send: %v", err)
			}
			done := make(chan error, 2)
			closeErrors := make(chan error, 2)
			var calls atomic.Int64
			joined := 0
			t.Cleanup(func() {
				for joined < 2 {
					select {
					case <-done:
						joined++
					case <-time.After(3 * time.Second):
						panic("callback Close probe: readers did not join; nonpass")
					}
				}
			})
			for range 2 {
				go func() {
					done <- sc.ListenOut(func(netip.AddrPort, []byte) {
						calls.Add(1)
						closeErrors <- sc.Close()
					})
				}()
			}
			for joined < 2 {
				select {
				case err := <-done:
					joined++
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("ListenOut after callback Close: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("callback Close completion guard expired; nonpass")
				}
			}
			if calls.Load() != 1 {
				t.Errorf("callbacks=%d, want 1", calls.Load())
			}
			select {
			case err := <-closeErrors:
				if err != nil {
					t.Errorf("callback Close: %v", err)
				}
			default:
				t.Error("callback Close did not return")
			}
		})
	}
}
