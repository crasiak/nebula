package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/overlay"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// newServicePair returns a server at 10.0.0.1 and a client at 10.0.0.2 that
// reaches it directly over loopback.
func newServicePair(t *testing.T) (server, client *Service) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	server = newSimpleService(ca, caKey, "server", netip.MustParseAddr("10.0.0.1"), m{
		"listen": m{"host": "127.0.0.1", "port": port},
	})
	t.Cleanup(func() { _ = server.Close() })
	client = newSimpleService(ca, caKey, "client", netip.MustParseAddr("10.0.0.2"), m{
		"static_host_map": m{"10.0.0.1": []string{"127.0.0.1:" + strconv.Itoa(port)}},
	})
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

// abandonHandshake writes a TCP SYN from src into the service's overlay
// device, as if a peer had dialed port and then gone away. Nothing answers
// the SYN-ACK, so gvisor keeps the handshake open for its full retransmit
// schedule (127s).
func abandonHandshake(t *testing.T, s *Service, src netip.Addr, port uint16) {
	t.Helper()
	dev := s.control.Device().(*overlay.UserDevice)
	dst := tcpip.AddrFrom4(dev.Networks()[0].Addr().As4())
	from := tcpip.AddrFrom4(src.As4())

	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     from,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	seg := header.TCP(b[header.IPv4MinimumSize:])
	seg.Encode(&header.TCPFields{
		SrcPort:    40000,
		DstPort:    port,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, from, dst, uint16(len(seg)))
	seg.SetChecksum(^seg.CalculateChecksum(xsum))
	if _, err := dev.Write(b); err != nil {
		t.Fatal(err)
	}
}

// pendingHandshakes counts the endpoints waiting in SYN-RCVD for the final
// ACK of a handshake.
func pendingHandshakes(s *Service) int {
	n := 0
	for _, ep := range s.ipstack.RegisteredEndpoints() {
		if e, ok := ep.(*tcp.Endpoint); ok && e.EndpointState() == tcp.StateSynRecv {
			n++
		}
	}
	return n
}

// within fails the test if f has not returned after d. It never waits longer
// than d, so a regression fails instead of hanging; f is left running.
func within(t *testing.T, d time.Duration, what string, f func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		t.Errorf("%s still blocked after %s", what, d)
		return false
	}
}

func echo(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}

func roundTrip(ctx context.Context, s *Service, address string) error {
	c, err := s.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return errors.New("echo mismatch: " + string(buf))
	}
	return nil
}

// A handshake that never completes must not stop the service from accepting
// other connections, listening or closing listeners. tcpHandler used to hold
// s.mu through CreateEndpoint, which waits out gvisor's whole SYN-ACK
// retransmit schedule.
func TestAbandonedHandshakeDoesNotBlockService(t *testing.T) {
	server, client := newServicePair(t)
	ln, err := server.Listen("tcp", ":1234")
	if err != nil {
		t.Fatal(err)
	}
	go echo(ln)

	abandonHandshake(t, server, netip.MustParseAddr("10.0.0.99"), 1234)
	deadline := time.Now().Add(5 * time.Second)
	for pendingHandshakes(server) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the abandoned handshake never started")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := roundTrip(ctx, client, "10.0.0.1:1234"); err != nil {
		t.Errorf("round trip during the abandoned handshake: %v", err)
	}
	within(t, 2*time.Second, "Listen(:1235)", func() {
		if l, err := server.Listen("tcp", ":1235"); err == nil {
			_ = l.Close()
		}
	})
	within(t, 2*time.Second, "listener Close", func() { _ = ln.Close() })

	if n := pendingHandshakes(server); n != 1 {
		t.Errorf("%d handshakes pending at the end, want the abandoned one still pending", n)
	}
}

// A connection nobody accepts must not stop the service from listening or
// closing the listener. tcpHandler used to hold s.mu until Accept took the
// connection.
func TestUnacceptedConnectionDoesNotBlockService(t *testing.T) {
	server, client := newServicePair(t)
	ln, err := server.Listen("tcp", ":1234")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "tcp", "10.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	within(t, 2*time.Second, "Listen(:1235)", func() {
		if l, err := server.Listen("tcp", ":1235"); err == nil {
			_ = l.Close()
		}
	})
	if !within(t, 2*time.Second, "listener Close", func() { _ = ln.Close() }) {
		// Take the connection so the blocked calls can finish.
		go func() { _, _ = ln.Accept() }()
		return
	}

	// The handler closes the connection it could not hand over.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("client Read after the listener closed = %v, want io.EOF", err)
	}
}

// closeListener turns a panic in Close into a test failure.
func closeListener(t *testing.T, l net.Listener) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Close panicked: %v", r)
			err = nil
		}
	}()
	return l.Close()
}

func TestListenerClose(t *testing.T) {
	// Listen and Close need no running nebula.
	s := &Service{}
	s.mu.listeners = map[uint16]*tcpListener{}

	first, err := s.Listen("tcp", ":1234")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		_, err := first.Accept()
		accepted <- err
	}()
	if err := closeListener(t, first); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("pending Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending Accept still blocked 2s after Close")
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
	}
	if err := closeListener(t, first); !errors.Is(err, net.ErrClosed) {
		t.Errorf("second Close = %v, want net.ErrClosed", err)
	}

	// A late Close of the first listener must not unregister a new listener
	// on the same port.
	second, err := s.Listen("tcp", ":1234")
	if err != nil {
		t.Fatalf("Listen after Close: %v", err)
	}
	_ = closeListener(t, first)
	if l, err := s.Listen("tcp", ":1234"); err == nil {
		_ = l.Close()
		t.Error("Listen(:1234) succeeded while the second listener is open on it")
	}
	if err := closeListener(t, second); err != nil {
		t.Errorf("Close of the second listener: %v", err)
	}
}
