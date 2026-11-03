package nebula

import (
	"context"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
)

// A reference must remain usable as a map key, not merely support IsZero.
var _ = map[PendingHandshakeRef]bool{}

func pendingHandshakeControl() *Control {
	l := test.NewLogger()
	hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), &udp.NoopConn{}, defaultHandshakeConfig)
	hm.mainHostMap.preferredRanges.Store(&[]netip.Prefix{})
	f := &Interface{handshakeManager: hm, hostMap: hm.mainHostMap, lightHouse: hm.lightHouse, l: l}
	hm.f = f
	return &Control{f: f, l: l}
}

func TestControlPendingHandshakeStates(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.2")
	other := netip.MustParseAddr("10.0.0.3")
	c := pendingHandshakeControl()
	hm := c.f.handshakeManager

	require.True(t, (PendingHandshakeRef{}).IsZero())
	require.True(t, c.PendingHandshake(peer).IsZero(), "absent")
	hi := hm.StartHandshake(peer, nil)
	require.True(t, c.PendingHandshake(peer).IsZero(), "not yet ready")
	hh := hm.queryVpnIp(peer)
	hh.Lock()
	hh.ready = true
	hh.Unlock()
	ref := c.PendingHandshake(peer)
	require.False(t, ref.IsZero())
	require.Equal(t, ref, c.PendingHandshake(peer), "stable identity")
	require.True(t, c.PendingHandshake(other).IsZero(), "different peer")
	require.True(t, map[PendingHandshakeRef]bool{ref: true}[c.PendingHandshake(peer)])

	hm.Complete(hi, c.f)
	require.Same(t, hi, hm.mainHostMap.QueryVpnAddr(peer))
	require.True(t, c.PendingHandshake(peer).IsZero(), "completed, even with a current tunnel")
	require.False(t, ref.IsZero(), "a retained identity is not a live status query")

	// Start a genuine new generation while the old tunnel is still published.
	hi2 := hm.StartHandshake(peer, nil)
	hh2 := hm.queryVpnIp(peer)
	hh2.Lock()
	hh2.ready = true
	hh2.Unlock()
	ref2 := c.PendingHandshake(peer)
	require.False(t, ref2.IsZero())
	require.NotEqual(t, ref, ref2)

	// Expire using the real outbound timeout path, without sending anything.
	hh2.Lock()
	hi2.remotes = NewRemoteList([]netip.Addr{peer}, nil)
	hh2.counter = hm.config.retries
	hh2.Unlock()
	hm.handleOutbound(peer, false)
	require.True(t, c.PendingHandshake(peer).IsZero(), "expired")
}

func TestControlPendingHandshakeIndexReuse(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.2")
	c := pendingHandshakeControl()
	hm := c.f.handshakeManager
	var refs [2]PendingHandshakeRef
	for i := range refs {
		hi := hm.StartHandshake(peer, nil)
		hh := hm.queryVpnIp(peer)
		hh.Lock()
		hi.localIndexId = 42 // Deliberately identical numeric identities, distinct objects.
		hh.ready = true
		hh.Unlock()
		refs[i] = c.PendingHandshake(peer)
		require.False(t, refs[i].IsZero())
		hm.DeleteHostInfo(hi)
	}
	require.NotEqual(t, refs[0], refs[1], "an index reused by another generation must not cause ABA")
}

// waitPendingHandshakeLock is a test-only barrier at the actual public accessor's
// hh.Lock. A parked stack (not a sleep) proves that the first manager query ran.
// Keeping this outside production code avoids adding a callback under query locks.
func waitPendingHandshakeLock(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(stack, "[sync.Mutex.Lock]") && strings.Contains(stack, "(*Control).PendingHandshake(") {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("accessor did not park on hh.Lock after its initial manager query")
}

func receivePendingHandshake[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("pending handshake operation blocked (possible lock-order inversion)")
		var zero T
		return zero
	}
}

func TestControlPendingHandshakeRevalidatesAfterWaiting(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.2")
	other := netip.MustParseAddr("10.0.0.3")
	for _, change := range []string{"removed", "completed", "replaced", "different peer", "not ready"} {
		t.Run(change, func(t *testing.T) {
			c := pendingHandshakeControl()
			hm := c.f.handshakeManager
			hi := hm.StartHandshake(peer, nil)
			hh := hm.queryVpnIp(peer)
			hh.Lock()
			hh.ready = true
			var unlock sync.Once
			defer unlock.Do(hh.Unlock)
			result := make(chan PendingHandshakeRef, 1)
			go func() { result <- c.PendingHandshake(peer) }()
			waitPendingHandshakeLock(t)

			// Must finish while the accessor waits on hh. Holding the manager
			// across that wait would deadlock this real manager operation.
			changed := make(chan struct{}, 1)
			go func() {
				switch change {
				case "removed":
					hm.DeleteHostInfo(hi)
				case "completed":
					hm.Complete(hi, c.f)
				case "replaced":
					hm.DeleteHostInfo(hi)
					hm.StartHandshake(peer, func(newHH *HandshakeHostInfo) { newHH.ready = true })
				case "different peer":
					hm.Lock()
					delete(hm.vpnIps, peer)
					hm.vpnIps[other] = hh
					hm.Unlock()
				case "not ready":
					// The caller owns hh.Lock; synchronize this mutation back
					// through changed before releasing it.
					hh.ready = false
				}
				changed <- struct{}{}
			}()
			receivePendingHandshake(t, changed)
			unlock.Do(hh.Unlock)
			require.True(t, receivePendingHandshake(t, result).IsZero(), "candidate is no longer ready membership for this peer")
		})
	}
}

func TestControlPendingHandshakeDoesNotLockMainHostMap(t *testing.T) {
	c := pendingHandshakeControl()
	peer := netip.MustParseAddr("10.0.0.2")
	c.f.handshakeManager.StartHandshake(peer, func(hh *HandshakeHostInfo) { hh.ready = true })
	c.f.hostMap.Lock()
	defer c.f.hostMap.Unlock()
	result := make(chan PendingHandshakeRef, 1)
	go func() { result <- c.PendingHandshake(peer) }()
	require.False(t, receivePendingHandshake(t, result).IsZero())
}

// pausePendingHandshakeLog parks the real continuation while it still holds hh,
// just before it updates vpnAddrs and calls Complete. No test hook is added to
// the handshake machine, manager, or accessor.
type pausePendingHandshakeLog struct {
	slog.Handler
	entered chan struct{}
	release chan struct{}
}

func (h *pausePendingHandshakeLog) Enabled(context.Context, slog.Level) bool { return true }
func (h *pausePendingHandshakeLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message == "Handshake message received" {
		close(h.entered)
		<-h.release
	}
	return nil
}

// readyPendingHandshake builds a real initiator through buildStage0Packet and
// returns the responder's valid IX continuation. All I/O is in-memory/NoopConn.
func readyPendingHandshake(t *testing.T) (*Control, *HandshakeHostInfo, []byte, ViaSender) {
	t.Helper()
	c := pendingHandshakeControl()
	hm := c.f.handshakeManager
	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	pool := ct.NewTestCAPool(ca)
	makeState := func(name, network string) *CertState {
		crt, _, rawKey, _ := ct.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey,
			name, ca.NotBefore(), ca.NotAfter(), []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil)
		priv, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawKey)
		require.NoError(t, err)
		hsBytes, err := crt.MarshalForHandshakes()
		require.NoError(t, err)
		cred := handshake.NewCredential(crt, hsBytes, priv, noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256))
		return &CertState{initiatingVersion: cert.Version2, v2Cert: crt, v2Credential: cred}
	}
	initState := makeState("initiator", "10.0.0.1/24")
	respState := makeState("responder", "10.0.0.2/24")
	hm.lightHouse.remoteAllowList.Store(&RemoteAllowList{})
	c.f.pki = &PKI{}
	c.f.pki.cs.Store(initState)
	c.f.pki.caPool.Store(pool)
	c.f.myVpnAddrsTable = new(bart.Lite)
	c.f.myVpnAddrsTable.Insert(netip.MustParsePrefix("10.0.0.1/32"))
	c.f.myVpnNetworksTable = new(bart.Lite)
	c.f.myVpnNetworksTable.Insert(netip.MustParsePrefix("10.0.0.0/24"))
	c.f.metricHandshakes = metrics.NewHistogram(metrics.NewUniformSample(10))
	peer := netip.MustParseAddr("10.0.0.2")
	hi := hm.StartHandshake(peer, nil)
	hi.remotes = NewRemoteList([]netip.Addr{peer}, nil)
	hh := hm.queryVpnIp(peer)
	hh.Lock()
	ready := hm.buildStage0Packet(hh)
	hh.Unlock()
	require.True(t, ready)
	resp, err := handshake.NewMachine(cert.Version2, respState.GetCredential, hm.certVerifier(),
		func() (uint32, error) { return 2000, nil }, false, header.HandshakeIXPSK0)
	require.NoError(t, err)
	packet, result, err := resp.ProcessPacket(nil, hi.HandshakePacket[handshakePacketStage0])
	require.NoError(t, err)
	require.NotNil(t, result)
	return c, hh, packet, ViaSender{UdpAddr: netip.MustParseAddrPort("127.0.0.1:4242")}
}

func TestControlPendingHandshakeContinuationCompletion(t *testing.T) {
	c, hh, packet, via := readyPendingHandshake(t)
	hm := c.f.handshakeManager
	peer := netip.MustParseAddr("10.0.0.2")
	require.False(t, c.PendingHandshake(peer).IsZero())
	pause := &pausePendingHandshakeLog{Handler: slog.DiscardHandler, entered: make(chan struct{}), release: make(chan struct{})}
	c.f.l = slog.New(pause)
	var release sync.Once
	defer release.Do(func() { close(pause.release) })
	done := make(chan struct{}, 1)
	go func() {
		hm.continueHandshake(via, hh, packet)
		done <- struct{}{}
	}()
	receivePendingHandshake(t, pause.entered)
	result := make(chan PendingHandshakeRef, 1)
	go func() { result <- c.PendingHandshake(peer) }()
	waitPendingHandshakeLock(t)
	release.Do(func() { close(pause.release) })
	receivePendingHandshake(t, done)
	require.True(t, receivePendingHandshake(t, result).IsZero(), "real continuation removed the candidate while the accessor waited")
	require.Same(t, hh.hostinfo, hm.mainHostMap.QueryVpnAddr(peer))
	require.NotNil(t, hh.hostinfo.ConnectionState)
}

func TestControlPendingHandshakeConcurrentReadiness(t *testing.T) {
	c, initial, _, _ := readyPendingHandshake(t)
	hm := c.f.handshakeManager
	peer := netip.MustParseAddr("10.0.0.2")
	hm.DeleteHostInfo(initial.hostinfo)
	hm.StartHandshake(peer, nil)
	hh := hm.queryVpnIp(peer)
	require.True(t, c.PendingHandshake(peer).IsZero())

	var readers sync.WaitGroup
	started := make(chan struct{}, 8)
	stop := make(chan struct{})
	for range 8 {
		readers.Go(func() {
			started <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
					_ = c.PendingHandshake(peer)
				}
			}
		})
	}
	for range 8 {
		receivePendingHandshake(t, started)
	}
	// Exercise the production readiness write, not an unrelated field race.
	hh.Lock()
	ready := hm.buildStage0Packet(hh)
	hh.Unlock()
	close(stop)
	readers.Wait()
	require.True(t, ready)
	require.False(t, c.PendingHandshake(peer).IsZero())
}

func TestControlPendingHandshakeConcurrentContinuation(t *testing.T) {
	c, hh, packet, via := readyPendingHandshake(t)
	peer := netip.MustParseAddr("10.0.0.2")
	ref := c.PendingHandshake(peer)
	require.False(t, ref.IsZero())
	var readers sync.WaitGroup
	started := make(chan struct{}, 8)
	stop := make(chan struct{})
	for range 8 {
		readers.Go(func() {
			started <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
					r := c.PendingHandshake(peer)
					if !r.IsZero() && r != ref {
						t.Error("unexpected generation")
					}
				}
			}
		})
	}
	for range 8 {
		receivePendingHandshake(t, started)
	}
	c.f.handshakeManager.continueHandshake(via, hh, packet)
	close(stop)
	readers.Wait()
	require.True(t, c.PendingHandshake(peer).IsZero())
	require.Same(t, hh.hostinfo, c.f.hostMap.QueryVpnAddr(peer))
}
