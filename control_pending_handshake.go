package nebula

import "net/netip"

// PendingHandshakeRef is an opaque, comparable identity for a local outbound
// handshake. A zero reference means no ready, tracked handshake was observed.
// References to different handshakes compare unequal, even if their numeric
// indexes match. A reference is process-local and must not be serialized or used
// as a tunnel, peer-authentication, or handshake-success indication.
//
// Retaining a nonzero reference keeps the handshake object and its reachable
// state (including cached packets) alive. Callers should bound the number and
// lifetime of retained references.
type PendingHandshakeRef struct {
	hh *HandshakeHostInfo
}

// IsZero reports whether r is the zero reference. It does not query the current
// state of a previously observed handshake.
func (r PendingHandshakeRef) IsZero() bool {
	return r.hh == nil
}

// PendingHandshake returns the identity of the ready, still-tracked local
// outbound handshake for vpnAddr, or a zero reference if none is ready and
// tracked at the observation point. Absence does not imply successful
// completion: a handshake may not yet be ready, or may have expired, failed,
// completed, or been replaced. The returned reference does not keep a handshake
// pending, and its state may change immediately after this call returns.
// Caller should take care to Unmap() any 4in6 addresses prior to calling.
//
// This call may wait for ongoing handshake work. It must not be called while
// holding the handshake manager or handshake object's lock, including from
// callbacks invoked with either lock held; it is not reentrant from those
// callbacks.
func (c *Control) PendingHandshake(vpnAddr netip.Addr) PendingHandshakeRef {
	hm := c.f.handshakeManager
	hh := hm.queryVpnIp(vpnAddr)
	if hh == nil {
		return PendingHandshakeRef{}
	}

	// Never wait for hh while holding the manager lock. Outbound handling and
	// continuation hold hh before accessing the manager.
	hh.Lock()
	defer hh.Unlock()
	hm.RLock()
	defer hm.RUnlock()

	// Membership and readiness must hold together: the candidate may have
	// been removed or replaced while we waited for hh. This revalidation is
	// the observation point; no mutable HostInfo fields need to be copied.
	if hm.vpnIps[vpnAddr] != hh || !hh.ready {
		return PendingHandshakeRef{}
	}
	return PendingHandshakeRef{hh: hh}
}
