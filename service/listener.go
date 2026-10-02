package service

import (
	"net"
)

type tcpListener struct {
	port   uint16
	s      *Service
	addr   *net.TCPAddr
	accept chan net.Conn
	// closed is closed by Close. accept is never closed, since a handler may
	// still be offering a connection on it.
	closed chan struct{}
}

func (l *tcpListener) Accept() (net.Conn, error) {
	// Don't hand out a connection that is on offer after Close
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}

	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *tcpListener) Close() error {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()

	// If we are no longer registered we were already closed, and the port may
	// belong to a newer listener
	if l.s.mu.listeners[l.port] != l {
		return net.ErrClosed
	}
	delete(l.s.mu.listeners, l.port)

	close(l.closed)

	return nil
}

// Addr returns the listener's network address.
func (l *tcpListener) Addr() net.Addr {
	return l.addr
}
