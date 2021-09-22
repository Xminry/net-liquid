/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"github.com/libp2p/go-yamux/v2"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/tjfoc/gmsm/gmtls"
)

var (
	// ErrConnClosed will be returned if the current connection closed.
	ErrConnClosed = errors.New("connection closed")
	// ErrUnknownDir will be returned if the direction is unknown.
	ErrUnknownDir = errors.New("unknown direction")
	// ErrNextProtoMismatch will be returned if next proto mismatch when tls handshaking.
	ErrNextProtoMismatch = errors.New("next proto mismatch")

	defaultYamuxConfig          = yamux.DefaultConfig()
	defaultYamuxConfigForStream = yamux.DefaultConfig()
)

func init() {
	defaultYamuxConfig.MaxStreamWindowSize = 32 << 20
	defaultYamuxConfig.LogOutput = ioutil.Discard
	defaultYamuxConfig.ReadBufSize = 0
	defaultYamuxConfig.ConnectionWriteTimeout = 1 * time.Second
	defaultYamuxConfig.EnableKeepAlive = true
	defaultYamuxConfig.KeepAliveInterval = 10 * time.Second
	defaultYamuxConfigForStream.MaxStreamWindowSize = 16 << 20
	defaultYamuxConfigForStream.LogOutput = ioutil.Discard
	defaultYamuxConfigForStream.ReadBufSize = 0
	defaultYamuxConfigForStream.EnableKeepAlive = false
}

var _ network.Conn = (*conn)(nil)

// conn is an implementation of network.Conn interface.
// If TLS enabled, the net.Conn will be upgraded to *tls.Conn.
// It wraps a yamux.Session which initialized with the Conn as the connection of transport.
type conn struct {
	network.BasicStat
	ctx context.Context
	nw  *tcpNetwork

	c    net.Conn
	sess *yamux.Session

	sessForUni *yamux.Session
	sessForBi  *yamux.Session

	laddr ma.Multiaddr
	raddr ma.Multiaddr

	lPID peer.ID
	rPID peer.ID

	closeC    chan struct{}
	closeOnce sync.Once
}

func (c *conn) handshakeInbound(conn net.Conn) (net.Conn, error) {
	var err error
	finalConn := conn
	if c.nw.enableTls {
		if c.nw.useGMTls {
			// gm tls handshake
			// inbound conn as server
			tlsCfg := c.nw.gmTlsServerCfg.Clone()
			tlsConn := gmtls.Server(finalConn, tlsCfg)
			err = tlsConn.Handshake()
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			connState := tlsConn.ConnectionState()
			// notice: seemingly gm tls not support protocol negotiate
			//if connState.NegotiatedProtocol != tlsCfg.NextProtos[0] {
			//	return nil, ErrNextProtoMismatch
			//}
			c.rPID, err = c.nw.loadPidFuncGm(connState.PeerCertificates)
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			finalConn = tlsConn
		} else {
			// tls handshake
			// inbound conn as server
			tlsCfg := c.nw.tlsCfg.Clone()
			tlsConn := tls.Server(finalConn, tlsCfg)
			err = tlsConn.Handshake()
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			connState := tlsConn.ConnectionState()
			if connState.NegotiatedProtocol != tlsCfg.NextProtos[0] {
				return nil, ErrNextProtoMismatch
			}
			c.rPID, err = c.nw.loadPidFunc(connState.PeerCertificates)
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			finalConn = tlsConn
		}
	} else {
		// exchange PID
		// receive pid
		rpidBytes := make([]byte, 46)
		_, err = finalConn.Read(rpidBytes)
		if err != nil {
			_ = finalConn.Close()
			return nil, err
		}
		c.rPID = peer.ID(rpidBytes)
		// send pid
		_, err = finalConn.Write([]byte(c.lPID))
		if err != nil {
			_ = finalConn.Close()
			return nil, err
		}
	}
	return finalConn, nil
}

func (c *conn) attachYamuxInbound(conn net.Conn) error {
	// inbound conn as server
	sess, err2 := yamux.Server(conn, defaultYamuxConfig)
	if err2 != nil {
		_ = conn.Close()
		return err2
	}
	virtualConnForUni, err3 := sess.Accept()
	if err3 != nil {
		_ = sess.Close()
		_ = conn.Close()
		return err3
	}
	virtualConnForBi, err4 := sess.Accept()
	if err4 != nil {
		_ = virtualConnForUni.Close()
		_ = sess.Close()
		_ = conn.Close()
		return err4
	}

	sessForUni, err5 := yamux.Server(virtualConnForUni, defaultYamuxConfigForStream)
	if err5 != nil {
		_ = virtualConnForBi.Close()
		_ = virtualConnForUni.Close()
		_ = sess.Close()
		_ = conn.Close()
		return err5
	}

	sessForBi, err6 := yamux.Server(virtualConnForBi, defaultYamuxConfigForStream)
	if err6 != nil {
		_ = sessForUni.Close()
		_ = virtualConnForBi.Close()
		_ = virtualConnForUni.Close()
		_ = sess.Close()
		_ = conn.Close()
		return err6
	}
	c.c = conn
	c.sess = sess
	c.sessForUni = sessForUni
	c.sessForBi = sessForBi
	return nil
}

func (c *conn) handshakeOutbound(conn net.Conn) (net.Conn, error) {
	var err error
	finalConn := conn
	if c.nw.enableTls {
		if c.nw.useGMTls {
			// gm tls handshake
			// outbound conn as client
			tlsCfg := c.nw.gmTlsClientCfg.Clone()
			tlsConn := gmtls.Client(finalConn, tlsCfg)
			err = tlsConn.Handshake()
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			connState := tlsConn.ConnectionState()
			// notice: seemingly gm tls not support protocol negotiate
			//if connState.NegotiatedProtocol != tlsCfg.NextProtos[0] {
			//	return nil, ErrNextProtoMismatch
			//}
			c.rPID, err = c.nw.loadPidFuncGm(connState.PeerCertificates)
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			finalConn = tlsConn
		} else {
			// tls handshake
			// outbound conn as client
			tlsCfg := c.nw.tlsCfg.Clone()
			tlsConn := tls.Client(finalConn, tlsCfg)
			err = tlsConn.Handshake()
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			connState := tlsConn.ConnectionState()
			if connState.NegotiatedProtocol != tlsCfg.NextProtos[0] {
				return nil, ErrNextProtoMismatch
			}
			c.rPID, err = c.nw.loadPidFunc(connState.PeerCertificates)
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			finalConn = tlsConn
		}
	} else {
		// exchange PID
		// send pid
		_, err = finalConn.Write([]byte(c.lPID))
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		// receive pid
		rpidBytes := make([]byte, 46)
		_, err = finalConn.Read(rpidBytes)
		if err != nil {
			_ = finalConn.Close()
			return nil, err
		}
		c.rPID = peer.ID(rpidBytes)
	}
	return finalConn, nil
}

func (c *conn) attachYamuxOutbound(conn net.Conn) error {
	// outbound conn as client
	sess, err2 := yamux.Client(conn, defaultYamuxConfig)
	if err2 != nil {
		_ = conn.Close()
		return err2
	}
	virtualConnForUni, err3 := sess.Open(c.ctx)
	if err3 != nil {
		_ = sess.Close()
		_ = conn.Close()
		return err3
	}
	virtualConnForBi, err4 := sess.Open(c.ctx)
	if err4 != nil {
		_ = virtualConnForUni.Close()
		_ = sess.Close()
		_ = conn.Close()
		return err4
	}

	sessForUni, err5 := yamux.Client(virtualConnForUni, defaultYamuxConfigForStream)
	if err5 != nil {
		_ = virtualConnForBi.Close()
		_ = virtualConnForUni.Close()
		_ = sess.Close()
		_ = conn.Close()
		return err5
	}

	sessForBi, err6 := yamux.Client(virtualConnForBi, defaultYamuxConfigForStream)
	if err6 != nil {
		_ = sessForUni.Close()
		_ = virtualConnForBi.Close()
		_ = virtualConnForUni.Close()
		_ = sess.Close()
		_ = conn.Close()
		return err6
	}
	c.c = conn
	c.sess = sess
	c.sessForUni = sessForUni
	c.sessForBi = sessForBi
	return nil
}

func (c *conn) handshakeAndAttachYamux(conn net.Conn) error {
	var err error
	var finalConn net.Conn
	switch c.Direction() {
	case network.Inbound:
		finalConn, err = c.handshakeInbound(conn)
		if err != nil {
			return err
		}
		err = c.attachYamuxInbound(finalConn)
		if err != nil {
			return err
		}
	case network.Outbound:
		finalConn, err = c.handshakeOutbound(conn)
		if err != nil {
			return err
		}
		err = c.attachYamuxOutbound(finalConn)
		if err != nil {
			return err
		}
	default:
		_ = c.Close()
		return ErrUnknownDir
	}
	return nil
}

// newConn create a new conn instance.
func newConn(ctx context.Context, nw *tcpNetwork, c net.Conn, dir network.Direction) (*conn, error) {
	res := &conn{
		BasicStat:  *network.NewStat(dir, time.Now(), nil),
		ctx:        ctx,
		nw:         nw,
		c:          nil,
		sess:       nil,
		sessForUni: nil,
		sessForBi:  nil,
		laddr:      nil,
		raddr:      nil,
		lPID:       nw.LocalPeerID(),
		rPID:       "",
		closeC:     make(chan struct{}),
		closeOnce:  sync.Once{},
	}
	var err error
	res.laddr, err = manet.FromNetAddr(c.LocalAddr())
	if err != nil {
		return nil, err
	}

	res.raddr, err = manet.FromNetAddr(c.RemoteAddr())
	if err != nil {
		return nil, err
	}

	err = res.handshakeAndAttachYamux(c)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// Close this connection.
func (c *conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.SetClosed()
		close(c.closeC)
		err = c.sessForBi.Close()
		if err != nil {
			return
		}
		err = c.sessForUni.Close()
		if err != nil {
			return
		}
		err = c.sess.Close()
		if err != nil {
			return
		}
		//err = c.c.Close()
	})
	return err
}

// LocalAddr is the local net multi-address of the connection.
func (c *conn) LocalAddr() ma.Multiaddr {
	return c.laddr
}

// LocalNetAddr is the local net address of the connection.
func (c *conn) LocalNetAddr() net.Addr {
	return c.c.LocalAddr()
}

// LocalPeerID is the local peer id of the connection.
func (c *conn) LocalPeerID() peer.ID {
	return c.lPID
}

// RemoteAddr is the remote net address of the connection.
func (c *conn) RemoteAddr() ma.Multiaddr {
	return c.raddr
}

// RemoteNetAddr is the remote net address of the connection.
func (c *conn) RemoteNetAddr() net.Addr {
	return c.c.RemoteAddr()
}

// RemotePeerID is the remote peer id of the connection.
func (c *conn) RemotePeerID() peer.ID {
	return c.rPID
}

// Network is the network instance who create this connection.
func (c *conn) Network() network.Network {
	return c.nw
}

// CreateSendStream try to open a send stream with the connection.
func (c *conn) CreateSendStream() (network.SendStream, error) {
	ys, err := c.sessForUni.OpenStream(c.ctx)
	if err != nil {
		return nil, err
	}
	_ = ys.CloseRead()
	return newSendStream(c, ys), nil
}

// AcceptReceiveStream accept a receive stream with the connection.
// It will block until a new receive stream accepted or connection closed.
func (c *conn) AcceptReceiveStream() (network.ReceiveStream, error) {
	select {
	case <-c.closeC:
		return nil, ErrConnClosed
	case <-c.sess.CloseChan():
		_ = c.Close()
		return nil, ErrConnClosed
	case <-c.ctx.Done():
		_ = c.Close()
		return nil, ErrConnClosed
	default:

	}
	rs, err := c.sessForUni.AcceptStream()
	if err != nil {
		return nil, err
	}
	_ = rs.CloseWrite()
	return newReceiveStream(c, rs), nil
}

// CreateBidirectionalStream try to open a bidirectional stream with the connection.
func (c *conn) CreateBidirectionalStream() (network.Stream, error) {
	ys, err := c.sessForBi.OpenStream(c.ctx)
	if err != nil {
		return nil, err
	}
	return newStream(c, ys, network.Outbound), nil
}

// AcceptBidirectionalStream accept a bidirectional stream with the connection.
// It will block until a new bidirectional stream accepted or connection closed.
func (c *conn) AcceptBidirectionalStream() (network.Stream, error) {
	select {
	case <-c.closeC:
		return nil, ErrConnClosed
	case <-c.sess.CloseChan():
		_ = c.Close()
		return nil, ErrConnClosed
	case <-c.ctx.Done():
		_ = c.Close()
		return nil, ErrConnClosed
	default:

	}
	s, err := c.sessForBi.AcceptStream()
	if err != nil {
		return nil, err
	}
	return newStream(c, s, network.Inbound), nil
}
