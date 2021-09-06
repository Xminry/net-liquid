/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/reuse"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/types"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/util"
	api "chainmaker.org/chainmaker/protocol/v2"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/tjfoc/gmsm/gmtls"
)

const (
	// TCPNetworkVersion is the current version of tcp network.
	TCPNetworkVersion = "v0.0.1"
)

var (
	// ErrNilTlsCfg will be returned if tls config is nil when network starting.
	ErrNilTlsCfg = errors.New("nil tls config")
	// ErrNilGMTlsServerCfg will be returned if gm tls server config is nil when gm tls enabled.
	ErrNilGMTlsServerCfg = errors.New("nil gm tls server config")
	// ErrNilGMTlsClientCfg will be returned if gm tls client config is nil when gm tls enabled.
	ErrNilGMTlsClientCfg = errors.New("nil gm tls client config")
	// ErrEmptyTlsCerts will be returned if no tls cert given when network starting with tls enabled.
	ErrEmptyTlsCerts = errors.New("empty tls certs")
	// ErrGMTlsCertsForServerLack will be returned if the count of certs for gm tls server configuration less than two.
	ErrGMTlsCertsForServerLack = errors.New("at last two certs required for gm tls server config")
	// ErrEmptyGMTlsClientCerts will be returned if no certs for gm tls client configuration.
	ErrEmptyGMTlsClientCerts = errors.New("empty gm tls certs for client")
	// ErrNilAddr will be returned if the listening address is empty.
	ErrNilAddr = errors.New("nil addr")
	// ErrEmptyListenAddress will be returned if no listening address given.
	ErrEmptyListenAddress = errors.New("empty listen address")
	// ErrListenerRequired will be returned if no listener created.
	ErrListenerRequired = errors.New("at least one listener is required")
	// ErrConnRejectedByConnHandler will be returned if connection handler reject a connection when establishing.
	ErrConnRejectedByConnHandler = errors.New("connection rejected by conn handler")
	// ErrNotTheSameNetwork will be returned if the connection disconnected is not created by current network.
	ErrNotTheSameNetwork = errors.New("not the same network")
	// ErrPidMismatch will be returned if the remote peer id is not the expected one.
	ErrPidMismatch = errors.New("pid mismatch")
	// ErrNilLoadPidFunc will be returned if loadPidFunc is nil.
	ErrNilLoadPidFunc = errors.New("load peer id function required")
	// ErrWrongTcpAddr  will be returned if the address is wrong when calling Dial method.
	ErrWrongTcpAddr = errors.New("wrong tcp address format")
	// ErrEmptyLocalPeerId will be returned if load local peer id failed.
	ErrEmptyLocalPeerId = errors.New("empty local peer id")
	// ErrNoUsableLocalAddress will be returned if no usable local address found
	// when the local listening address is a Unspecified address.
	ErrNoUsableLocalAddress = errors.New("no usable local address found")
	// ErrLocalPidNotSet will be returned if local peer id not set on insecurity mode.
	ErrLocalPidNotSet = errors.New("local peer id not set")

	listenMatcher      = mafmt.And(mafmt.IP, mafmt.Base(ma.P_TCP))
	dialMatcherNoP2p   = mafmt.TCP
	dialMatcherWithP2p = mafmt.And(mafmt.TCP, mafmt.Base(ma.P_P2P))

	control = reuse.Control
)

// Option is a function to set option value for tcp network.
type Option func(n *tcpNetwork) error

var _ network.Network = (*tcpNetwork)(nil)

// tcpNetwork is an implementation of network.Network interface.
// It uses TCP as transport layer.
// Crypto with TLS supported, and insecurity(TLS disabled) supported.
type tcpNetwork struct {
	mu   sync.RWMutex
	once sync.Once
	ctx  context.Context

	tlsCfg         *tls.Config
	loadPidFunc    types.LoadPeerIdFromTlsCertFunc
	enableTls      bool
	gmTlsServerCfg *gmtls.Config
	gmTlsClientCfg *gmtls.Config
	loadPidFuncGm  types.LoadPeerIdFromGMTlsCertFunc
	useGMTls       bool
	connHandler    network.ConnHandler

	lPID         peer.ID
	lAddrList    []ma.Multiaddr
	tcpListeners []net.Listener
	listening    bool

	closeChan chan struct{}

	logger api.Logger
}

func (t *tcpNetwork) apply(opt ...Option) error {
	for _, o := range opt {
		if err := o(t); err != nil {
			return err
		}
	}
	return nil
}

// WithTlsCfg set a tls.Config option value.
// If enable tls is false, tls.Config will not usable.
func WithTlsCfg(tlsCfg *tls.Config) Option {
	return func(n *tcpNetwork) error {
		n.tlsCfg = tlsCfg
		return nil
	}
}

// WithLoadPidFunc set a types.LoadPeerIdFromTlsCertFunc for loading peer.ID from x509 certs when tls handshaking.
func WithLoadPidFunc(f types.LoadPeerIdFromTlsCertFunc) Option {
	return func(n *tcpNetwork) error {
		n.loadPidFunc = f
		return nil
	}
}

// WithLocalPeerId will set the local peer.ID for the network.
// If LoadPidFunc option set, the local peer.ID set by this method will be overwritten probably.
func WithLocalPeerId(pid peer.ID) Option {
	return func(n *tcpNetwork) error {
		n.lPID = pid
		return nil
	}
}

// WithEnableTls set a bool value deciding whether tls enabled.
func WithEnableTls(enable bool) Option {
	return func(n *tcpNetwork) error {
		n.enableTls = enable
		return nil
	}
}

// WithGMTlsServerCfg set a gmtls.Config option value for gmtls server.
// If enable tls or use gmtls is false, gmtls.Config will not usable.
func WithGMTlsServerCfg(gmTlsCfg *gmtls.Config) Option {
	return func(n *tcpNetwork) error {
		n.gmTlsServerCfg = gmTlsCfg
		return nil
	}
}

// WithGMTlsClientCfg set a gmtls.Config option value for gmtls client.
// If enable tls or use gmtls is false, gmtls.Config will not usable.
func WithGMTlsClientCfg(gmTlsCfg *gmtls.Config) Option {
	return func(n *tcpNetwork) error {
		n.gmTlsClientCfg = gmTlsCfg
		return nil
	}
}

// WithLoadPidFuncGm set a types.LoadPeerIdFromGMTlsCertFunc for loading peer.ID from gmx509 certs when gmtls handshaking.
func WithLoadPidFuncGm(f types.LoadPeerIdFromGMTlsCertFunc) Option {
	return func(n *tcpNetwork) error {
		n.loadPidFuncGm = f
		return nil
	}
}

// WithGMTls set a bool value deciding whether gm tls used.
// If enable is true, enableTLS option also will be set true.
func WithGMTls(enable bool) Option {
	return func(n *tcpNetwork) error {
		if n.enableTls {
			n.useGMTls = enable
		}
		return nil
	}
}

// NewNetwork create a new network instance with TCP transport.
func NewNetwork(ctx context.Context, logger api.Logger, opt ...Option) (*tcpNetwork, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	n := &tcpNetwork{
		mu:   sync.RWMutex{},
		once: sync.Once{},
		ctx:  ctx,

		tlsCfg:         nil,
		loadPidFunc:    nil,
		enableTls:      true,
		gmTlsServerCfg: nil,
		gmTlsClientCfg: nil,
		loadPidFuncGm:  nil,
		useGMTls:       false,
		lAddrList:      make([]ma.Multiaddr, 0, 10),
		tcpListeners:   make([]net.Listener, 0, 10),

		closeChan: make(chan struct{}),
		lPID:      "",

		logger: logger,
	}
	if err := n.apply(opt...); err != nil {
		return nil, err
	}

	if err := n.checkTlsCfg(); err != nil {
		return nil, err
	}

	if n.lPID == "" {
		return nil, ErrLocalPidNotSet
		/*if !n.enableTls {
			return nil, ErrLocalPidNotSet
		}
		if n.useGMTls {
			if n.loadPidFuncGm == nil {
				return nil, ErrNilLoadPidFunc
			}
			//resolve local PID from GMTlsCfg.Certificates
			cert, err := gmx509.ParseCertificate(n.gmTlsServerCfg.Certificates[1].Certificate[0])
			if err != nil {
				return nil, err
			}
			n.lPID, err = n.loadPidFuncGm([]*gmx509.Certificate{cert})
			if err != nil {
				return nil, err
			}
		} else {
			if n.loadPidFunc == nil {
				return nil, ErrNilLoadPidFunc
			}
			//resolve local PID from TlsCfg.Certificates
			cert, err := x509.ParseCertificate(n.tlsCfg.Certificates[0].Certificate[0])
			if err != nil {
				return nil, err
			}
			n.lPID, err = n.loadPidFunc([]*x509.Certificate{cert})
			if err != nil {
				return nil, err
			}
		}

		if n.lPID == "" {
			return nil, ErrEmptyLocalPeerId
		}*/
	}

	return n, nil
}

func (t *tcpNetwork) checkTlsCfg() error {
	if !t.enableTls {
		return nil
	}
	if t.useGMTls {
		if t.gmTlsServerCfg == nil {
			return ErrNilGMTlsServerCfg
		}
		if t.gmTlsClientCfg == nil {
			return ErrNilGMTlsClientCfg
		}
		if t.gmTlsServerCfg.Certificates == nil || len(t.gmTlsServerCfg.Certificates) < 2 {
			return ErrGMTlsCertsForServerLack
		}
		if t.gmTlsClientCfg.Certificates == nil || len(t.gmTlsClientCfg.Certificates) < 1 {
			return ErrEmptyGMTlsClientCerts
		}
		t.gmTlsServerCfg.NextProtos = []string{"liquid-network-tcp-" + TCPNetworkVersion}
		t.gmTlsServerCfg.Renegotiation = gmtls.RenegotiateFreelyAsClient
		t.gmTlsClientCfg.NextProtos = []string{"liquid-network-tcp-" + TCPNetworkVersion}
		t.gmTlsClientCfg.Renegotiation = gmtls.RenegotiateFreelyAsClient
		return nil
	}
	if t.tlsCfg == nil {
		return ErrNilTlsCfg
	}
	if t.tlsCfg.Certificates == nil || len(t.tlsCfg.Certificates) == 0 {
		return ErrEmptyTlsCerts
	}
	t.tlsCfg.NextProtos = []string{"liquid-network-tcp-" + TCPNetworkVersion}
	return nil
}

func (t *tcpNetwork) canDial(addr ma.Multiaddr) bool {
	return dialMatcherNoP2p.Matches(addr) || dialMatcherWithP2p.Matches(addr)
}

func (t *tcpNetwork) dial(ctx context.Context, remoteAddr ma.Multiaddr) (*conn, []error) {
	errs := make([]error, 0)
	nAddr, err := manet.ToNetAddr(remoteAddr)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}
	if ctx == nil {
		ctx = t.ctx
	}
	var tc *conn
	// try to dial to remote with each local address
	for i := range t.lAddrList {
		lAddr := t.lAddrList[i]
		lnAddr, err2 := manet.ToNetAddr(lAddr)
		if err2 != nil {
			errs = append(errs, err2)
			continue
		}
		// dial
		dialer := &net.Dialer{
			LocalAddr: lnAddr,
			Control:   control,
		}
		c, err3 := dialer.DialContext(ctx, nAddr.Network(), nAddr.String())
		if err3 != nil {
			errs = append(errs, err3)
			continue
		}
		// create a new conn with net.Conn
		tc, err = newConn(ctx, t, c, network.Outbound)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		break
	}
	if tc == nil {
		// all failed, try dial
		dialer := &net.Dialer{
			Control: control,
		}
		c, err3 := dialer.DialContext(ctx, nAddr.Network(), nAddr.String())
		if err3 != nil {
			errs = append(errs, err3)
			return nil, errs
		}
		// create a new conn with net.Conn
		tc, err = newConn(ctx, t, c, network.Outbound)
		if err != nil {
			errs = append(errs, err)
			return nil, errs
		}
		// TODO: temp listener
	}
	if tc != nil {
		errs = nil
	}
	return tc, errs
}

// Dial try to establish a outbound connection with the remote address.
func (t *tcpNetwork) Dial(ctx context.Context, remoteAddr ma.Multiaddr) (network.Conn, error) {
	// check network listen state
	if !t.listening {
		return nil, ErrListenerRequired
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	var remotePID peer.ID
	// check dial address
	if !t.canDial(remoteAddr) {
		return nil, ErrWrongTcpAddr
	}
	remoteAddr, remotePID = util.GetNetAddrAndPidFromNormalMultiAddr(remoteAddr)
	if remoteAddr == nil && remotePID == "" {
		return nil, errors.New("wrong addr")
	}
	if remoteAddr == nil {
		return nil, ErrWrongTcpAddr
	}

	// try to dial
	tc, errs := t.dial(ctx, remoteAddr)
	if tc == nil {
		err := fmt.Errorf("all dial failed, errors found below:%s", util.ParseErrsToStr(errs))
		return nil, err
	}
	if remotePID != "" && tc.rPID != remotePID {
		_ = tc.Close()
		return nil, ErrPidMismatch
	}
	// call conn handler
	accept := t.callConnHandler(tc)
	if !accept {
		return nil, ErrConnRejectedByConnHandler
	}
	return tc, nil
}

// Close the network.
func (t *tcpNetwork) Close() error {
	close(t.closeChan)
	//stop listening
	t.mu.Lock()
	defer t.mu.Unlock()
	t.listening = false
	for _, listener := range t.tcpListeners {
		_ = listener.Close()
	}
	return nil
}

// CanListen return whether address can be listened on.
func CanListen(addr ma.Multiaddr) bool {
	return listenMatcher.Matches(addr)
}

func (t *tcpNetwork) printListeningAddress(pid peer.ID, addr ma.Multiaddr) error {
	// join net multiaddr with p2p protocol
	// like "/ip4/127.0.0.1/udp/8081/quic" + "/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
	// -> "/ip4/127.0.0.1/udp/8081/quic/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
	mAddr := util.CreateMultiAddrWithPidAndNetAddr(pid, addr)
	t.logger.Infof("[Network] listening on address : %s", mAddr.String())
	return nil
}

func (t *tcpNetwork) reGetListenAddresses(addr ma.Multiaddr) ([]ma.Multiaddr, error) {
	tcpAddr, err := manet.ToNetAddr(addr)
	if err != nil {
		return nil, err
	}
	if tcpAddr.(*net.TCPAddr).IP.IsUnspecified() {
		// if unspecified
		// whether a ipv6 address
		isIp6 := strings.Contains(tcpAddr.(*net.TCPAddr).IP.String(), ":")
		// get local addresses usable
		addrList, e := util.GetLocalAddrs()
		if e != nil {
			return nil, e
		}
		if len(addrList) == 0 {
			return nil, errors.New("no usable local address found")
		}
		// split TCP protocol , like "/tcp/8081"
		_, lastAddr := ma.SplitFunc(addr, func(component ma.Component) bool {
			return component.Protocol().Code == ma.P_TCP
		})
		res := make([]ma.Multiaddr, 0, len(addrList))
		for _, address := range addrList {
			firstAddr, e2 := manet.FromNetAddr(address)
			if e2 != nil {
				return nil, e2
			}
			// join ip protocol with TCP protocol
			// like "/ip4/127.0.0.1" + "/tcp/8081" -> "/ip4/127.0.0.1/tcp/8081"
			temp := ma.Join(firstAddr, lastAddr)
			tempTcpAddr, err := manet.ToNetAddr(temp)
			if err != nil {
				return nil, err
			}
			tempIsIp6 := strings.Contains(tempTcpAddr.(*net.TCPAddr).IP.String(), ":")
			// if both are ipv6 or ipv4, append
			// otherwise continue
			if (isIp6 && !tempIsIp6) || (!isIp6 && tempIsIp6) {
				continue
			}
			if CanListen(temp) {
				res = append(res, temp)
			}
		}
		if len(res) == 0 {
			return nil, ErrNoUsableLocalAddress
		}
		return res, nil
	}
	res, e := manet.FromNetAddr(tcpAddr)
	if e != nil {
		return nil, e
	}
	return []ma.Multiaddr{res}, nil
}

func (t *tcpNetwork) listenTCPWithAddrList(ctx context.Context, addrList []ma.Multiaddr) ([]net.Listener, error) {
	if len(addrList) == 0 {
		return nil, ErrEmptyListenAddress
	}
	res := make([]net.Listener, 0, len(addrList))
	for _, mAddr := range addrList {
		// get net address
		nAddr, _ := util.GetNetAddrAndPidFromNormalMultiAddr(mAddr)
		if nAddr == nil {
			return nil, ErrNilAddr
		}
		// parse to net.Addr
		n, err := manet.ToNetAddr(nAddr)
		if err != nil {
			return nil, err
		}
		// try to listen
		var tl net.Listener
		lc := net.ListenConfig{Control: control}
		tl, err = lc.Listen(ctx, n.Network(), n.String())
		if err != nil {
			t.logger.Warnf("[Network] listen on address failed, %s (address: %s)", err.Error(), n.String())
			continue
		}
		res = append(res, tl)
		// print listen address
		err = t.printListeningAddress(t.lPID, nAddr)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (t *tcpNetwork) resetCheck() {
	select {
	case <-t.closeChan:
		t.closeChan = make(chan struct{})
		t.once = sync.Once{}
	default:

	}
}

func (t *tcpNetwork) callConnHandler(tc *conn) bool {
	var accept = true
	var err error
	if t.connHandler != nil {
		accept, err = t.connHandler(tc)
		if err != nil {
			t.logger.Errorf("[Network] call connection handler failed, %s", err.Error())
		}
	}
	if !accept {
		_ = tc.Close()
	}
	return accept
}

func (t *tcpNetwork) listenerAcceptLoop(listener net.Listener) {
Loop:
	for {
		select {
		case <-t.ctx.Done():
			break Loop
		case <-t.closeChan:
			break Loop
		default:

		}
		c, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				break Loop
			}
			t.logger.Errorf("[Network] listener accept err: %s", err.Error())
			continue
		}
		t.logger.Debugf("[Network] listener accept connection.(remote addr:%s)", c.RemoteAddr().String())
		tc, err := newConn(t.ctx, t, c, network.Inbound)
		if err != nil {
			t.logger.Errorf("[Network] create new connection failed, %s", err.Error())
			continue
		}
		t.logger.Debugf("[Network] create new connection success.(remote pid: %s)", tc.rPID)
		// call conn handler
		t.callConnHandler(tc)
	}
}

// Listen will run a task that start create listeners with the given addresses waiting
// for accepting inbound connections.
func (t *tcpNetwork) Listen(ctx context.Context, addrs ...ma.Multiaddr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resetCheck()
	var err error
	t.once.Do(func() {
		t.listening = true
		t.logger.Infof("[Network] local peer id : %s", t.lPID)
		if t.enableTls {
			t.logger.Info("[Network] TLS enabled.")
		} else {
			t.logger.Info("[Network] TLS disabled.")
		}
		for i := range addrs {
			addr := addrs[i]
			if !CanListen(addr) {
				err = ErrWrongTcpAddr
				return
			}
			if ctx == nil {
				ctx = t.ctx
			}
			listenAddrList, err2 := t.reGetListenAddresses(addr)
			if err2 != nil {
				err = err2
				return
			}
			tcpListeners, err3 := t.listenTCPWithAddrList(ctx, listenAddrList)
			if err3 != nil {
				err = err3
				return
			}

			if len(tcpListeners) == 0 {
				err = ErrListenerRequired
				return
			}

			for _, tl := range tcpListeners {
				go t.listenerAcceptLoop(tl)

				lAddr, err4 := manet.FromNetAddr(tl.Addr())
				if err4 != nil {
					err = err4
					return
				}
				t.lAddrList = append(t.lAddrList, lAddr)
				t.tcpListeners = append(t.tcpListeners, tl)
			}
		}
	})
	return err
}

// ListenAddresses return the list of the local addresses for listeners.
func (t *tcpNetwork) ListenAddresses() []ma.Multiaddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	res := make([]ma.Multiaddr, len(t.lAddrList))
	copy(res, t.lAddrList)
	return res
}

// SetNewConnHandler register a ConnHandler to handle the connection established.
func (t *tcpNetwork) SetNewConnHandler(handler network.ConnHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connHandler = handler
}

// Disconnect a connection.
func (t *tcpNetwork) Disconnect(conn network.Conn) error {
	if t != conn.Network().(*tcpNetwork) {
		return ErrNotTheSameNetwork
	}
	err := conn.Close()
	if err != nil {
		return err
	}
	return nil
}

// Closed return whether network closed.
func (t *tcpNetwork) Closed() bool {
	if t.closeChan == nil {
		return false
	}
	select {
	case <-t.closeChan:
		return true
	default:
		return false
	}
}

// LocalPeerID return the local peer id.
func (t *tcpNetwork) LocalPeerID() peer.ID {
	return t.lPID
}
