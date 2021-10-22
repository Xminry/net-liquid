/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	cmTls "chainmaker.org/chainmaker/common/v2/crypto/tls"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
	"chainmaker.org/chainmaker/net-liquid/core/util"
	api "chainmaker.org/chainmaker/protocol/v2"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/xiaotianfork/quic-go"
)

const (
	// QuicNetworkVersion is the current version of quic network .
	QuicNetworkVersion = "v0.0.1"
)

var (
	// ErrNilTlsCfg will be returned if tls config is nil when network starting.
	ErrNilTlsCfg = errors.New("nil tls config")
	// ErrEmptyTlsCerts will be returned if no tls cert given when network starting with tls enabled.
	ErrEmptyTlsCerts = errors.New("empty tls certs")
	// ErrNilAddr will be returned if the listening address is empty.
	ErrNilAddr = errors.New("nil addr")
	// ErrListenerRequired will be returned if no listening address given.
	ErrListenerRequired = errors.New("at least one listener is required")
	// ErrConnRejectedByConnHandler will be returned if connection handler reject a connection when establishing.
	ErrConnRejectedByConnHandler = errors.New("connection rejected by conn handler")
	// ErrNotTheSameNetwork will be returned if the connection disconnected is not created by current network.
	ErrNotTheSameNetwork = errors.New("not the same network")
	// ErrPidMismatch will be returned if the remote peer id is not the expected one.
	ErrPidMismatch = errors.New("pid mismatch")
	// ErrNilLoadPidFunc will be returned if loadPidFunc is nil.
	ErrNilLoadPidFunc = errors.New("load peer id function required")
	// ErrWrongQuicAddr will be returned if the address is wrong when calling Dial method.
	ErrWrongQuicAddr = errors.New("wrong quic address format")
	// ErrEmptyLocalPeerId will be returned if load local peer id failed.
	ErrEmptyLocalPeerId = errors.New("empty local peer id")
	// ErrNoUsableLocalAddress will be returned if no usable local address found
	// when the local listening address is an unspecified address.
	ErrNoUsableLocalAddress = errors.New("no usable local address found")

	listenMatcher      = mafmt.And(mafmt.IP, mafmt.Base(ma.P_UDP), mafmt.Base(ma.P_QUIC))
	dialMatcherNoP2p   = mafmt.QUIC
	dialMatcherWithP2p = mafmt.And(mafmt.QUIC, mafmt.Base(ma.P_P2P))
	quicMa             = ma.StringCast("/quic")
)

// Option is a function to set option value for quic network.
type Option func(n *qNetwork) error

var _ network.Network = (*qNetwork)(nil)

// qNetwork is an implementation of network.Network interface.
// It uses quic-go as transport layer.
type qNetwork struct {
	mu   sync.RWMutex
	once sync.Once
	ctx  context.Context

	qCfg        *quic.Config
	cmTlsCfg    *cmTls.Config
	loadPidFunc types.LoadPeerIdFromCMTlsCertFunc
	tlsCfg      *tls.Config
	connHandler network.ConnHandler

	lPID       peer.ID
	laddrs     []ma.Multiaddr
	pktConns   []net.PacketConn
	qListeners []quic.Listener
	listening  bool

	closeChan chan struct{}

	logger api.Logger
}

func (q *qNetwork) apply(opt ...Option) error {
	for _, o := range opt {
		if err := o(q); err != nil {
			return err
		}
	}
	return nil
}

// WithTlsCfg set a tls.Config option value.
func WithTlsCfg(tlsCfg *cmTls.Config) Option {
	return func(n *qNetwork) error {
		n.cmTlsCfg = tlsCfg
		// wrap tls config
		var cipherSuite []uint16
		useSm := IsGMPrivateKey(tlsCfg.Certificates[0].PrivateKey)
		if useSm {
			cipherSuite = []uint16{0x00c6}
		} else {
			cipherSuite = []uint16{0x1301, 0x1302, 0x1303}
		}
		certs, e2 := ParseCMTLSCertsToGoTLSCerts(tlsCfg.Certificates)
		if e2 != nil {
			return e2
		}
		verifyFunc := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return n.cmTlsCfg.VerifyPeerCertificate(rawCerts, nil)
		}
		n.tlsCfg = &tls.Config{
			Certificates:          certs,
			InsecureSkipVerify:    true,
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: verifyFunc,
			MaxVersion:            tls.VersionTLS13,
			CipherSuites:          cipherSuite,
		}
		return nil
	}
}

// WithLoadPidFunc set a types.LoadPeerIdFromTlsCertFunc for loading peer.ID from x509 certs when tls handshaking.
func WithLoadPidFunc(f types.LoadPeerIdFromCMTlsCertFunc) Option {
	return func(n *qNetwork) error {
		n.loadPidFunc = f
		return nil
	}
}

// WithLocalPeerId will set the local peer.ID for the network.
// If LoadPidFunc option set, the local peer.ID set by this method will be overwritten, probably.
func WithLocalPeerId(pid peer.ID) Option {
	return func(n *qNetwork) error {
		n.lPID = pid
		return nil
	}
}

// NewNetwork create a new network instance with QUIC transport.
func NewNetwork(ctx context.Context, logger api.Logger, opt ...Option) (network.Network, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// create qNetwork
	n := &qNetwork{
		mu:   sync.RWMutex{},
		once: sync.Once{},
		ctx:  ctx,

		tlsCfg:      nil,
		loadPidFunc: nil,
		laddrs:      make([]ma.Multiaddr, 0, 10),
		pktConns:    make([]net.PacketConn, 0, 10),
		qListeners:  make([]quic.Listener, 0, 10),

		closeChan: make(chan struct{}),
		lPID:      "",

		logger: logger,
	}

	if err := n.apply(opt...); err != nil {
		return nil, err
	}

	// init configuration fo quic
	n.initQuicCfg()
	// check tls config
	if err := n.checkTlsCfg(); err != nil {
		return nil, err
	}
	if n.lPID == "" {
		return nil, ErrEmptyLocalPeerId
		/*if n.loadPidFunc == nil {
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
		if n.lPID == "" {
			return nil, ErrEmptyLocalPeerId
		}*/
	}
	return n, nil
}

// Close the network.
// Stop listening and close all connection established.
func (q *qNetwork) Close() error {
	close(q.closeChan)
	//stop listening
	q.mu.Lock()
	defer q.mu.Unlock()
	q.listening = false
	for _, listener := range q.qListeners {
		_ = listener.Close()
	}
	for _, conn := range q.pktConns {
		_ = conn.Close()
	}
	return nil
}

// Closed return whether the network has been closed.
func (q *qNetwork) Closed() bool {
	if q.closeChan == nil {
		return false
	}
	select {
	case <-q.closeChan:
		return true
	default:
		return false
	}
}

// LocalPeerID is the local peer.ID of network.
func (q *qNetwork) LocalPeerID() peer.ID {
	return q.lPID
}

// SetNewConnHandler register a ConnHandler to handle the connection established.
func (q *qNetwork) SetNewConnHandler(handler network.ConnHandler) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.connHandler = handler
}

// callConnHandler will call connection handler.
// If call success and accepted by handler, return true.
func (q *qNetwork) callConnHandler(qc *qConn) bool {
	var accept = true
	var err error
	if q.connHandler != nil {
		accept, err = q.connHandler(qc)
		if err != nil {
			q.logger.Errorf("[Network] call connection handler failed, %s", err.Error())
		}
	}
	if !accept {
		_ = qc.Close()
	}
	return accept
}

// listenerAcceptLoop is a loop task for a listener to wait for accepting a quic session.
func (q *qNetwork) listenerAcceptLoop(listener quic.Listener) {
Loop:
	for {
		select {
		case <-q.ctx.Done():
			break Loop
		case <-q.closeChan:
			break Loop
		default:

		}
		// wait for accepting
		sess, err := listener.Accept(q.ctx)
		if err != nil {
			if err.Error() == "server closed" {
				// server closed , break
				break Loop
			}
			q.logger.Errorf("[Network] listener accept err: %s", err.Error())
			continue
		}
		q.logger.Debugf("[Network] listener accept session.(remote addr:%s)", sess.RemoteAddr().String())
		// create a new qConn with the session
		qc, err := NewQConn(q, sess, network.Inbound, q.loadPidFunc)
		if err != nil {
			q.logger.Errorf("[Network] create new connection failed, %s", err.Error())
			continue
		}
		q.logger.Debugf("[Network] create new connection success.(remote pid: %s)", qc.rPID)
		// call conn handler
		q.callConnHandler(qc)
	}
}

// CanListen return whether address can be listened on.
func CanListen(addr ma.Multiaddr) bool {
	return listenMatcher.Matches(addr)
}

// Listen will run a task that start create listeners with the given addresses waiting for accepting inbound connections.
func (q *qNetwork) Listen(ctx context.Context, addrs ...ma.Multiaddr) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.resetCheck()
	var err error
	q.once.Do(func() {
		q.listening = true
		q.logger.Infof("[Network] local peer id : %s", q.lPID)
		for i := range addrs {
			addr := addrs[i]
			// whether can listen
			if !CanListen(addr) {
				err = ErrWrongQuicAddr
				return
			}
			usableAddrList, e := q.reGetListenAddresses(addr)
			if e != nil {
				err = e
				return
			}
			for j := range usableAddrList {
				usableAddr := usableAddrList[j]
				// create packet listener with addr
				pc, e := listenPacketWithAddr(usableAddr)
				if e != nil {
					err = e
					return
				}

				// create quic listener
				listener, e := quic.Listen(pc, q.tlsCfg.Clone(), q.qCfg.Clone())
				if e != nil {
					err = e
					return
				}
				// print local addresses listening on
				e = q.printListeningAddress(q.lPID, usableAddr)
				if e != nil {
					err = e
					return
				}
				if ctx == nil {
					ctx = q.ctx
				}
				// run an accepting loop task with listener
				go q.listenerAcceptLoop(listener)
				// save the local address and packet connection and listener
				q.laddrs = append(q.laddrs, usableAddr)
				q.pktConns = append(q.pktConns, pc)
				q.qListeners = append(q.qListeners, listener)
			}
		}
	})
	return err
}

// ListenAddresses return the list of the local addresses for listeners.
func (q *qNetwork) ListenAddresses() []ma.Multiaddr {
	q.mu.RLock()
	defer q.mu.RUnlock()
	res := make([]ma.Multiaddr, len(q.laddrs))
	copy(res, q.laddrs)
	return res
}

func (q *qNetwork) canDial(addr ma.Multiaddr) bool {
	return dialMatcherNoP2p.Matches(addr) || dialMatcherWithP2p.Matches(addr)
}

func (q *qNetwork) dial(ctx context.Context, remoteAddr ma.Multiaddr) (*qConn, []error) {
	errs := make([]error, 0)
	nAddr, err := manet.ToNetAddr(remoteAddr)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}
	if ctx == nil {
		ctx = q.ctx
	}
	var qc *qConn
	// try to dial to remote with each packet connection
	for i := range q.pktConns {
		pc := q.pktConns[i]
		// dial
		sess, dialErr := quic.DialContext(ctx, pc, nAddr, nAddr.String(), q.tlsCfg.Clone(), q.qCfg.Clone())
		if dialErr != nil {
			errs = append(errs, dialErr)
			continue
		}
		// create a new qConn with the session
		qc, err = NewQConn(q, sess, network.Outbound, q.loadPidFunc)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// break if success
		break
	}
	return qc, errs
}

// Dial try to establish an outbound connection with the remote address.
func (q *qNetwork) Dial(ctx context.Context, remoteAddr ma.Multiaddr) (network.Conn, error) {
	// check network listen state
	if !q.listening {
		return nil, ErrListenerRequired
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	// whether remote address can be dial to
	if !q.canDial(remoteAddr) {
		return nil, ErrWrongQuicAddr
	}
	// resolve remote net address and remote peer.ID
	var remotePID peer.ID
	remoteAddr, remotePID = util.GetNetAddrAndPidFromNormalMultiAddr(remoteAddr)
	if remoteAddr == nil && remotePID == "" {
		return nil, errors.New("wrong addr")
	}
	if remoteAddr == nil {
		return nil, ErrWrongQuicAddr
	}
	remoteAddr = remoteAddr.Decapsulate(quicMa)
	// try to dial
	qc, errs := q.dial(ctx, remoteAddr)
	if qc == nil {
		err := fmt.Errorf("all dial failed, errors found below:%s", util.ParseErrsToStr(errs))
		return nil, err
	}
	// whether remote peer.ID matched
	if remotePID != "" && qc.rPID != remotePID {
		_ = qc.Close()
		q.logger.Debugf("[Network][Dial] pid mismatch, expected: %s, got: %s, close the connection.", remotePID, qc.rPID)
		return nil, ErrPidMismatch
	}
	// call connection hanler
	accept := q.callConnHandler(qc)
	if !accept {
		return nil, ErrConnRejectedByConnHandler
	}
	// return
	return qc, nil
}

// Disconnect a connection.
func (q *qNetwork) Disconnect(conn network.Conn) error {
	if q != conn.Network().(*qNetwork) {
		return ErrNotTheSameNetwork
	}
	err := conn.Close()
	if err != nil {
		return err
	}
	return nil
}

// initQuicCfg prepare the configuration for quic-go.
func (q *qNetwork) initQuicCfg() {
	q.qCfg = &quic.Config{
		MaxIdleTimeout:                 2 * time.Second,
		InitialStreamReceiveWindow:     0,
		MaxStreamReceiveWindow:         40 * (1 << 20),
		InitialConnectionReceiveWindow: 0,
		MaxConnectionReceiveWindow:     50 * (1 << 20),
		MaxIncomingStreams:             50,
		MaxIncomingUniStreams:          2 ^ 60,
		KeepAlive:                      true,
	}
}

func (q *qNetwork) checkTlsCfg() error {
	if q.tlsCfg == nil {
		return ErrNilTlsCfg
	}
	if q.tlsCfg.Certificates == nil || len(q.tlsCfg.Certificates) == 0 {
		return ErrEmptyTlsCerts
	}
	q.tlsCfg.NextProtos = []string{"liquid-network-quic-" + QuicNetworkVersion}
	return nil
}

func (q *qNetwork) reGetListenAddresses(addr ma.Multiaddr) ([]ma.Multiaddr, error) {
	addr = addr.Decapsulate(quicMa)
	udpAddr, err := manet.ToNetAddr(addr)
	if err != nil {
		return nil, err
	}
	if udpAddr.(*net.UDPAddr).IP.IsUnspecified() {
		// if unspecified
		// whether a ipv6 address
		isIp6 := strings.Contains(udpAddr.(*net.UDPAddr).IP.String(), ":")
		// get local addresses usable
		addrList, e := util.GetLocalAddrs()
		if e != nil {
			return nil, e
		}
		if len(addrList) == 0 {
			return nil, errors.New("no usable local address found")
		}
		// split UDP protocol , like "/udp/8081"
		_, lastAddr := ma.SplitFunc(addr, func(component ma.Component) bool {
			return component.Protocol().Code == ma.P_UDP
		})
		res := make([]ma.Multiaddr, 0, len(addrList))
		for _, address := range addrList {
			firstAddr, e2 := manet.FromNetAddr(address)
			if e2 != nil {
				return nil, e2
			}
			// join ip protocol with UDP protocol
			// like "/ip4/127.0.0.1" + "/udp/8081" -> "/ip4/127.0.0.1/udp/8081"
			temp := ma.Join(firstAddr, lastAddr)
			tempUdpAddr, err := manet.ToNetAddr(temp)
			if err != nil {
				return nil, err
			}
			tempIsIp6 := strings.Contains(tempUdpAddr.(*net.UDPAddr).IP.String(), ":")
			// if both are ipv6 or ipv4, append
			// otherwise continue
			if (isIp6 && !tempIsIp6) || (!isIp6 && tempIsIp6) {
				continue
			}
			temp = temp.Encapsulate(quicMa)
			if CanListen(temp) {
				res = append(res, temp)
			}
		}
		if len(res) == 0 {
			return nil, ErrNoUsableLocalAddress
		}
		return res, nil
	}
	res, e := manet.FromNetAddr(udpAddr)
	if e != nil {
		return nil, e
	}
	res = res.Encapsulate(quicMa)
	return []ma.Multiaddr{res}, nil
}

// listenPacketWithAddr create a packet connection with address given.
func listenPacketWithAddr(addr ma.Multiaddr) (net.PacketConn, error) {
	if addr == nil {
		return nil, ErrNilAddr
	}
	nAddr, _ := util.GetNetAddrAndPidFromNormalMultiAddr(addr)
	if nAddr == nil {
		return nil, ErrNilAddr
	}
	nAddr = nAddr.Decapsulate(quicMa)
	n, err := manet.ToNetAddr(nAddr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenPacket(n.Network(), n.String())
	if err != nil {
		return nil, err
	}

	return pc, err
}

func (q *qNetwork) resetCheck() {
	select {
	case <-q.closeChan:
		q.closeChan = make(chan struct{})
		q.once = sync.Once{}
	default:

	}
}

func (q *qNetwork) printListeningAddress(pid peer.ID, addr ma.Multiaddr) error {
	// join net multiaddr with p2p protocol
	// like "/ip4/127.0.0.1/udp/8081/quic" + "/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
	// -> "/ip4/127.0.0.1/udp/8081/quic/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
	mAddr := util.CreateMultiAddrWithPidAndNetAddr(pid, addr)
	q.logger.Infof("[Network] listening on address : %s", mAddr.String())
	return nil
}
