/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"chainmaker.org/chainmaker/chainmaker-net-common/utils"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/blacklist"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/handler"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/mgr"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/protocol"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/store"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/types"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/util"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/simple"
	api "chainmaker.org/chainmaker/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/tjfoc/gmsm/gmtls"
)

var (
	// ErrProtocolIDNotSupportedByPeer will be returned if protocol not supported by remote peer when calling SendMsg method.
	ErrProtocolIDNotSupportedByPeer = errors.New("protocol id not supported by remote peer")
	// ErrPeerNotConnected will be returned if remote peer not connect to us when calling SendMsg method.
	ErrPeerNotConnected = errors.New("peer not connected")
	// ErrConnClosed will be returned if the current connection closed when calling SendMsg method.
	ErrConnClosed = errors.New("connection closed")
	// ErrStreamPoolNotFound will be returned if the stream pool of remote peer not found when calling SendMsg method.
	ErrStreamPoolNotFound = errors.New("peer stream pool not found")
	// ErrSendMsgIncompletely will be returned if the msg sent incompletely when calling SendMsg method.
	ErrSendMsgIncompletely = errors.New("send msg incompletely")
	// ErrPeerAddrNotFoundInPeerStore will be returned if peer address not found in peer store when calling Dial method.
	ErrPeerAddrNotFoundInPeerStore = errors.New("peer address not found in peer store")
	// ErrAllDialFailed will be returned if all dialing return errors when calling Dial method.
	ErrAllDialFailed = errors.New("all dial failed")
	// ErrBlackPeer will be returned if remote peer id in blacklist when handling new peer connected.
	ErrBlackPeer = errors.New("black peer")
)

// HostConfig contains necessary parameters for BasicHost.
type HostConfig struct {
	//NetType is the net type of liquid net.
	NetType NetworkType
	// TlsCfg is the configuration for both tls server and client.
	TlsCfg *tls.Config
	// LoadPidFunc is a function which type is types.LoadPeerIdFromTlsCertFunc, used to load peer.ID from x509 certs.
	LoadPidFunc types.LoadPeerIdFromTlsCertFunc
	// QTlsCfg is the configuration for both quic tls server and client.
	QTlsCfg *tls.Config
	// LoadPidFunc is a function which type is types.LoadPeerIdFromQTlsCertFunc, used to load peer.ID from quic x509 certs.
	LoadPidFuncQ types.LoadPeerIdFromQTlsCertFunc
	// GMTlsServerCfg is the configuration for gm tls server.
	GMTlsServerCfg *gmtls.Config
	// GMTlsClientCfg is the configuration for gm tls client.
	GMTlsClientCfg *gmtls.Config
	// LoadPidFuncGm is a function which type is types.LoadPeerIdFromGMTlsCertFunc, used to load peer.ID from gmx509 certs.
	LoadPidFuncGm types.LoadPeerIdFromGMTlsCertFunc
	// UseGMTls decides whether to use gm tls security.
	UseGMTls bool
	// SendStreamPoolInitSize is the size of send streams will be created when a send stream pool initialing.
	SendStreamPoolInitSize int32
	// SendStreamPoolCap is the max size of the send stream pool of each conn.
	SendStreamPoolCap int32
	// PeerReceiveStreamMaxCount is the max limit count of receive streams for each peer.
	PeerReceiveStreamMaxCount int32
	// MaxPeerCountAllowed is the max count of peers allowed to connect to us.
	MaxPeerCountAllowed int
	// MaxConnCountEachPeerAllowed is the max count of connections for each peer allowed.
	MaxConnCountEachPeerAllowed int
	// ConnEliminationStrategy is the strategy for connection manager eliminating connections.
	ConnEliminationStrategy int
	// ListenAddresses is the local addresses for listeners listening.
	ListenAddresses []ma.Multiaddr
	// DirectPeers stores the peer.ID and it's remote address of peers need keeping connected.
	// ConnSupervisor will check the connection stat of these peers.
	// If any one disconnected to us, supervisor will try to dial to it auto.
	DirectPeers map[peer.ID]ma.Multiaddr
	// BlackNetAddr is the list of net addresses that will be appended into blacklist.
	// e.g. "127.0.0.1","127.0.0.1:8080","[::1]","[::1]:8080"
	BlackNetAddr []string
	// BlackPeers is the list of peer.ID that will be appended into blacklist.
	BlackPeers []peer.ID
	// MsgCompress decides whether net message payload compress enable.
	MsgCompress bool
	// Insecurity decides whether insecurity enable.
	// It is invalid in some implementations of network.
	Insecurity bool
}

func (c *HostConfig) AddDirectPeer(addr string) error {
	mA, err := ma.NewMultiaddr(addr)
	if err != nil {
		return err
	}
	netMA, pid := util.GetNetAddrAndPidFromNormalMultiAddr(mA)
	if c.DirectPeers == nil {
		c.DirectPeers = make(map[peer.ID]ma.Multiaddr)
	}
	c.DirectPeers[pid] = netMA
	return nil
}

func (c *HostConfig) AddBlackPeers(pidStr ...string) error {
	if c.BlackPeers == nil {
		c.BlackPeers = make([]peer.ID, 0, 10)
	}
	for _, s := range pidStr {
		c.BlackPeers = append(c.BlackPeers, peer.ID(s))
	}
	return nil
}

// NewHost create a BasicHost instance.
// Supported network type : QuicNetwork, TcpNetwork
func (c *HostConfig) NewHost(networkType NetworkType, ctx context.Context, logger api.Logger) (*BasicHost, error) {
	h := &BasicHost{
		cfg:                    c,
		ctx:                    ctx,
		peerConnExclusiveMap:   sync.Map{},
		notifiee:               sync.Map{},
		pushProtocolSignalChan: make(chan struct{}, 2),
		notifyPeerConnChan:     make(chan network.Conn),
		logger:                 logger,
	}
	// create a new network instance
	options := make([]Option, 0)
	options = append(options, WithCtx(ctx), WithEnableTls(!c.Insecurity))
	if !c.Insecurity {
		if networkType == QuicNetwork {
			options = append(options,
				WithGMTls(false),
				WithQTlsCfg(c.QTlsCfg.Clone()),
				WithLoadPidFuncQ(c.LoadPidFuncQ))
		} else if c.UseGMTls {
			options = append(options,
				WithGMTls(true),
				WithGMTlcServerCfg(c.GMTlsServerCfg),
				WithGMTlcClientCfg(c.GMTlsClientCfg),
				WithLoadPidFuncGm(c.LoadPidFuncGm))
		} else {
			options = append(options,
				WithGMTls(false),
				WithTlcCfg(c.TlsCfg.Clone()),
				WithLoadPidFunc(c.LoadPidFunc))
		}
	}
	nw, err := newNetwork(networkType, h.logger, options...)
	if err != nil {
		return nil, err
	}
	h.nw = nw
	// set up PeerStore
	h.peerStore = simple.NewSimplePeerStore(h.ID())
	// set up ConnSupervisor
	h.supervisor = simple.NewConnSupervisor(h, h.logger)
	for id, addr := range c.DirectPeers {
		h.supervisor.SetPeerAddr(id, addr)
	}

	h.notifiee = sync.Map{}

	// set up ConnMgr
	h.connMgr = simple.NewLevelConnManager(h.logger, h)
	h.connMgr.(*simple.LevelConnManager).SetMaxPeerCountAllowed(h.cfg.MaxPeerCountAllowed)
	h.connMgr.(*simple.LevelConnManager).SetMaxConnCountEachPeerAllowed(h.cfg.MaxConnCountEachPeerAllowed)
	h.connMgr.(*simple.LevelConnManager).SetStrategy(simple.EliminationStrategyFromInt(h.cfg.ConnEliminationStrategy))
	// set up SendStreamPoolMgr
	h.peerSendStreamPoolMgr = simple.NewSendStreamPoolManager(h.connMgr, h.logger)
	// set up ProtocolMgr
	h.protocolMgr = simple.NewSimpleProtocolMgr(h.ID(), h.peerStore)
	h.protocolMgr.SetProtocolSupportedNotifyFunc(h.notifyProtocolSupportedHandlers)
	h.protocolMgr.SetProtocolUnsupportedNotifyFunc(h.notifyProtocolUnsupportedHandlers)
	// set up ProtocolExchanger
	h.protocolExchanger = simple.NewSimpleProtocolExchanger(h, h.protocolMgr, h.logger)
	if err = h.RegisterMsgPayloadHandler(h.protocolExchanger.ProtocolID(), h.protocolExchanger.Handle()); err != nil {
		return nil, err
	}
	// set up ReceiveStreamMgr
	h.peerReceiveStreamMgr = simple.NewReceiveStreamManager(h.cfg.PeerReceiveStreamMaxCount)
	// set up Blacklist
	h.blacklist = simple.NewBlackList()
	for i := range h.cfg.BlackNetAddr {
		h.blacklist.AddIPAndPort(h.cfg.BlackNetAddr[i])
	}
	for i := range h.cfg.BlackPeers {
		h.blacklist.AddPeer(h.cfg.BlackPeers[i])
	}
	// attach ConnHandler on network
	nw.SetNewConnHandler(h.handleNewConn)

	return h, nil
}

var _ host.Host = (*BasicHost)(nil)

// BasicHost is a implementation of host.Host interface.
// BasicHost can build a network with the same one of different implementations of network.Network.
// It provides connections management and streams management and protocol management.
// It uses a mgr.ConnSupervisor to maintain the stat of connections with necessary directed peers.
type BasicHost struct {
	cfg  *HostConfig
	once sync.Once

	ctx context.Context
	nw  network.Network

	peerStore store.PeerStore
	notifiee  sync.Map // map[host.Notifiee]struct{}

	connMgr               mgr.ConnMgr
	supervisor            mgr.ConnSupervisor
	protocolMgr           mgr.ProtocolManager
	protocolExchanger     mgr.ProtocolExchanger
	peerSendStreamPoolMgr mgr.SendStreamPoolManager
	peerReceiveStreamMgr  mgr.ReceiveStreamManager

	blacklist blacklist.BlackList

	peerConnExclusiveMap   sync.Map // map[peer.ID]network.Conn
	pushProtocolSignalChan chan struct{}
	notifyPeerConnChan     chan network.Conn
	closedChan             chan struct{}

	logger api.Logger
}

// Start to listen on local addresses and run all managers.
func (bh *BasicHost) Start() error {
	var err error
	bh.once.Do(func() {
		bh.closedChan = make(chan struct{})
		bh.runLoop()
		err = bh.nw.Listen(bh.ctx, bh.cfg.ListenAddresses...)
		if err != nil {
			return
		}
		//start connection supervisor
		err = bh.supervisor.Start()
		if err != nil {
			return
		}
		bh.logger.Infof("[Host] host started.")
	})
	return err
}

// Stop listening and close all the connections.
func (bh *BasicHost) Stop() error {
	bh.logger.Infof("[Host] host stopping...")
	defer func() {
		bh.once = sync.Once{}
	}()
	close(bh.closedChan)
	if err := bh.supervisor.Stop(); err != nil {
		return err
	}
	if err := bh.closeAllConn(); err != nil {
		return err
	}
	if err := bh.nw.Close(); err != nil {
		return err
	}
	bh.logger.Infof("[Host] host stopped.")
	return nil
}

func (bh *BasicHost) closeAllConn() error {
	return bh.connMgr.Close()
}

// RegisterMsgPayloadHandler register a handler.MsgPayloadHandler
// for handling the msg received with the protocol which id is the given protocolID .
func (bh *BasicHost) RegisterMsgPayloadHandler(protocolID protocol.ID, handler handler.MsgPayloadHandler) error {
	err := bh.protocolMgr.RegisterMsgPayloadHandler(protocolID, handler)
	if err != nil {
		return err
	}
	bh.logger.Infof("[Host] register new msg payload handler (protocol id: %s)", protocolID)
	// push new protocol supported notice to all
	bh.sendPushProtocolSignal()
	return nil
}

// UnregisterMsgPayloadHandler unregister the handler.MsgPayloadHandler
// for handling the msg received with the protocol which id is the given protocolID .
func (bh *BasicHost) UnregisterMsgPayloadHandler(protocolID protocol.ID) error {
	err := bh.protocolMgr.UnregisterMsgPayloadHandler(protocolID)
	if err != nil {
		return err
	}
	// push protocol supported notice to all
	bh.sendPushProtocolSignal()
	return nil
}

// IsPeerSupportProtocol return true if peer which id is the given pid support the given protocol.
// Otherwise return false.
func (bh *BasicHost) IsPeerSupportProtocol(pid peer.ID, protocolID protocol.ID) bool {
	return bh.protocolMgr.IsPeerSupported(pid, protocolID)
}

// PeerProtocols query peer.ID and the protocol.ID list supported by peer.
// If protocolIDs is nil ,return the list of all connected to us.
// Otherwise return the list of part of all which support the protocols that id contains in the given protocolIDs.
func (bh *BasicHost) PeerProtocols(protocolIDs []protocol.ID) ([]*host.PeerProtocols, error) {
	res := make([]*host.PeerProtocols, 0)
	pids := bh.connMgr.AllPeer()
F:
	for i := range pids {
		pid := pids[i]
		if len(protocolIDs) > 0 {
			for j := range protocolIDs {
				if !bh.protocolMgr.IsPeerSupported(pid, protocolIDs[j]) {
					continue F
				}
			}
		}
		ps := bh.protocolMgr.GetPeerSupportedProtocols(pid)
		res = append(res, &host.PeerProtocols{
			PID:       pid,
			Protocols: ps,
		})
	}
	return res, nil
}

func (bh *BasicHost) pushProtocolsSupportedToAll() {
	peers := bh.connMgr.AllPeer()
	var wg sync.WaitGroup
	wg.Add(len(peers))
	for i := range peers {
		pid := peers[i]
		go func(pid peer.ID) {
			defer wg.Done()
			err := bh.protocolExchanger.PushProtocols(pid)
			if err != nil {
				bh.logger.Warnf("[Host] push protocol supported failed. %s (remote pid: %s)", err.Error(), pid)
			}
		}(pid)
	}
	wg.Wait()
}

func (bh *BasicHost) loop() {
Loop:
	for {
		select {
		case <-bh.closedChan:
			break Loop
		case c := <-bh.notifyPeerConnChan:
			bh.notifyPeerHandlers(c.RemotePeerID(), !c.IsClosed())
		}
	}
}

func (bh *BasicHost) pushProtocolSignalLoop() {
Loop:
	for {
		select {
		case <-bh.closedChan:
			break Loop
		case <-bh.pushProtocolSignalChan:
			bh.pushProtocolsSupportedToAll()
		}
	}
}
func (bh *BasicHost) sendPushProtocolSignal() {
	select {
	case bh.pushProtocolSignalChan <- struct{}{}:
	default:

	}
}

func (bh *BasicHost) runLoop() {
	go bh.loop()
	go bh.pushProtocolSignalLoop()
}

// SendMsg will send a msg with the protocol which id is the given protocolID to
// the receiver whose peer.ID is the given receiverPID.
func (bh *BasicHost) SendMsg(protocolID protocol.ID, receiverPID peer.ID, msgPayload []byte) error {
	// whether protocol supported
	if !bh.protocolMgr.IsPeerSupported(receiverPID, protocolID) {
		return ErrProtocolIDNotSupportedByPeer
	}
	// whether receiver connected to us
	if !bh.connMgr.IsConnected(receiverPID) {
		return ErrPeerNotConnected
	}
	// get send stream pool of receiver
	streamPool := bh.peerSendStreamPoolMgr.GetPeerBestConnSendStreamPool(receiverPID)
	if streamPool == nil {
		return ErrStreamPoolNotFound
	}
	// borrow a send stream
	stream, err := streamPool.(mgr.SendStreamPool).BorrowStream()
	if err != nil {
		return err
	}
	// create net message package
	pkg := protocol.NewPackage(protocolID, msgPayload)
	pkgData, err := pkg.ToBytes(bh.cfg.MsgCompress)
	if err != nil {
		return err
	}
	// write data length to stream
	pkgDataLen := len(pkgData)
	pkgDataLenBytes := utils.Uint64ToBytes(uint64(pkgDataLen))
	n, err := stream.Write(pkgDataLenBytes)
	if err == nil {
		// write package bytes
		var n2 int
		n2, err = stream.Write(pkgData)
		n = n + n2
	}
	if err != nil {
		// err found
		// whether network has shutdown
		if bh.nw.Closed() {
			return nil
		}
		// whether connection created the stream has closed
		if bh.CheckClosedConnWithErr(stream.Conn(), err) {
			return ErrConnClosed
		}
		// drop stream
		streamPool.(mgr.SendStreamPool).DropStream(stream)
		return err
	}
	// whether write data completely
	if n < pkgDataLen+8 {
		streamPool.(mgr.SendStreamPool).DropStream(stream)
		return ErrSendMsgIncompletely
	}
	// send success, return the stream
	err = streamPool.(mgr.SendStreamPool).ReturnStream(stream)
	if err != nil {
		return err
	}
	return nil
}

func (bh *BasicHost) receiveStreamHandler(stream network.ReceiveStream) {
	rPID := stream.Conn().RemotePeerID()
	var err error = nil
Loop:
	for {
		if stream.Conn().IsClosed() {
			bh.handleClosingConn(stream.Conn())
			break Loop
		}
		dataLength, _, e := util.ReadPackageLength(stream)
		if e != nil {
			err = e
			break Loop
		}
		dataBytes, e := util.ReadPackageData(stream, dataLength)
		if e != nil {
			err = e
			break Loop
		}
		pkg := &protocol.Package{}
		e = pkg.FromBytes(dataBytes)
		if e != nil {
			err = e
			break Loop
		}
		payloadHandler := bh.protocolMgr.GetHandler(pkg.ProtocolID())
		if payloadHandler == nil {
			bh.logger.Warnf("[Host] msg payload handler not found(protocol id:%s), drop this package(remote pid:%s)",
				pkg.ProtocolID(), rPID)
			continue Loop
		}
		payloadHandler(rPID, pkg.Payload())
	}
	if err != nil {
		if bh.nw.Closed() {
			return
		}
		if bh.CheckClosedConnWithErr(stream.Conn(), err) {
			return
		}
		//drop the stream
		_ = stream.Close()
		_ = bh.peerReceiveStreamMgr.RemovePeerReceiveStream(rPID, stream.Conn(), stream)
		bh.logger.Debugf("[Host] handle stream error found, drop the stream(remote pid:%s). %s", rPID, err.Error())
	}
}

func (bh *BasicHost) handleReceiveStream(stream network.ReceiveStream) {
	rPID := stream.Conn().RemotePeerID()
	if !bh.connMgr.IsConnected(rPID) || !bh.connMgr.ExistPeerConn(rPID, stream.Conn()) {
		bh.logger.Warnf("[Host][PeerReceiveStreamMgr] receive stream mismatch accepted connection, close it.")
		_ = stream.Close()
	}
	err := bh.peerReceiveStreamMgr.AddPeerReceiveStream(rPID, stream.Conn(), stream)
	if err != nil {
		bh.logger.Errorf("[Host][PeerReceiveStreamMgr] add peer stream failed, %s", err.Error())
		_ = stream.Close()
	}
	go bh.receiveStreamHandler(stream)
}

func (bh *BasicHost) acceptReceiveStreamLoop(conn network.Conn) {
LOOP:
	for {
		select {
		case <-bh.closedChan:
		default:
			if conn.IsClosed() {
				bh.handleClosingConn(conn)
				break LOOP
			}
		}
		rs, err := conn.AcceptReceiveStream()
		if err != nil {
			switch {
			case bh.CheckClosedConnWithErr(conn, err):
				break LOOP
			case util.IsNetErrorTemporary(err):
				bh.logger.Debugf("[Network][AcceptReceiveStreamLoop] net error temporary, continue.")
				continue
			default:
				if conn.IsClosed() {
					break LOOP
				}
				bh.logger.Errorf("[Network][AcceptReceiveStreamLoop] accept receive stream failed, %s", err.Error())
				continue
			}
		}
		bh.handleReceiveStream(rs)
	}
}

func (bh *BasicHost) handleNewConn(conn network.Conn) (bool, error) {
	if bh.blacklist.IsBlack(conn) {
		return false, ErrBlackPeer
	}
	rPID := conn.RemotePeerID()
	v, loaded := bh.peerConnExclusiveMap.LoadOrStore(rPID, conn)
	if loaded {
		oldConn, _ := v.(network.Conn)
		if oldConn.Direction() != conn.Direction() {
			var whichDrop network.Direction
			saveSelf := conn.LocalPeerID().WeightCompare(conn.RemotePeerID())
			if saveSelf {
				// drop inbound
				whichDrop = network.Inbound
			} else {
				// drop outbound
				whichDrop = network.Outbound
			}
			if oldConn.Direction() == whichDrop {
				bh.peerConnExclusiveMap.Store(rPID, conn)
				_ = oldConn.Close()
			} else {
				_ = conn.Close()
				return false, nil
			}
		} else {
			_ = conn.Close()
			return false, nil
		}
	}
	defer bh.peerConnExclusiveMap.Delete(rPID)

	if !bh.connMgr.IsAllowed(rPID) {
		_ = conn.Close()
		bh.logger.Infof("[Host] connection not allowed , close it. (remote pid:%s)", rPID)
		return false, nil
	}

	var rProtocols []protocol.ID
	var err error
	exchangeProtocol := false
	if !bh.connMgr.IsConnected(rPID) {
		// if it is the first time establishing connection with us, exchange protocols supported
		// exchange protocols supported
		rProtocols, err = bh.protocolExchanger.ExchangeProtocol(conn)
		if err != nil {
			bh.logger.Errorf("[Host] exchange supported protocols failed. err:%v.(local:%v,remote:%v)",
				err, conn.LocalPeerID(), conn.RemotePeerID())
			_ = conn.Close()
			return false, nil
		}
		bh.logger.Infof("[Host] exchange protocols supported success. (local_pid:%v,remote_pid: %s, protocols:%s)",
			conn.LocalPeerID(), rPID, rProtocols)
		exchangeProtocol = true
	}

	// init send stream pool
	streamPool, err := simple.NewSimpleStreamPool(
		bh.cfg.SendStreamPoolInitSize,
		bh.cfg.SendStreamPoolCap,
		conn,
		bh,
		bh.logger)
	if err != nil {
		panic(fmt.Sprintf("new simple stream pool failed. %s", err.Error()))
	}

	bh.logger.Debugf("[Host] init send streams. (remote pid:%s)", rPID)
	err = streamPool.InitStreams()
	if err != nil {
		bh.logger.Errorf("[Host] send stream pool of connection init failed. %s", err.Error())
		_ = conn.Close()
		return false, nil
	}

	// add send stream pool to mgr
	err = bh.peerSendStreamPoolMgr.AddPeerConnSendStreamPool(rPID, conn, streamPool)
	if err != nil {
		bh.logger.Errorf("[Host] add send stream pool to mgr failed. %s", err.Error())
		_ = conn.Close()
		return false, err
	}

	// add conn to conn mgr
	if !bh.connMgr.AddPeerConn(rPID, conn) {
		_ = conn.Close()
		bh.logger.Debugf("[Host] add connection failed , close it. (remote pid:%s)", rPID)
		return false, nil
	}

	if exchangeProtocol {
		// set peer supported protocols
		bh.protocolMgr.SetPeerSupportedProtocols(rPID, rProtocols)
	}

	// start accept receive stream loop
	go bh.acceptReceiveStreamLoop(conn)

	// add peer addr
	bh.peerStore.AddAddr(rPID, conn.RemoteAddr())

	bh.logger.Infof("[Host] new connection established(remote pid: %s, addr: %s, direction:%d)",
		rPID, conn.RemoteAddr().String(), conn.Direction())
	if exchangeProtocol {
		bh.logger.Infof("[Host] peer connected(remote pid: %s, addr: %s)",
			rPID, conn.RemoteAddr().String())
		bh.notifyPeerConnChan <- conn
	}

	return true, nil
}

func (bh *BasicHost) handleClosingConn(conn network.Conn) {
	// close connection
	_ = conn.Close()
	rPID := conn.RemotePeerID()
	// remove conn from ConnMgr
	if !bh.connMgr.RemovePeerConn(rPID, conn) {
		return
	}
	bh.logger.Infof("[Host] a connection disestablished(remote pid: %s, addr: %s, direction:%d)",
		rPID, conn.RemoteAddr().String(), conn.Direction())
	if !bh.connMgr.IsConnected(rPID) {
		bh.logger.Infof("[Host] peer disconnected(remote pid: %s, addr: %s)",
			rPID, conn.RemoteAddr().String())
		// notify disconnected
		bh.notifyPeerConnChan <- conn
		// clean protocols records of remote peer
		bh.protocolMgr.CleanPeerSupportedProtocols(rPID)
	}

	// remove remote address of this connection
	bh.peerStore.RemoveAddr(rPID, conn.RemoteAddr())
	// clean all send streams of this connection
	err := bh.peerSendStreamPoolMgr.RemovePeerConnAndCloseSendStreamPool(rPID, conn)
	if err != nil {
		bh.logger.Errorf("[host] remove peer connection and close send stream pool failed, %s (remote pid: %s)", err.Error(), rPID)
	}
	// clean all receive streams of this connection
	_ = bh.peerReceiveStreamMgr.ClosePeerReceiveStreams(rPID, conn)
}

// CheckClosedConnWithErr return whether the connection has closed.
// If conn.IsClosed() is true, return true.
// If err contains closed info, return true.
// Otherwise return false.
func (bh *BasicHost) CheckClosedConnWithErr(conn network.Conn, err error) bool {
	res := false
	switch {
	case util.IsNetErrorTimeout(err):
		//bh.logger.Debugf("[Host] net error timeout, drop the connection.")
		res = true
	case util.IsConnClosedError(err):
		//bh.logger.Debugf("[Host] connection closed, drop it.")
		res = true
	case conn.IsClosed():
		res = true
	default:

	}
	if res {
		// call closing conn handler
		bh.handleClosingConn(conn)
		return res
	}
	return res
}

// Context of the host instance.
func (bh *BasicHost) Context() context.Context {
	return bh.ctx
}

// ID is local peer id.
func (bh *BasicHost) ID() peer.ID {
	return bh.nw.LocalPeerID()
}

// Dial try to establish a connection with peer whose address is the given.
func (bh *BasicHost) Dial(remoteAddr ma.Multiaddr) (network.Conn, error) {
	// resolve remote net address and remote peer.ID
	rAddr, remotePID := util.GetNetAddrAndPidFromNormalMultiAddr(remoteAddr)
	if rAddr == nil && remotePID == "" {
		return nil, errors.New("wrong addr")
	}
	if rAddr == nil {
		// if remote net address is nil, try to query any from PeerStore.
		remoteAddresses := bh.peerStore.GetAddrs(remotePID)
		if len(remoteAddresses) == 0 {
			// no address queried, return err
			return nil, ErrPeerAddrNotFoundInPeerStore
		}
		// try to dial to each addresses found
		for i := range remoteAddresses {
			addr := remoteAddresses[i]
			bh.logger.Infof("[Host][Dial] try to connect to peer(remote pid: %s, addr: %s)",
				remotePID, addr.String())
			conn, err := bh.nw.Dial(context.Background(), addr)
			if err != nil {
				bh.logger.Warnf("[Host][Dial] connect to peer failed, %s (remote pid: %s, addr: %s)",
					err.Error(), remotePID, addr.String())
				continue
			}
			// if dial success, return
			return conn, nil
		}
		bh.logger.Errorf("[Host][Dial] all dial failed(remote pid: %s)", remotePID)
		return nil, ErrAllDialFailed
	}
	// dial to remote
	bh.logger.Infof("[Host][Dial] try to connect to peer(remote pid: %s, addr: %s)",
		remotePID, rAddr.String())
	conn, err := bh.nw.Dial(context.Background(), rAddr)
	if err != nil {
		bh.logger.Warnf("[Host][Dial] connect to peer failed, %s (remote pid: %s, addr: %s)",
			err.Error(), remotePID, rAddr.String())
		return nil, ErrAllDialFailed
	}
	return conn, nil
}

// PeerStore return the store.PeerStore instance of the host.
func (bh *BasicHost) PeerStore() store.PeerStore {
	return bh.peerStore
}

// ConnMgr return the mgr.ConnMgr instance of the host.
func (bh *BasicHost) ConnMgr() mgr.ConnMgr {
	return bh.connMgr
}

// ProtocolMgr return the mgr.ProtocolManager instance of the host.
func (bh *BasicHost) ProtocolMgr() mgr.ProtocolManager {
	return bh.protocolMgr
}

// Blacklist return the blacklist.BlackList instance of the host.
func (bh *BasicHost) Blacklist() blacklist.BlackList {
	return bh.blacklist
}

// Notify registers a Notifiee to host.
func (bh *BasicHost) Notify(notifiee host.Notifiee) {
	bh.notifiee.LoadOrStore(notifiee, struct{}{})
}

// AddDirectPeer append a directed peer.
func (bh *BasicHost) AddDirectPeer(mA ma.Multiaddr) {
	_, peerId := util.GetNetAddrAndPidFromNormalMultiAddr(mA)
	if bh.cfg.DirectPeers == nil {
		bh.cfg.DirectPeers = make(map[peer.ID]ma.Multiaddr)
	}
	bh.cfg.DirectPeers[peerId] = mA
	bh.supervisor.SetPeerAddr(peerId, mA)
}

// ClearDirectPeers remove all directed peers.
func (bh *BasicHost) ClearDirectPeers() {
	bh.cfg.DirectPeers = make(map[peer.ID]ma.Multiaddr)
	bh.supervisor.RemoveAllPeer()
}

// LocalAddresses return the list of net addresses for listener listening.
func (bh *BasicHost) LocalAddresses() []ma.Multiaddr {
	return bh.nw.ListenAddresses()
}

// notifyPeerHandlers called when peer connected or disconnected
func (bh *BasicHost) notifyPeerHandlers(pid peer.ID, isConnected bool) {
	// call all notifees
	bh.notifiee.Range(func(key, _ interface{}) bool {
		notifiee, _ := key.(host.Notifiee)
		if isConnected {
			notifiee.PeerConnected(pid)
		} else {
			notifiee.PeerDisconnected(pid)
		}
		return true
	})
}

// notifyProtocolHandlers called when peer supporting a new protocol or canceling support a protocol
func (bh *BasicHost) notifyProtocolHandlers(pid peer.ID, protocolID protocol.ID, isNew bool) {
	bh.notifiee.Range(func(key, _ interface{}) bool {
		notifiee, _ := key.(host.Notifiee)
		if isNew {
			notifiee.PeerProtocolSupported(protocolID, pid)
		} else {
			notifiee.PeerProtocolUnsupported(protocolID, pid)
		}
		return true
	})
}

// notifyProtocolSupportedHandlers called when peer supporting a new protocol
func (bh *BasicHost) notifyProtocolSupportedHandlers(protocolID protocol.ID, pid peer.ID) {
	bh.notifyProtocolHandlers(pid, protocolID, true)
}

// notifyProtocolUnsupportedHandlers called when peer canceling support a protocol
func (bh *BasicHost) notifyProtocolUnsupportedHandlers(protocolID protocol.ID, pid peer.ID) {
	bh.notifyProtocolHandlers(pid, protocolID, false)
}
