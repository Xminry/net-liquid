/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"chainmaker.org/chainmaker/net-common/utils"
	"chainmaker.org/chainmaker/net-liquid/core/handler"
	"chainmaker.org/chainmaker/net-liquid/core/host"
	"chainmaker.org/chainmaker/net-liquid/core/mgr"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
	"chainmaker.org/chainmaker/net-liquid/core/store"
	"chainmaker.org/chainmaker/net-liquid/core/util"
	"chainmaker.org/chainmaker/net-liquid/simple/pb"
	api "chainmaker.org/chainmaker/protocol/v2"
	"github.com/gogo/protobuf/proto"
)

const (
	// ProtocolExchangerProtocolID is the protocol.ID for exchanger.
	ProtocolExchangerProtocolID protocol.ID = "/protocol-exchanger/v0.0.1"
)

var (
	// ErrProtocolIDRegistered will be returned if protocol id has registered
	// when calling RegisterMsgPayloadHandler method.
	ErrProtocolIDRegistered = errors.New("protocol id has registered")
	// ErrProtocolIDNotRegistered will be returned if protocol id has not been registered
	// when calling UnregisterMsgPayloadHandler method.
	ErrProtocolIDNotRegistered = errors.New("protocol id is not registered")
	// ErrPushProtocolTimeout will be returned if protocol pushing timeout.
	ErrPushProtocolTimeout = errors.New("push protocol timeout")
	// ErrProtocolOfExchangerMismatch will be returned if the protocol of exchanger mismatch.
	ErrProtocolOfExchangerMismatch = errors.New("exchanger protocol mismatch")
	exchangeTimeout                = 10 * time.Second
)

var _ mgr.ProtocolExchanger = (*protocolExchanger)(nil)

// protocolExchanger is a simple implementation of mgr.ProtocolExchanger interface.
type protocolExchanger struct {
	host          host.Host
	protocolMgr   mgr.ProtocolManager
	pushSignalMap sync.Map //map[peer.ID]*chan struct{}
	logger        api.Logger
}

// NewSimpleProtocolExchanger create a new simple mgr.ProtocolExchanger instance.
func NewSimpleProtocolExchanger(
	host host.Host,
	protocolMgr mgr.ProtocolManager,
	logger api.Logger) mgr.ProtocolExchanger {
	return &protocolExchanger{
		host:          host,
		protocolMgr:   protocolMgr,
		pushSignalMap: sync.Map{},
		logger:        logger,
	}
}

// ProtocolID is the protocol.ID of exchanger service.
// The protocol id will be registered in host.RegisterMsgPayloadHandler method.
func (p *protocolExchanger) ProtocolID() protocol.ID {
	return ProtocolExchangerProtocolID
}

func (p *protocolExchanger) createSelfProtocolsPayload(
	msgType pb.ProtocolExchangerMsg_ProtocolExchangerMsgType) ([]byte, error) {
	// get all protocols supported
	protocolIDs := p.protocolMgr.GetSelfSupportedProtocols()
	protocols := make([]string, len(protocolIDs))
	for i := range protocolIDs {
		protocols[i] = string(protocolIDs[i])
	}
	sort.Strings(protocols)
	// get local peer.ID
	lID := p.host.ID()
	// create pb.ProtocolExchangerMsg
	msg := &pb.ProtocolExchangerMsg{
		Pid:       string(lID),
		Protocols: protocols,
		MsgType:   msgType,
	}
	// marshal & return
	return proto.Marshal(msg)
}

func (p *protocolExchanger) sendSelfProtocols(
	pid peer.ID, msgType pb.ProtocolExchangerMsg_ProtocolExchangerMsgType) error {
	bytes, err := p.createSelfProtocolsPayload(msgType)
	if err != nil {
		return err
	}
	err = p.host.SendMsg(ProtocolExchangerProtocolID, pid, bytes)
	if err != nil {
		return err
	}
	return nil
}

// Handle is the msg payload handler of exchanger service.
// It will be registered in host.Host.RegisterMsgPayloadHandler method.
func (p *protocolExchanger) Handle() handler.MsgPayloadHandler {
	return func(senderPID peer.ID, msgPayload []byte) {
		// parse payload bytes to pb.ProtocolExchangerMsg
		msg := &pb.ProtocolExchangerMsg{}
		err := proto.Unmarshal(msgPayload, msg)
		if err != nil {
			p.logger.Errorf("[ProtocolExchanger] handler msg payload failed, %s (sender id: %s)",
				err.Error(), senderPID)
			return
		}
		// check sender matcher
		if string(senderPID) != msg.Pid {
			p.logger.Errorf("[ProtocolExchanger] sender id mismatch err, (sender id: %s, msg pid: %s)",
				senderPID, msg.Pid)
			return
		}
		// get protocols remote supported
		protocolIDs := make([]protocol.ID, len(msg.Protocols))
		for i := range msg.Protocols {
			protocolIDs[i] = protocol.ID(msg.Protocols[i])
		}
		p.logger.Debugf("[ProtocolExchanger] receive protocol exchanger msg. "+
			"(type: %s, remote pid:%s, supported: %v)", msg.MsgType.String(), senderPID, protocolIDs)
		switch msg.MsgType {
		case pb.ProtocolExchangerMsg_PUSH:
			// PUSH received
			// record protocols with remote peer.ID
			p.protocolMgr.SetPeerSupportedProtocols(senderPID, protocolIDs)
			// send back PUSH_OK
			e := p.sendSelfProtocols(senderPID, pb.ProtocolExchangerMsg_PUSH_OK)
			if e != nil {
				p.logger.Errorf("[ProtocolExchanger] send push ok msg failed, (sender id: %s)", senderPID)
			}
		case pb.ProtocolExchangerMsg_PUSH_OK:
			// PUSH_OK received
			// push signal
			v, ok := p.pushSignalMap.Load(senderPID)
			if ok {
				signalC, _ := v.(*chan struct{})
				*signalC <- struct{}{}
			}
			// record protocols with remote peer.ID
			p.protocolMgr.SetPeerSupportedProtocols(senderPID, protocolIDs)
		default:
			return
		}
	}
}

//func (p *protocolExchanger) ProtocolsReceivedRefreshNotify(f func(pid peer.ID, protocolIDs []protocol.ID)) {
//	p.refreshCallback = f
//}
//

func (p *protocolExchanger) sendExchangeMsg(
	sendStream network.SendStream, msgType pb.ProtocolExchangerMsg_ProtocolExchangerMsgType) error {
	payload, err := p.createSelfProtocolsPayload(msgType)
	if err != nil {
		return err
	}
	pkg := protocol.NewPackage(p.ProtocolID(), payload)
	pkgData, err := pkg.ToBytes(false)
	if err != nil {
		return err
	}
	pkgDataLen := len(pkgData)
	pkgDataLenBytes := utils.Uint64ToBytes(uint64(pkgDataLen))
	_, err = sendStream.Write(pkgDataLenBytes)
	if err == nil {
		_, err = sendStream.Write(pkgData)
	}
	if err != nil {
		return err
	}
	p.logger.Debugf("[ProtocolExchanger] send protocol exchanger msg. (type: %s, remote pid:%s)",
		msgType.String(), sendStream.Conn().RemotePeerID())
	return nil
}

func (p *protocolExchanger) receiveExchangeMsg(
	receiveStream network.ReceiveStream,
	msgType pb.ProtocolExchangerMsg_ProtocolExchangerMsgType) ([]protocol.ID, error) {
	dataLength, _, e := util.ReadPackageLength(receiveStream)
	if e != nil {
		return nil, e
	}
	dataBytes, e := util.ReadPackageData(receiveStream, dataLength)
	if e != nil {
		return nil, e
	}
	pkg := protocol.Package{}
	e = pkg.FromBytes(dataBytes)
	if e != nil {
		return nil, e
	}
	if pkg.ProtocolID() != p.ProtocolID() {
		return nil, ErrProtocolOfExchangerMismatch
	}
	resMsg := &pb.ProtocolExchangerMsg{}
	err := proto.Unmarshal(pkg.Payload(), resMsg)
	if err != nil {
		return nil, err
	}
	p.logger.Debugf("[ProtocolExchanger] receive protocol exchanger msg. (type: %s, remote pid:%s)",
		resMsg.MsgType.String(), receiveStream.Conn().RemotePeerID())
	if resMsg.MsgType != msgType {
		return nil, errors.New("msg type mismatch")
	}
	protocolIDs := make([]protocol.ID, len(resMsg.Protocols))
	for i := range resMsg.Protocols {
		protocolIDs[i] = protocol.ID(resMsg.Protocols[i])
	}
	return protocolIDs, nil
}

func (p *protocolExchanger) exchange(conn network.Conn) ([]protocol.ID, error) {
	switch conn.Direction() {
	case network.Inbound:
		var res []protocol.ID
		var err error

		stream, err := conn.CreateBidirectionalStream()
		if err != nil {
			return nil, fmt.Errorf("create stream failed,%s", err.Error())
		}
		//defer stream.Close()
		err = p.sendExchangeMsg(stream, pb.ProtocolExchangerMsg_REQUEST)
		if err != nil {
			return nil, err
		}
		res, err = p.receiveExchangeMsg(stream, pb.ProtocolExchangerMsg_RESPONSE)
		if err != nil {
			return nil, err
		}
		return res, nil
	case network.Outbound:
		var res []protocol.ID
		var err error

		stream, err := conn.AcceptBidirectionalStream()
		if err != nil {
			return nil, fmt.Errorf("accept stream failed,%s", err.Error())
		}
		//defer stream.Close()
		res, err = p.receiveExchangeMsg(stream, pb.ProtocolExchangerMsg_REQUEST)
		if err != nil {
			return nil, err
		}

		err = p.sendExchangeMsg(stream, pb.ProtocolExchangerMsg_RESPONSE)
		if err != nil {
			return nil, err
		}

		return res, nil
	default:
		return nil, errors.New("unknown connection direction")
	}
}

// ExchangeProtocol will send protocols supported by us to the other and receive protocols supported by the other.
// This method will be invoked during connection establishing.
func (p *protocolExchanger) ExchangeProtocol(conn network.Conn) ([]protocol.ID, error) {
	var err error
	var res []protocol.ID
	signalC := make(chan struct{})
	go func() {
		res, err = p.exchange(conn)
		if err != nil {
			res = nil
		}
		signalC <- struct{}{}
	}()
	timer := time.NewTimer(exchangeTimeout)
	select {
	case <-timer.C:
		return nil, errors.New("exchange timeout")
	case <-signalC:
		return res, err
	}
}

// PushProtocols will send protocols supported by us to the other.
// This method will be invoked when new protocol registering.
func (p *protocolExchanger) PushProtocols(pid peer.ID) error {
	// create a signal chan, for listening PUSH_OK back.
	signalC := make(chan struct{}, 1)
	_, loaded := p.pushSignalMap.LoadOrStore(pid, &signalC)
	if loaded {
		// pushing now , retry it until current pushing finished.
		go func() {
			time.Sleep(500 * time.Millisecond)
			err := p.PushProtocols(pid)
			if err != nil {
				p.logger.Warnf("[ProtocolExchanger][PushProtocols] push failed, (remote pid: %s)", pid)
			}
		}()
		return nil
	}
	defer p.pushSignalMap.Delete(pid)
	// send PUSH , waiting for PUSH_OK back or timeout
	timer := time.NewTimer(exchangeTimeout)
	err := p.sendSelfProtocols(pid, pb.ProtocolExchangerMsg_PUSH)
	if err != nil {
		return err
	}
	select {
	case <-signalC:
		p.logger.Infof("[ProtocolExchanger][PushProtocols] push success, (remote pid: %s)", pid)
	case <-timer.C:
		return ErrPushProtocolTimeout
	}
	return nil
}

var _ mgr.ProtocolManager = (*simpleProtocolMgr)(nil)

// simpleProtocolMgr is a simple implementation of mgr.ProtocolManager interface.
// ProtocolManager manages all protocol and protocol msg handler for all peers.
type simpleProtocolMgr struct {
	sync.Mutex
	lPID             peer.ID
	protocolHandlers sync.Map // map[protocol.ID]host.MsgPayloadHandler
	protocolBook     store.ProtocolBook
	supportedN       mgr.ProtocolSupportNotifyFunc
	unsupportedN     mgr.ProtocolSupportNotifyFunc
}

// NewSimpleProtocolMgr create a new simple mgr.ProtocolManager instance.
func NewSimpleProtocolMgr(localPID peer.ID, protocolBook store.ProtocolBook) mgr.ProtocolManager {
	return &simpleProtocolMgr{
		lPID:             localPID,
		protocolHandlers: sync.Map{},
		protocolBook:     protocolBook,
	}
}

// RegisterMsgPayloadHandler register a protocol supported by us and map a handler.MsgPayloadHandler to this protocol.
func (s *simpleProtocolMgr) RegisterMsgPayloadHandler(protocolID protocol.ID, handler handler.MsgPayloadHandler) error {
	_, loaded := s.protocolHandlers.LoadOrStore(protocolID, handler)
	if loaded {
		return ErrProtocolIDRegistered
	}
	s.protocolBook.AddProtocol(s.lPID, protocolID)
	return nil
}

// UnregisterMsgPayloadHandler unregister a protocol supported by us.
func (s *simpleProtocolMgr) UnregisterMsgPayloadHandler(protocolID protocol.ID) error {
	_, loaded := s.protocolHandlers.LoadAndDelete(protocolID)
	if !loaded {
		return ErrProtocolIDNotRegistered
	}
	s.protocolBook.DeleteProtocol(s.lPID, protocolID)
	return nil
}

// IsRegistered return whether a protocol given is supported by us.
func (s *simpleProtocolMgr) IsRegistered(protocolID protocol.ID) bool {
	_, ok := s.protocolHandlers.Load(protocolID)
	return ok
}

// GetHandler return the handler.MsgPayloadHandler mapped to the protocol supported by us and id is the given.
// If the protocol not supported by us, return nil.
func (s *simpleProtocolMgr) GetHandler(protocolID protocol.ID) handler.MsgPayloadHandler {
	h, _ := s.protocolHandlers.Load(protocolID)
	return h.(handler.MsgPayloadHandler)
}

// GetSelfSupportedProtocols return a list of protocol.ID that supported by ourself.
func (s *simpleProtocolMgr) GetSelfSupportedProtocols() []protocol.ID {
	res := make([]protocol.ID, 0)
	s.protocolHandlers.Range(func(key, _ interface{}) bool {
		protocolID, _ := key.(protocol.ID)
		res = append(res, protocolID)
		return true
	})
	return res
}

// IsPeerSupported return whether the protocol is supported by peer which id is the given pid.
// If peer not connected to us, return false.
func (s *simpleProtocolMgr) IsPeerSupported(pid peer.ID, protocolID protocol.ID) bool {
	return s.protocolBook.ContainsProtocol(pid, protocolID)
}

// GetPeerSupportedProtocols return a list of protocol.ID that supported by the peer which id is the given pid.
func (s *simpleProtocolMgr) GetPeerSupportedProtocols(pid peer.ID) []protocol.ID {
	return s.protocolBook.GetProtocols(pid)
}

func (s *simpleProtocolMgr) callNotifyIfChanged(pid peer.ID, news []protocol.ID) {
	if len(news) == 0 {
		return
	}
	// check new
	if s.supportedN != nil {
		for i := range news {
			if !s.protocolBook.ContainsProtocol(pid, news[i]) {
				go s.supportedN(news[i], pid)
			}
		}
	}

	// check drop
	if s.unsupportedN != nil {
		tempMap := make(map[protocol.ID]struct{})
		for i := range news {
			tempMap[news[i]] = struct{}{}
		}
		oldSupported := s.protocolBook.GetProtocols(pid)
		for idx := range oldSupported {
			_, notDrop := tempMap[oldSupported[idx]]
			if !notDrop {
				go s.unsupportedN(oldSupported[idx], pid)
			}
		}
	}
}

// SetPeerSupportedProtocols stores the protocols supported by the peer which id is the given pid.
func (s *simpleProtocolMgr) SetPeerSupportedProtocols(pid peer.ID, protocolIDs []protocol.ID) {
	s.callNotifyIfChanged(pid, protocolIDs)
	s.protocolBook.SetProtocols(pid, protocolIDs)
}

// CleanPeerSupportedProtocols remove all records of protocols supported by the peer which id is the given pid.
func (s *simpleProtocolMgr) CleanPeerSupportedProtocols(pid peer.ID) {
	s.protocolBook.ClearProtocol(pid)
}

// SetProtocolSupportedNotifyFunc set a function for notifying peer protocol supporting.
func (s *simpleProtocolMgr) SetProtocolSupportedNotifyFunc(notifyFunc mgr.ProtocolSupportNotifyFunc) {
	s.supportedN = notifyFunc
}

// SetProtocolUnsupportedNotifyFunc set a function for notifying peer protocol supporting canceled.
func (s *simpleProtocolMgr) SetProtocolUnsupportedNotifyFunc(notifyFunc mgr.ProtocolSupportNotifyFunc) {
	s.unsupportedN = notifyFunc
}
