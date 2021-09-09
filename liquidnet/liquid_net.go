/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package liquidnet

import (
	"chainmaker.org/chainmaker/chainmaker-net-common/common"
	"chainmaker.org/chainmaker/chainmaker-net-common/common/priorityblocker"
	netGMTls "chainmaker.org/chainmaker/chainmaker-net-common/gmtlssupport"
	qTls "chainmaker.org/chainmaker/chainmaker-net-common/qtlssupport"
	netTls "chainmaker.org/chainmaker/chainmaker-net-common/tlssupport"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/broadcast"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/discovery"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/handler"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/types"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/util"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/discovery/protocoldiscovery"
	lHost "chainmaker.org/chainmaker/chainmaker-net-liquid/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/pubsub"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/tlssupport"
	"chainmaker.org/chainmaker/common/v2/crypto/asym"
	cmx509 "chainmaker.org/chainmaker/common/v2/crypto/x509"
	pbac "chainmaker.org/chainmaker/pb-go/v2/accesscontrol"
	commonPb "chainmaker.org/chainmaker/pb-go/v2/common"
	"chainmaker.org/chainmaker/pb-go/v2/syscontract"
	api "chainmaker.org/chainmaker/protocol/v2"
	"github.com/gogo/protobuf/proto"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/tjfoc/gmsm/gmtls"
	gmx509 "github.com/tjfoc/gmsm/x509"
	qx509 "github.com/xiaotianfork/q-tls-common/x509"

	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var log api.Logger
var pubSubLoggerCreator func(chainId string) api.Logger

var (
	// ErrorPubSubNotExist will be returned when pub-sub service not exist.
	ErrorPubSubNotExist = errors.New("pub-sub service not exist")
	// ErrorPubSubExisted will be returned if the pub-sub service exist
	// when calling InitPubSub method.
	ErrorPubSubExisted = errors.New("pub-sub service existed")
	// ErrorTopicSubscribed will be returned if the topic has been
	// subscribed when calling SubscribeWithChainId method.
	ErrorTopicSubscribed = errors.New("topic has been subscribed")
	// ErrorTopicNotSubscribed will be returned if the topic has
	// not been subscribed when calling CancelSubscribeWithChainId method.
	ErrorTopicNotSubscribed = errors.New("topic has not been subscribed")
	// ErrorNotBelongToChain will be returned if the remote node
	// not belong to chain expected when calling SendMsg method.
	ErrorNotBelongToChain = errors.New("node not belong to chain")
	// ErrorWrongAddressOrUnsupported will be returned if the listening
	// address is wrong or unsupported when calling Start method.
	ErrorWrongAddressOrUnsupported = errors.New("wrong address or address unsupported")
	// ErrorNetRunning will be returned if Start method has been called
	// when calling Start method.
	ErrorNetRunning = errors.New("net running")
)

const (
	// DefaultMaxPeerCount is the default value for HostConfig.MaxPeerCountAllowed.
	DefaultMaxPeerCount = 20
	// DefaultMaxConnCountEachPeer is the default value for HostConfig.MaxConnCountEachPeerAllowed.
	DefaultMaxConnCountEachPeer = 1
	// DefaultPeerEliminationStrategy is the default value for HostConfig.ConnEliminationStrategy.
	DefaultPeerEliminationStrategy = 3
	// DefaultInitSendStreamSize is the default value for HostConfig.SendStreamPoolInitSize.
	DefaultInitSendStreamSize = 10
	// DefaultSendStreamMaxCount is the default value for HostConfig.SendStreamPoolCap.
	DefaultSendStreamMaxCount = 100
	// DefaultListenAddress is the default value for HostConfig.ListenAddresses.
	DefaultListenAddress = "/ip4/0.0.0.0/tcp/0"
	// DefaultPubSubMaxMessageSize is the default value for pubSubConfig.MaxPubMessageSize.
	DefaultPubSubMaxMessageSize = 50 * (2 << 20)
)

func InitLogger(globalNetLogger api.Logger, pubSubLogCreator func(chainId string) api.Logger) {
	log = globalNetLogger
	pubSubLoggerCreator = pubSubLogCreator
}

var _ api.Net = (*LiquidNet)(nil)

// LiquidNet is an implementation of Net interface with liquid.
type LiquidNet struct {
	lock sync.Mutex

	context context.Context

	startUp bool
	netType api.NetType

	hostCfg *lHost.HostConfig
	host    host.Host
	psCfg   *pubSubConfig
	psMap   sync.Map //map[string]broadcast.PubSub

	cryptoCfg             *cryptoConfig
	memberStatusValidator *common.MemberStatusValidator

	tlsChainTrustRoots *netTls.ChainTrustRoots
	tlsCertValidator   *netTls.CertValidator

	gmTlsChainTrustRoots *netGMTls.ChainTrustRoots
	gmTlsCertValidator   *netGMTls.CertValidator

	qTlsChainTrustRoots *qTls.ChainTrustRoots
	qTlsCertValidator   *qTls.CertValidator

	peerIdChainIdsRecorder *common.PeerIdChainIdsRecorder
	certIdPeerIdMapper     *common.CertIdPeerIdMapper
	peerIdTlsCertStore     *common.PeerIdTlsCertStore

	subscribeTopic *types.StringSet

	discoveryService discovery.Discovery

	extensionsCfg      *extensionsConfig
	pktAdapter         *pktAdapter
	priorityController *priorityblocker.Blocker
}

// NewLiquidNet create a new LiquidNet instance.
func NewLiquidNet() (*LiquidNet, error) {
	ctx := context.Background()
	liquidNet := &LiquidNet{
		context: ctx,
		startUp: false,
		netType: api.Liquid,
		hostCfg: &lHost.HostConfig{
			TlsCfg:                      nil,
			LoadPidFunc:                 nil,
			SendStreamPoolInitSize:      DefaultInitSendStreamSize,
			SendStreamPoolCap:           DefaultSendStreamMaxCount,
			PeerReceiveStreamMaxCount:   0,
			MaxPeerCountAllowed:         DefaultMaxPeerCount,
			MaxConnCountEachPeerAllowed: DefaultMaxConnCountEachPeer,
			ConnEliminationStrategy:     DefaultPeerEliminationStrategy,
			ListenAddresses:             []ma.Multiaddr{ma.StringCast(DefaultListenAddress)},
			DirectPeers:                 make(map[peer.ID]ma.Multiaddr),
			BlackNetAddr:                make([]string, 0),
			BlackPeers:                  make([]peer.ID, 0),
			MsgCompress:                 false,
			Insecurity:                  false,
		},
		psCfg: &pubSubConfig{
			MaxPubMessageSize: DefaultPubSubMaxMessageSize,
		},
		cryptoCfg: &cryptoConfig{
			KeyBytes:                 nil,
			CertBytes:                nil,
			ChainTrustRootCertsBytes: make(map[string][][]byte),
		},
		memberStatusValidator: common.NewMemberStatusValidator(),
		subscribeTopic:        &types.StringSet{},
		extensionsCfg:         &extensionsConfig{EnablePkt: false},
		pktAdapter:            nil,
		priorityController:    nil,
	}
	liquidNet.peerIdChainIdsRecorder = common.NewPeerIdChainIdsRecorder(log)
	liquidNet.certIdPeerIdMapper = common.NewCertIdPeerIdMapper(log)
	liquidNet.peerIdTlsCertStore = common.NewPeerIdTlsCertStore(log)
	return liquidNet, nil
}

// HostConfig is the configuration of liquid host.
func (l *LiquidNet) HostConfig() *lHost.HostConfig {
	return l.hostCfg
}

// PubSubConfig is the configuration of liquid host.
func (l *LiquidNet) PubSubConfig() *pubSubConfig {
	return l.psCfg
}

// CryptoConfig is the configuration for crypto.
func (l *LiquidNet) CryptoConfig() *cryptoConfig {
	return l.cryptoCfg
}

// ExtensionsConfig is the configuration for extensions.
func (l *LiquidNet) ExtensionsConfig() *extensionsConfig {
	return l.extensionsCfg
}

// GetNodeUid get self peer id
func (l *LiquidNet) GetNodeUid() string {
	return l.host.ID().ToString()
}

// InitPubSub will init new PubSub instance with given chainId and maxMessageSize.
func (l *LiquidNet) InitPubSub(chainId string, maxMessageSize int) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	if _, ok := l.psMap.Load(chainId); ok {
		return ErrorPubSubExisted
	}
	if maxMessageSize <= 0 {
		maxMessageSize = l.PubSubConfig().MaxPubMessageSize
	}
	var err error

	pubSubLogger := pubSubLoggerCreator(chainId)
	ps := pubsub.NewChainPubSub(chainId, pubSubLogger, pubsub.WithPubSubMessageMaxSize(int32(maxMessageSize)))
	if l.startUp {
		err = ps.AttachHost(l.host)
		if err != nil {
			return err
		}
	}
	l.psMap.Store(chainId, ps)

	if l.startUp {
		err = l.attachDiscovery(chainId)
		if err != nil {
			return err
		}
	}

	return err
}

// BroadcastWithChainId publish the message to topic, if not subscribe the topic, will return error
func (l *LiquidNet) BroadcastWithChainId(chainId string, topic string, data []byte) error {
	// whether pub-sub service exist
	ps, ok := l.psMap.Load(chainId)
	if !ok {
		return ErrorPubSubNotExist
	}
	// publish msg
	chainPubSub, _ := ps.(*pubsub.ChainPubSub)
	chainPubSub.Publish(topic, data)
	return nil
}

func (l *LiquidNet) createSubMsgHandler(chainId string, handler api.PubSubMsgHandler) handler.SubMsgHandler {
	return func(publisher peer.ID, topic string, msg []byte) {
		go func(publisherInner peer.ID, topicInner string, msgInner []byte) {
			// whether published by myself
			if publisherInner.ToString() == l.GetNodeUid() {
				return
			}
			// whether belong to the chain
			if !l.peerIdChainIdsRecorder.IsPeerBelongToChain(publisherInner.ToString(), chainId) {
				log.Debug("[LiquidNet] get sub msg from peer not belong to chain (publisher:", publisherInner.ToString(), ", chain:", chainId, ")")
				return
			}

			// call msg handler
			err := handler(publisherInner.ToString(), msgInner)
			if err != nil {
				log.Errorf(
					"[LiquidNet] call subscribe handler failed, %s (publisher: %s,topic: %s,msg: %v)",
					err.Error(), publisherInner.ToString(), topicInner, msgInner)
				return
			}
		}(publisher, topic, msg)
	}
}

// SubscribeWithChainId register a PubSubMsgHandler to a PubSubTopic with the pub-sub service which id is given chainId.
func (l *LiquidNet) SubscribeWithChainId(chainId string, topic string, handler api.PubSubMsgHandler) error {
	// whether pub-sub service exist
	chainPubSub, ok := l.psMap.Load(chainId)
	if !ok {
		return ErrorPubSubNotExist
	}
	// whether has subscribed
	chainTopic := chainAppendTopic(chainId, topic)
	if l.subscribeTopic.Exist(chainTopic) {
		return ErrorTopicSubscribed
	}
	// create sub msg handler
	h := l.createSubMsgHandler(chainId, handler)
	// subscribe topic
	chainPubSub.(*pubsub.ChainPubSub).Subscribe(topic, h)
	l.subscribeTopic.Put(chainTopic)
	return nil
}

// CancelSubscribeWithChainId cancel subscribe a PubSubTopic with the pub-sub service which id is given chainId.
func (l *LiquidNet) CancelSubscribeWithChainId(chainId string, topic string) error {
	// whether pub-sub service exist
	ps, ok := l.psMap.Load(chainId)
	if !ok {
		return ErrorPubSubNotExist
	}
	// whether has subscribe
	chainTopic := chainAppendTopic(chainId, topic)
	if !l.subscribeTopic.Exist(chainTopic) {
		return ErrorTopicNotSubscribed
	}
	// unsubscribe topic
	ps.(*pubsub.ChainPubSub).Unsubscribe(topic)
	l.subscribeTopic.Remove(chainTopic)
	return nil
}

func chainAppendTopic(chain, topic string) string {
	return chain + "-" + topic
}

// SendMsg send msg to the node which id is given string.
// 		msgFlag: is a flag used to distinguish msg type.
func (l *LiquidNet) SendMsg(chainId string, targetPeer string, msgFlag string, data []byte) error {
	if targetPeer == l.GetNodeUid() {
		log.Warn("[LiquidNet] [SendMsg] can not send msg to self")
		return nil
	}

	if l.priorityController != nil {
		l.priorityController.Block(msgFlag)
	}

	targetPeerId := peer.ID(targetPeer)

	// whether peer belong to chain
	if !l.hostCfg.Insecurity && !l.peerIdChainIdsRecorder.IsPeerBelongToChain(targetPeer, chainId) {
		return ErrorNotBelongToChain
	}
	// create protocol id
	netProtocolId := CreateProtocolIdWithChainIdAndMsgFlag(chainId, msgFlag)
	// whether pktAdapter enabled
	if l.pktAdapter != nil {
		e := l.pktAdapter.sendMsg(targetPeerId, netProtocolId, data)
		if e != nil {
			log.Errorf("[LiquidNet] [SendMsg][Pkt] send message failed, %s "+
				"(chain: %s, targetPeer: %s, msg_flag: %s)",
				e.Error(), chainId, targetPeer, msgFlag)
			return e
		}
		return nil
	}

	// send msg
	err := l.host.SendMsg(netProtocolId, targetPeerId, data)
	if err != nil {
		log.Errorf("[LiquidNet] [SendMsg] send message failed, %s (chain: %s, targetPeer: %s, msg_flag: %s)",
			err.Error(), chainId, targetPeer, msgFlag)
		return err
	}
	return nil
}

func (l *LiquidNet) createMsgPayloadHandler(handler api.DirectMsgHandler) handler.MsgPayloadHandler {
	return func(senderPID peer.ID, msgPayload []byte) {
		go func(senderPIDInner peer.ID, msgPayloadInner []byte) {
			// call handler
			err := handler(string(senderPIDInner), msgPayloadInner)
			if err != nil {
				log.Errorf("[LiquidNet] [DirectMsgHandle] call direct msg handler failed, %s "+
					"(sender: %s, message_length: %d)",
					err.Error(), senderPIDInner, len(msgPayloadInner))
				return
			}
		}(senderPID, msgPayload)
	}
}

// DirectMsgHandle register a DirectMsgHandler to the net.
// 		msgFlag: is a flag used to distinguish msg type.
func (l *LiquidNet) DirectMsgHandle(chainId string, msgFlag string, handler api.DirectMsgHandler) error {
	// create net protocol id
	netProtocolId := CreateProtocolIdWithChainIdAndMsgFlag(chainId, msgFlag)
	// create msg payload handler
	h := l.createMsgPayloadHandler(handler)
	// register handler
	err := l.host.RegisterMsgPayloadHandler(netProtocolId, h)
	if err != nil {
		log.Errorf("[LiquidNet] [DirectMsgHandle] register handler failed, %s (chain id:%s, msg_flag:%s)",
			err.Error(), chainId, msgFlag)
		return err
	}
	return nil
}

// CancelDirectMsgHandle unregister a DirectMsgHandler.
// 		msgFlag: is a flag used to distinguish msg type.
func (l *LiquidNet) CancelDirectMsgHandle(chainId string, msgFlag string) error {
	// create net protocol id
	netProtocolId := CreateProtocolIdWithChainIdAndMsgFlag(chainId, msgFlag)
	// unregister handler
	err := l.host.UnregisterMsgPayloadHandler(netProtocolId)
	if err != nil {
		log.Errorf("[LiquidNet] [CancelDirectMsgHandle] caccel handler failed, %s (chain:%s, msg_flag:%s)",
			err.Error(), chainId, msgFlag)
	}
	return err
}

// AddSeed add a seed node addr.
func (l *LiquidNet) AddSeed(seed string) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.startUp {
		dp, err := ma.NewMultiaddr(seed)
		if err != nil {
			return err
		}
		l.host.AddDirectPeer(dp)
	}
	if err := l.hostCfg.AddDirectPeer(seed); err != nil {
		return err
	}
	return nil
}

// RefreshSeeds refresh the seed node addr list.
func (l *LiquidNet) RefreshSeeds(seeds []string) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.hostCfg.DirectPeers = make(map[peer.ID]ma.Multiaddr)
	if l.startUp {
		l.host.ClearDirectPeers()
	}
	for _, seed := range seeds {
		if err := l.hostCfg.AddDirectPeer(seed); err != nil {
			return err
		}
		if l.startUp {
			dp, err := ma.NewMultiaddr(seed)
			if err != nil {
				return err
			}
			l.host.AddDirectPeer(dp)
		}
	}
	return nil
}

// AddTrustRoot add a tls root cert to the cert pool of chain.
func (l *LiquidNet) AddTrustRoot(chainId string, rootCertByte []byte) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.startUp {
		if !l.hostCfg.Insecurity {
			var err error
			if l.hostCfg.NetType == lHost.QuicNetwork {
				_, err = qTls.AppendNewCertsToTrustRoots(l.qTlsChainTrustRoots, chainId, rootCertByte)
			} else if l.hostCfg.UseGMTls {
				_, err = netGMTls.AppendNewCertsToTrustRoots(l.gmTlsChainTrustRoots, chainId, rootCertByte)
			} else {
				_, err = netTls.AppendNewCertsToTrustRoots(l.tlsChainTrustRoots, chainId, rootCertByte)
			}
			if err != nil {
				log.Errorf("[LiquidNet] [AddTrustRoot] add trust root failed. %s", err.Error())
				return err
			}
		}
		return nil
	}
	l.cryptoCfg.AddTrustRootCert(chainId, rootCertByte)
	return nil
}

// RefreshTrustRoots refresh the cert pool of chain.
func (l *LiquidNet) RefreshTrustRoots(chainId string, rootsCertsBytes [][]byte) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.startUp {
		if l.hostCfg.Insecurity {
			log.Warn("[LiquidNet] [RefreshTrustRoots] tls disabled. ignored.")
			return nil
		}
		var bl bool
		if l.hostCfg.NetType == lHost.QuicNetwork {
			bl = l.qTlsChainTrustRoots.RefreshRootsFromPem(chainId, rootsCertsBytes)
		} else if l.hostCfg.UseGMTls {
			bl = l.gmTlsChainTrustRoots.RefreshRootsFromPem(chainId, rootsCertsBytes)
		} else {
			bl = l.tlsChainTrustRoots.RefreshRootsFromPem(chainId, rootsCertsBytes)
		}
		if !bl {
			return errors.New("refresh trust roots failed")
		}
		return nil
	}
	l.cryptoCfg.ChainTrustRootCertsBytes = make(map[string][][]byte)
	for _, certsByte := range rootsCertsBytes {
		l.cryptoCfg.AddTrustRootCert(chainId, certsByte)
	}
	return nil
}

// ReVerifyTrustRoots will verify tls certs existed with the trust
// roots pool of the chain which id is the given chainId.
func (l *LiquidNet) ReVerifyTrustRoots(chainId string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if !l.startUp {
		return
	}
	if l.hostCfg.Insecurity {
		return
	}
	peerIdTlsCertMap := l.peerIdTlsCertStore.StoreCopy()
	if len(peerIdTlsCertMap) == 0 {
		return
	}

	// re verify exist peers
	existPeers := l.peerIdChainIdsRecorder.PeerIdsOfChain(chainId)
	for _, existPeerId := range existPeers {
		bytes, ok := peerIdTlsCertMap[existPeerId]
		if ok {
			if l.hostCfg.NetType == lHost.QuicNetwork {
				// tls cert exist, parse to cert
				cert, err := qx509.ParseCertificate(bytes)
				if err != nil {
					log.Errorf("[LiquidNet] [ReVerifyTrustRoots] re-verify quic tls cert failed. %s",
						err.Error())
					continue
				}
				// whether verify failed, if failed remove it
				if !l.qTlsChainTrustRoots.VerifyCertOfChain(chainId, cert) {
					l.peerIdChainIdsRecorder.RemovePeerChainId(existPeerId, chainId)
					log.Infof("[LiquidNet] [ReVerifyTrustRoots] remove peer from chain, (pid: %s, chain id: %s)",
						existPeerId, chainId)
				}
				delete(peerIdTlsCertMap, existPeerId)
				continue
			}
			if l.hostCfg.UseGMTls {
				// tls cert exist, parse to cert
				cert, err := gmx509.ParseCertificate(bytes)
				if err != nil {
					log.Errorf("[LiquidNet] [ReVerifyTrustRoots] re-verify tls cert failed. %s", err.Error())
					continue
				}
				// whether verify failed, if failed remove it
				if !l.gmTlsChainTrustRoots.VerifyCertOfChain(chainId, cert) {
					l.peerIdChainIdsRecorder.RemovePeerChainId(existPeerId, chainId)
					log.Infof("[LiquidNet] [ReVerifyTrustRoots] remove peer from chain, (pid: %s, chain id: %s)",
						existPeerId, chainId)
				}
				delete(peerIdTlsCertMap, existPeerId)
				continue
			}
			// tls cert exist, parse to cert
			cert, err := x509.ParseCertificate(bytes)
			if err != nil {
				log.Errorf("[LiquidNet] [ReVerifyTrustRoots] re-verify tls cert failed. %s", err.Error())
				continue
			}
			// whether verify failed, if failed remove it
			if !l.tlsChainTrustRoots.VerifyCertOfChain(chainId, cert) {
				l.peerIdChainIdsRecorder.RemovePeerChainId(existPeerId, chainId)
				log.Infof("[LiquidNet] [ReVerifyTrustRoots] remove peer from chain, (pid: %s, chain id: %s)",
					existPeerId, chainId)
			}
			delete(peerIdTlsCertMap, existPeerId)
		} else {
			l.peerIdChainIdsRecorder.RemovePeerChainId(existPeerId, chainId)
			log.Infof("[LiquidNet] [ReVerifyTrustRoots] remove peer from chain, (pid: %s, chain id: %s)",
				existPeerId, chainId)
		}
	}
	// verify other peers
	for pid, bytes := range peerIdTlsCertMap {
		if l.hostCfg.NetType == lHost.QuicNetwork {
			cert, err := qx509.ParseCertificate(bytes)
			if err != nil {
				log.Errorf("[LiquidNet] [ReVerifyTrustRoots] re-verify quic tls cert failed. %s", err.Error())
				continue
			}
			// whether verify success, if success add it
			if l.qTlsChainTrustRoots.VerifyCertOfChain(chainId, cert) {
				l.peerIdChainIdsRecorder.AddPeerChainId(pid, chainId)
				log.Infof("[LiquidNet] [ReVerifyTrustRoots] add peer to chain, (pid: %s, chain id: %s)",
					pid, chainId)
			}
			continue
		}
		if l.hostCfg.UseGMTls {
			cert, err := gmx509.ParseCertificate(bytes)
			if err != nil {
				log.Errorf("[LiquidNet] [ReVerifyTrustRoots] re-verify tls cert failed. %s", err.Error())
				continue
			}
			// whether verify success, if success add it
			if l.gmTlsChainTrustRoots.VerifyCertOfChain(chainId, cert) {
				l.peerIdChainIdsRecorder.AddPeerChainId(pid, chainId)
				log.Infof("[LiquidNet] [ReVerifyTrustRoots] add peer to chain, (pid: %s, chain id: %s)",
					pid, chainId)
			}
			continue
		}
		cert, err := x509.ParseCertificate(bytes)
		if err != nil {
			log.Errorf("[LiquidNet] [ReVerifyTrustRoots] re-verify tls cert failed. %s", err.Error())
			continue
		}
		// whether verify success, if success add it
		if l.tlsChainTrustRoots.VerifyCertOfChain(chainId, cert) {
			l.peerIdChainIdsRecorder.AddPeerChainId(pid, chainId)
			log.Infof("[LiquidNet] [ReVerifyTrustRoots] add peer to chain, (pid: %s, chain id: %s)",
				pid, chainId)
		}
	}

	// close all connections of peers not belong to any chain
	for _, s := range l.peerIdChainIdsRecorder.PeerIdsOfNoChain() {
		pid := peer.ID(s)
		for c := l.host.ConnMgr().GetPeerConn(pid); c != nil; c = l.host.ConnMgr().GetPeerConn(pid) {
			_ = c.Close()
			log.Infof("[LiquidNet] [ReVerifyTrustRoots] close connection of peer %s", s)
			time.Sleep(time.Second)
		}
	}
}

// IsRunning return true when the net instance is running.
func (l *LiquidNet) IsRunning() bool {
	l.lock.Lock()
	defer l.lock.Unlock()
	return l.startUp
}

func (l *LiquidNet) confirmConfig() {
	log.Info("[LiquidNet] config confirming...")
	hc := l.hostCfg
	if hc.SendStreamPoolInitSize <= 0 {
		log.Warnf("[LiquidNet] wrong init send stream size set, use default (set: %d, default: %d)",
			hc.SendStreamPoolInitSize, DefaultInitSendStreamSize)
		hc.SendStreamPoolInitSize = DefaultInitSendStreamSize
	}
	if hc.SendStreamPoolCap <= 0 {
		log.Warnf("[LiquidNet] wrong send stream max count value set, use default (set: %d, default: %d)",
			hc.SendStreamPoolCap, DefaultSendStreamMaxCount)
		hc.SendStreamPoolCap = DefaultSendStreamMaxCount
	}
	if hc.MaxConnCountEachPeerAllowed <= 0 {
		log.Warnf("[LiquidNet] wrong max connection count value of each peer set, use default "+
			"(set: %d, default: %d)",
			hc.MaxConnCountEachPeerAllowed, DefaultMaxConnCountEachPeer)
		hc.MaxConnCountEachPeerAllowed = DefaultSendStreamMaxCount
	}
	if hc.PeerReceiveStreamMaxCount <= 0 {
		recommended := hc.SendStreamPoolCap * int32(hc.MaxConnCountEachPeerAllowed)
		log.Warnf("[LiquidNet] wrong receive stream max count value of each peer set, use recommended value "+
			"(set: %d, recommended: %d)",
			hc.PeerReceiveStreamMaxCount, recommended)
		hc.PeerReceiveStreamMaxCount = recommended
	}
	if hc.MaxPeerCountAllowed <= 0 {
		log.Warnf("[LiquidNet] wrong max peer count allowed value set, use default (set: %d, default: %d)",
			hc.MaxPeerCountAllowed, DefaultMaxPeerCount)
		hc.MaxPeerCountAllowed = DefaultMaxPeerCount
	}
	if hc.ConnEliminationStrategy <= 0 {
		log.Warnf("[LiquidNet] wrong connection elimination strategy value set, use default "+
			"(set: %d, default: %d)",
			hc.ConnEliminationStrategy, DefaultPeerEliminationStrategy)
		hc.ConnEliminationStrategy = DefaultPeerEliminationStrategy
	}
	var err error
	hc.UseGMTls, err = tlssupport.UseGMTls(l.cryptoCfg.CertBytes)
	if err != nil {
		panic("[LiquidNet] can not confirm crypto cert:" + err.Error())
	}
	log.Info("[LiquidNet] config confirmed.")
}

func (l *LiquidNet) setUpChainTrustRoots() error {
	log.Info("[LiquidNet] chain trust roots setting...")
	if !l.hostCfg.Insecurity {
		// if tls enabled
		if len(l.cryptoCfg.ChainTrustRootCertsBytes) == 0 {
			log.Warn("[LiquidNet] no trust root certs found. use default security.")
		} else {
			if l.hostCfg.NetType == lHost.QuicNetwork {
				trustRoots, err := qTls.BuildTlsTrustRoots(l.cryptoCfg.ChainTrustRootCertsBytes)
				if err != nil {
					log.Errorf("[LiquidNet] build quic tls trust root failed, %s", err.Error())
					return err
				}
				l.qTlsChainTrustRoots = trustRoots
			} else if l.hostCfg.UseGMTls {
				trustRoots, err := netGMTls.BuildTlsTrustRoots(l.cryptoCfg.ChainTrustRootCertsBytes)
				if err != nil {
					log.Errorf("[LiquidNet] build gm tls trust root failed, %s", err.Error())
					return err
				}
				l.gmTlsChainTrustRoots = trustRoots
			} else {
				trustRoots, err := netTls.BuildTlsTrustRoots(l.cryptoCfg.ChainTrustRootCertsBytes)
				if err != nil {
					log.Errorf("[LiquidNet] build tls trust root failed, %s", err.Error())
					return err
				}
				l.tlsChainTrustRoots = trustRoots
			}
		}
	}
	log.Info("[LiquidNet] chain trust roots set up.")
	return nil
}

func (l *LiquidNet) setUpGMTlsConfig() error {
	log.Info("[LiquidNet] gm tls config setting...")
	// try gm tls
	var (
		gmTlsEncryptCert *gmtls.Certificate
		peerId           string
		err              error
	)

	gmTlsEncryptCert, peerId, err = netGMTls.GetCertAndPeerIdWithKeyPair(l.cryptoCfg.CertBytes, l.cryptoCfg.KeyBytes)
	if err != nil {
		return err
	}
	l.peerIdTlsCertStore.SetPeerTlsCert(peerId, gmTlsEncryptCert.Certificate[0])

	// gm tls cert validator
	l.gmTlsCertValidator = netGMTls.NewCertValidator(l.gmTlsChainTrustRoots, l.memberStatusValidator)

	// gm tls config for server/client
	var tlsServerCfg, tlsClientCfg *gmtls.Config
	var randomSignCert bool
	tlsServerCfg, randomSignCert, err = netGMTls.GenerateGMTlsServerConfigWithDualCerts(
		gmTlsEncryptCert,
		l.cryptoCfg.SignKeyBytes,
		l.cryptoCfg.SignCertBytes,
		l.gmTlsCertValidator)
	if err != nil {
		return err
	}
	if randomSignCert {
		log.Info("[LiquidNet] sign key or cert not found, " +
			"try to create a new cert with encrypt cert as temp sign cert.")
		log.Debug("[LiquidNet] generate random sign certificate success.")
	} else {
		log.Info("[LiquidNet] sign key and cert found, use dual certificate mode.")
	}
	tlsClientCfg, err = netGMTls.NewTlsClientConfig(*gmTlsEncryptCert, l.gmTlsCertValidator, true)
	if err != nil {
		return err
	}
	l.hostCfg.GMTlsServerCfg = tlsServerCfg
	l.hostCfg.GMTlsClientCfg = tlsClientCfg
	l.hostCfg.LoadPidFuncGm = tlssupport.PeerIdFunctionGM()
	l.hostCfg.UseGMTls = true
	log.Info("[LiquidNet] gm tls config set up.")
	return nil
}

func (l *LiquidNet) setUpTlsConfig() error {
	log.Info("[LiquidNet] tls config setting...")
	tlsCert, peerId, err := netTls.GetCertAndPeerIdWithKeyPair(l.cryptoCfg.CertBytes, l.cryptoCfg.KeyBytes)
	if err != nil {
		return err
	}
	l.peerIdTlsCertStore.SetPeerTlsCert(peerId, tlsCert.Certificate[0])
	// tls cert validator
	tcv := netTls.NewCertValidator(l.tlsChainTrustRoots, l.memberStatusValidator)
	l.tlsCertValidator = tcv
	//tls config
	tlsConfig, err := netTls.NewTlsConfig(
		*tlsCert,
		tcv,
	)
	if err != nil {
		return err
	}
	l.hostCfg.TlsCfg = tlsConfig
	l.hostCfg.LoadPidFunc = tlssupport.PeerIdFunction()
	log.Info("[LiquidNet] tls config set up.")
	return nil
}

func (l *LiquidNet) setUpQTlsConfig() error {
	log.Info("[LiquidNet] quic tls config setting...")
	tlsCert, peerId, err := qTls.GetCertAndPeerIdWithKeyPair(l.cryptoCfg.CertBytes, l.cryptoCfg.KeyBytes)
	if err != nil {
		return err
	}
	l.peerIdTlsCertStore.SetPeerTlsCert(peerId, tlsCert.Certificate[0])
	// tls cert validator
	tcv := qTls.NewCertValidator(l.qTlsChainTrustRoots, l.memberStatusValidator)
	l.qTlsCertValidator = tcv
	//tls config
	tlsConfig, err := qTls.NewTlsConfig(
		*tlsCert,
		tcv,
		l.hostCfg.UseGMTls,
	)
	if err != nil {
		return err
	}
	l.hostCfg.QTlsCfg = tlsConfig
	l.hostCfg.LoadPidFuncQ = tlssupport.PeerIdFunctionQuic()
	log.Info("[LiquidNet] quic tls config set up.")
	return nil
}

// Start the local net.
func (l *LiquidNet) Start() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	var err error

	if l.startUp {
		return ErrorNetRunning
	}

	// confirm config
	l.confirmConfig()

	// load private key
	l.hostCfg.PrivateKey, err = asym.PrivateKeyFromPEM(l.cryptoCfg.KeyBytes, nil)
	if err != nil {
		return err
	}

	// confirm network type
	var netType lHost.NetworkType
	firstListenAddr := l.hostCfg.ListenAddresses[0]
	netType = lHost.ConfirmNetworkTypeByAddr(firstListenAddr)
	if netType == lHost.UnknownNetwork {
		return ErrorWrongAddressOrUnsupported
	}
	l.hostCfg.NetType = netType
	log.Infof("[LiquidNet] network type: %s", netType)

	// set upt chain trust roots
	err = l.setUpChainTrustRoots()
	if err != nil {
		return err
	}

	// set up tls config , local peer.ID will be set using options set in this step
	if l.hostCfg.NetType == lHost.QuicNetwork {
		err = l.setUpQTlsConfig()
	} else if l.hostCfg.UseGMTls {
		err = l.setUpGMTlsConfig()
	} else {
		err = l.setUpTlsConfig()
	}
	if err != nil {
		return err
	}

	// create new host
	newHost, err := l.hostCfg.NewHost(netType, l.context, log)
	if err != nil {
		return err
	}

	l.host = newHost
	// bind notifiee
	l.bindNotifiee()

	// pkt adapter
	if l.extensionsCfg.EnablePkt {
		log.Infof("[LiquidNet] Pkt enabled.")
		l.pktAdapter = newPktAdapter(l.host, log)
		l.pktAdapter.run()
		err = l.host.RegisterMsgPayloadHandler(pktProtocol, l.pktAdapter.msgPayloadFunc)
		if err != nil {
			return err
		}
	}

	// priority blocker
	if l.extensionsCfg.EnablePriorityCtrl {
		log.Infof("[LiquidNet] priority control enabled.")
		l.priorityController = priorityblocker.NewBlocker(nil)
		l.priorityController.Run()
	}

	// start host
	err = newHost.Start()
	if err != nil {
		log.Errorf("[LiquidNet] host start failed, %s", err.Error())
		return err
	}

	// start pub-sub
	log.Info("[LiquidNet] pub-sub services attaching...")
	l.psMap.Range(func(key, value interface{}) bool {
		ps, _ := value.(*pubsub.ChainPubSub)
		err = ps.AttachHost(l.host)
		if err != nil {
			return false
		}
		chainId, _ := key.(string)
		log.Infof("[LiquidNet] pub-sub service attached. (chain-id: %s)", chainId)
		err = l.attachDiscovery(chainId)
		return err == nil
	})
	if err != nil {
		return err
	}
	log.Info("[LiquidNet] pub-sub services attached.")

	// set up discovery service
	l.discoveryService, err = protocoldiscovery.NewProtocolBasedDiscovery(
		l.host,
		protocoldiscovery.WithLogger(log),
		protocoldiscovery.WithMaxQuerySize(3),
	)
	if err != nil {
		log.Errorf("[LiquidNet] set up discovery service failed, %s", err.Error())
		return err
	}
	log.Info("[LiquidNet] discovery service set up.")
	l.startUp = true
	return err
}

func (l *LiquidNet) queryAndStoreDerivedInfoInCertValidator(peerIdStr string) {
	if l.hostCfg.Insecurity {
		return
	}
	if l.hostCfg.NetType == lHost.QuicNetwork {
		derivedInfo := l.qTlsCertValidator.QueryDerivedInfoWithPeerId(peerIdStr)
		if derivedInfo != nil {
			l.peerIdTlsCertStore.SetPeerTlsCert(derivedInfo.PeerId, derivedInfo.TlsCertBytes)
			for i := range derivedInfo.ChainIds {
				l.peerIdChainIdsRecorder.AddPeerChainId(derivedInfo.PeerId, derivedInfo.ChainIds[i])
			}
			l.certIdPeerIdMapper.Add(derivedInfo.CertId, derivedInfo.PeerId)
		} else {
			log.Warnf("[LiquidNet] no derived info found from quic tls cert validator! (pid: %s)", peerIdStr)
		}
		return
	}
	if l.hostCfg.UseGMTls {
		derivedInfo := l.gmTlsCertValidator.QueryDerivedInfoWithPeerId(peerIdStr)
		if derivedInfo != nil {
			l.peerIdTlsCertStore.SetPeerTlsCert(derivedInfo.PeerId, derivedInfo.TlsCertBytes)
			for i := range derivedInfo.ChainIds {
				l.peerIdChainIdsRecorder.AddPeerChainId(derivedInfo.PeerId, derivedInfo.ChainIds[i])
			}
			l.certIdPeerIdMapper.Add(derivedInfo.CertId, derivedInfo.PeerId)
		} else {
			log.Warnf("[LiquidNet] no derived info found from gmtls cert validator! (pid: %s)", peerIdStr)
		}
		return
	}
	derivedInfo := l.tlsCertValidator.QueryDerivedInfoWithPeerId(peerIdStr)
	if derivedInfo != nil {
		l.peerIdTlsCertStore.SetPeerTlsCert(derivedInfo.PeerId, derivedInfo.TlsCertBytes)
		for i := range derivedInfo.ChainIds {
			l.peerIdChainIdsRecorder.AddPeerChainId(derivedInfo.PeerId, derivedInfo.ChainIds[i])
		}
		l.certIdPeerIdMapper.Add(derivedInfo.CertId, derivedInfo.PeerId)
	} else {
		log.Warnf("[LiquidNet] no derived info found from tls cert validator! (pid: %s)", peerIdStr)
	}
}

// bindNotifiee create a notifiee bundle then register it to the host.
func (l *LiquidNet) bindNotifiee() {
	notifieeBundle := &host.NotifieeBundle{
		PeerConnectedFunc: func(id peer.ID) {
			l.lock.Lock()
			defer l.lock.Unlock()
			peerIdStr := id.ToString()
			log.Debugf("[LiquidNet] peer connected. (pid: %s)", peerIdStr)
			l.queryAndStoreDerivedInfoInCertValidator(peerIdStr)
		},
		PeerDisconnectedFunc: func(peerId peer.ID) {
			l.lock.Lock()
			defer l.lock.Unlock()
			peerIdStr := peerId.ToString()
			log.Debugf("[LiquidNet] peer disconnect. (pid: %s)", peerIdStr)
			l.peerIdChainIdsRecorder.RemoveAllByPeerId(peerIdStr)
			l.peerIdTlsCertStore.RemoveByPeerId(peerIdStr)
			l.certIdPeerIdMapper.RemoveByPeerId(peerIdStr)
		},
	}
	l.host.Notify(notifieeBundle)
}

func (l *LiquidNet) listenFindingChanTask(c <-chan ma.Multiaddr) {
	for {
		select {
		case <-l.context.Done():
			return
		case ai := <-c:
			addr, pid := util.GetNetAddrAndPidFromNormalMultiAddr(ai)
			if pid == "" {
				log.Errorf("[LiquidNet] [Discovery] peer id not contains in addr")
				continue
			}
			if l.host.ConnMgr().PeerCount() >= l.host.ConnMgr().MaxPeerCountAllowed() ||
				l.host.ID() == pid ||
				l.host.ConnMgr().IsConnected(pid) {
				continue
			}
			log.Infof("[LiquidNet] [Discovery] find new peer.(pid: %s, addr: %s)", pid, addr.String())
			_, _ = l.host.Dial(ai)
		}
	}
}

func (l *LiquidNet) attachDiscovery(chainId string) error {
	var err error
	// discovery announce
	err = l.discoveryService.Announce(l.context, chainId)
	if err != nil {
		return err
	}
	log.Infof("[LiquidNet] chain service announced. (chain-id: %s)", chainId)
	// discovery finding
	var findingC <-chan ma.Multiaddr
	findingC, err = l.discoveryService.FindPeers(l.context, chainId, protocoldiscovery.WithQuerySize(3))
	if err != nil {
		return err
	}
	go l.listenFindingChanTask(findingC)
	log.Infof("[LiquidNet] chain peers finding... (chain-id: %s)", chainId)
	return nil
}

// Stop the local net.
func (l *LiquidNet) Stop() error {
	l.lock.Lock()
	defer l.lock.Unlock()
	log.Infof("[LiquidNet] stopping...")
	l.startUp = false

	l.psMap.Range(func(key, value interface{}) bool {
		_ = value.(broadcast.PubSub).Stop()
		return true
	})
	l.psMap = sync.Map{}
	log.Infof("[LiquidNet] pubsub cleaned.")

	log.Infof("[LiquidNet] host stopping...")
	if l.pktAdapter != nil {
		l.pktAdapter.cancel()
	}
	err := l.host.Stop()
	if err != nil {
		log.Infof("[LiquidNet] [Stop] stop host error. err:%v", err)
		return err
	}
	log.Infof("[LiquidNet] host stopped.")
	log.Infof("[LiquidNet] stopped.")
	return nil
}

// ChainNodesInfo return base node info list of chain which id is the given chainId.
func (l *LiquidNet) ChainNodesInfo(chainId string) ([]*api.ChainNodeInfo, error) {
	result := make([]*api.ChainNodeInfo, 0)
	if !l.hostCfg.Insecurity {
		peerIds := make([]string, 0)
		peerIds = append(peerIds, l.GetNodeUid())
		peerIds = append(peerIds, l.peerIdChainIdsRecorder.PeerIdsOfChain(chainId)...)
		for _, peerId := range peerIds {
			pid := peerId
			addrs := make([]string, 0)
			if pid == l.GetNodeUid() {
				for _, addr := range l.host.LocalAddresses() {
					addrs = append(addrs, addr.String())
				}
			} else {
				for _, addr := range l.host.PeerStore().GetAddrs(peer.ID(pid)) {
					addrs = append(addrs, addr.String())
				}
			}
			cert := l.peerIdTlsCertStore.GetCertByPeerId(peerId)
			result = append(result, &api.ChainNodeInfo{
				NodeUid:     peerId,
				NodeAddress: addrs,
				NodeTlsCert: cert,
			})
		}
	}
	return result, nil
}

// GetNodeUidByCertId return node uid which mapped to the given cert id. If unmapped return error.
func (l *LiquidNet) GetNodeUidByCertId(certId string) (string, error) {
	nodeUid, err := l.certIdPeerIdMapper.FindPeerIdByCertId(certId)
	if err != nil {
		return "", err
	}
	return nodeUid, nil
}

// CheckRevokeTlsCerts check whether any tls certs revoked.
func (l *LiquidNet) CheckRevokeTlsCerts(ac api.AccessControlProvider, certManageSystemContractPayload []byte) error {
	var payload commonPb.Payload
	err := proto.Unmarshal(certManageSystemContractPayload, &payload)
	if err != nil {
		return fmt.Errorf("resolve payload failed: %v", err)
	}
	switch payload.Method {
	case syscontract.CertManageFunction_CERTS_REVOKE.String():
		return l.checkRevokeTlsCertsWithSystemContractPayload(ac, &payload)
	default:
		return nil
	}
}

func (l *LiquidNet) checkRevokeTlsCertsWithSystemContractPayload(
	ac api.AccessControlProvider,
	payload *commonPb.Payload) error {
	allPeerIdAndCertBytesMap := l.peerIdTlsCertStore.StoreCopy()
	if len(allPeerIdAndCertBytesMap) == 0 {
		return nil
	}
	peerIdCertMap, err := common.ParsePeerIdCertBytesMapToPeerIdCertMap(allPeerIdAndCertBytesMap)
	if err != nil {
		log.Errorf("[LiquidNet] [checkRevokeTlsCertsWithSystemContractPayload] parse bytes to cert failed, %s",
			err.Error())
		return err
	}
	return l.checkRevokeThenDisconnect(ac, payload, peerIdCertMap)
}

func (l *LiquidNet) checkRevokeThenDisconnect(
	ac api.AccessControlProvider,
	payload *commonPb.Payload,
	peerIdCertMap map[string]*cmx509.Certificate) error {
	for _, param := range payload.Parameters {
		if param.Key == "cert_crl" {
			crlStr := strings.Replace(string(param.Value), ",", "\n", -1)
			_, err := ac.VerifyRelatedMaterial(pbac.VerifyType_CRL, []byte(crlStr))
			if err != nil {
				log.Errorf("[LiquidNet] [checkRevokeThenDisconnect] validate crl failed, %s", err.Error())
				return err
			}

			var crls []*pkix.CertificateList

			crl, err := x509.ParseCRL([]byte(crlStr))
			if err != nil {
				log.Errorf("[LiquidNet] [checkRevokeThenDisconnect] validate crl failed, %s", err.Error())
				return err
			}
			crls = append(crls, crl)
			if err != nil {
				log.Errorf("[LiquidNet] [checkRevokeThenDisconnect] validate crl failed, %s", err.Error())
				return err
			}
			revokedPeerIds := l.findRevokedPeerIdsByCRLs(crls, peerIdCertMap)
			return l.closeRevokedPeerConnection(revokedPeerIds)
		}
	}
	return nil
}

func (l *LiquidNet) findRevokedPeerIdsByCRLs(
	crls []*pkix.CertificateList,
	peerIdCertMap map[string]*cmx509.Certificate) []string {
	revokedPeerIds := make([]string, 0)
	for _, crl := range crls {
		for _, rc := range crl.TBSCertList.RevokedCertificates {
			for pid := range peerIdCertMap {
				cert := peerIdCertMap[pid]
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					revokedPeerIds = append(revokedPeerIds, pid)
				}
			}
		}
	}
	return revokedPeerIds
}

func (l *LiquidNet) closeRevokedPeerConnection(revokedPeerIds []string) error {
	for idx := range revokedPeerIds {
		pid := revokedPeerIds[idx]
		log.Infof("[LiquidNet] [closeRevokedPeerConnection] revoked peer found(pid: %s)", pid)
		peerId := peer.ID(pid)
		l.memberStatusValidator.AddPeerId(pid)
		if l.host.ConnMgr().IsConnected(peerId) {
			conn := l.host.ConnMgr().GetPeerConn(peerId)
			_ = conn.Close()
			log.Infof("[LiquidNet] [closeRevokedPeerConnection] closing revoked peer connection(pid: %s)", pid)
		}
	}
	return nil
}

// AddAC add a AccessControlProvider for revoked validator.
func (l *LiquidNet) AddAC(chainId string, ac api.AccessControlProvider) {
	l.memberStatusValidator.AddAC(chainId, ac)
}

// SetMsgPriority set the priority of the msg flag.
// If priority control disabled, it is no-op.
func (l *LiquidNet) SetMsgPriority(msgFlag string, priority uint8) {
	if l.priorityController != nil {
		l.priorityController.SetPriority(msgFlag, priorityblocker.Priority(priority))
	}
}
