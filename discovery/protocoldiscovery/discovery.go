/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocoldiscovery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/discovery"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/handler"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/protocol"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/util"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/discovery/protocoldiscovery/pb"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/logger"
	api "chainmaker.org/chainmaker/protocol"
	"github.com/gogo/protobuf/proto"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	discoveryProtocolIDPrefix = "/chain-discovery/v0.0.1/"
	// DefaultFindingHeartbeat is the default heartbeat interval.
	DefaultFindingHeartbeat = time.Minute
	// DefaultMaxQuerySize is the default max query size when finding peers.
	DefaultMaxQuerySize = 10
	// DefaultQuerySize is the default size for finding from each others.
	DefaultQuerySize = 3

	optKeyTimeout   = "timeout"
	optKeyQuerySize = "query-size"
)

var (
	// ErrFinding will be returned if there is already a finding task running when calling FindPeers method.
	ErrFinding = errors.New("there is already a finding task running, try it again later")
)

type options struct {
	discovery.Options

	timeout time.Duration
	size    int
}

func (o *options) applyDiscoveryOptions(opts ...discovery.Option) error {
	err := o.Apply(opts...)
	if err != nil {
		return err
	}

	v, ok := o.Opts[optKeyTimeout]
	if ok {
		o.timeout, _ = v.(time.Duration)
	}

	v, ok = o.Opts[optKeyQuerySize]
	if ok {
		o.size, _ = v.(int)
	}

	return nil
}

// WithTimeout set a time.Duration as timeout for finding peers.
func WithTimeout(timeout time.Duration) discovery.Option {
	return func(options *discovery.Options) error {
		options.Opts[optKeyTimeout] = timeout
		return nil
	}
}

// WithQuerySize set an int value as default query size for finding peers.
func WithQuerySize(size int) discovery.Option {
	return func(options *discovery.Options) error {
		options.Opts[optKeyQuerySize] = size
		return nil
	}
}

// Option is a function to apply properties for discovery service.
type Option func(*ProtocolBasedDiscovery) error

func (d *ProtocolBasedDiscovery) applyOptions(opts ...Option) error {
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return err
		}
	}
	return nil
}

// WithLogger set a logger.
func WithLogger(logger api.Logger) Option {
	return func(d *ProtocolBasedDiscovery) error {
		d.logger = logger
		return nil
	}
}

// WithMaxQuerySize set an int value as default max query size for finding peers.
func WithMaxQuerySize(max int) Option {
	return func(d *ProtocolBasedDiscovery) error {
		d.maxQuerySize = max
		return nil
	}
}

// WithDefaultQueryTimeout set a time.Duration as default timeout for finding peers.
func WithDefaultQueryTimeout(timeout time.Duration) Option {
	return func(d *ProtocolBasedDiscovery) error {
		d.defaultQueryTimeout = timeout
		return nil
	}
}

// WithFindingTickerInterval set a time.Duration as interval for finding task heartbeat.
func WithFindingTickerInterval(interval time.Duration) Option {
	return func(d *ProtocolBasedDiscovery) error {
		d.findingTickerInterval = interval
		return nil
	}
}

var _ discovery.Discovery = (*ProtocolBasedDiscovery)(nil)

// ProtocolBasedDiscovery provides a discovery service based on protocols supported.
type ProtocolBasedDiscovery struct {
	host host.Host

	svcMap       sync.Map // map[string]struct{}, stores service name announced by myself
	findingMap   sync.Map // map[string]*chan network.AddrInfo, stores task of finding service
	findingWgMap sync.Map // map[string]*sync.WaitGroup , stores wait group for task

	maxQuerySize          int
	defaultQueryTimeout   time.Duration
	findingTickerInterval time.Duration

	logger api.Logger
}

// NewProtocolBasedDiscovery create a new ProtocolBasedDiscovery instance.
func NewProtocolBasedDiscovery(host host.Host, opts ...Option) (*ProtocolBasedDiscovery, error) {
	d := &ProtocolBasedDiscovery{
		host:                  host,
		svcMap:                sync.Map{},
		findingMap:            sync.Map{},
		findingWgMap:          sync.Map{},
		maxQuerySize:          DefaultMaxQuerySize,
		defaultQueryTimeout:   0,
		findingTickerInterval: DefaultFindingHeartbeat,
		logger:                logger.NilLogger,
	}
	if err := d.applyOptions(opts...); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *ProtocolBasedDiscovery) createProtocolIDWithServiceName(serviceName string) protocol.ID {
	return protocol.ID(discoveryProtocolIDPrefix + serviceName)
}

func (d *ProtocolBasedDiscovery) handlerFindReq(senderPID peer.ID, msg *pb.DiscoveryMsg, protocol protocol.ID) {
	// finding request type msg
	// read peers known by finder
	knownPeersMap := make(map[peer.ID]struct{})
	knownPeersMap[senderPID] = struct{}{}
	for i := range msg.PInfos {
		knownPeersMap[peer.ID(msg.PInfos[i].Pid)] = struct{}{}
	}
	// get query size
	querySize := int(msg.Size_)
	if querySize > d.maxQuerySize {
		querySize = d.maxQuerySize
	}
	foundSize := 0
	// get all peers who support protocol
	peersFound := d.host.PeerStore().AllSupportProtocolPeers(protocol)
	pInfoList := make([]*pb.PeerInfo, 0, len(peersFound))
	for i := range peersFound {
		pid := peersFound[i]
		if _, ok := knownPeersMap[pid]; ok {
			// if known by finder , ignore
			continue
		}
		pNetworkAddr := d.host.PeerStore().GetFirstAddr(pid)
		if pNetworkAddr == nil {
			// if no addr found , ignore
			continue
		}
		// append peer address to result
		pNetworkAddr = util.CreateMultiAddrWithPidAndNetAddr(pid, pNetworkAddr)
		pInfoList = append(pInfoList, &pb.PeerInfo{
			Pid:  pid.ToString(),
			Addr: pNetworkAddr.String(),
		})
		foundSize++
		// whether enough peers found
		if foundSize >= querySize {
			break
		}
	}
	// send find-response msg to finder
	m := &pb.DiscoveryMsg{
		Type:   pb.DiscoveryMsg_FindRes,
		PInfos: pInfoList,
	}
	msgBytes, e := proto.Marshal(m)
	if e != nil {
		d.logger.Errorf("marshal discovery msg failed, %s", e.Error())
		return
	}
	e = d.host.SendMsg(protocol, senderPID, msgBytes)
	if e != nil {
		d.logger.Debugf("send discovery find response msg failed, %s (remote pid: %s)", e.Error(), senderPID)
		return
	}
}

func (d *ProtocolBasedDiscovery) handlerFindRes(serviceName string, msg *pb.DiscoveryMsg) {
	// finding response type msg
	// whether not found
	if len(msg.PInfos) == 0 {
		// do nothing
		return
	}
	// whether finding task exist
	v, ok := d.findingMap.Load(serviceName)
	if !ok {
		// finding task not found , do nothing
		return
	}
	// push addresses of peers found to result chan
	c := v.(chan ma.Multiaddr)
	for i := range msg.PInfos {
		pInfo := msg.PInfos[i]
		pid := peer.ID(pInfo.Pid)
		if d.host.ConnMgr().IsConnected(pid) || !d.host.ConnMgr().IsAllowed(pid) || d.host.ID() == pid {
			// if peer connected or not allowed or its myself, ignore.
			continue
		}
		// push addr to finding out chan
		mAddr, err := ma.NewMultiaddr(pInfo.Addr)
		if err != nil {
			d.logger.Errorf("not a effective addr, %s", err.Error())
			continue
		}
		c <- mAddr
	}
}

func (d *ProtocolBasedDiscovery) createProtocolMsgHandler(serviceName string, protocol protocol.ID) handler.MsgPayloadHandler {
	return func(senderPID peer.ID, msgPayload []byte) {
		// parse payload as DiscoveryMsg
		msg := &pb.DiscoveryMsg{}
		err := proto.Unmarshal(msgPayload, msg)
		if err != nil {
			d.logger.Errorf("unmarshal discovery msg failed, %s", err.Error())
			return
		}
		// switch msg type
		switch msg.Type {
		case pb.DiscoveryMsg_Announce:
			// announce type msg
			if len(msg.PInfos) == 0 {
				d.logger.Warnf("nil or empty pid. (msg type: %s)", pb.DiscoveryMsg_Announce.String())
				return
			}
			// load peer.ID
			newSupportPid := peer.ID(msg.PInfos[0].Pid)
			// if i have the addr info of peer, add this protocol to the list that peer supported
			if d.host.PeerStore().GetFirstAddr(newSupportPid) != nil {
				d.host.PeerStore().AddProtocol(newSupportPid, protocol)
			}
		case pb.DiscoveryMsg_FindReq:
			d.handlerFindReq(senderPID, msg, protocol)
		case pb.DiscoveryMsg_FindRes:
			d.handlerFindRes(serviceName, msg)
		default:
			d.logger.Warnf("unknown discovery msg type")
		}
	}
}

// Announce tell other peers that I have supported a new service with name given.
func (d *ProtocolBasedDiscovery) Announce(_ context.Context, serviceName string, _ ...discovery.Option) error {
	serviceName = strings.TrimSpace(serviceName)
	// create protocol ID
	protoID := d.createProtocolIDWithServiceName(serviceName)
	_, ok := d.svcMap.Load(serviceName)
	if !ok {
		// create protocol msg handler
		h := d.createProtocolMsgHandler(serviceName, protoID)
		// register discovery protocol to host
		err := d.host.RegisterMsgPayloadHandler(protoID, h)
		if err != nil {
			return err
		}
		d.svcMap.Store(serviceName, struct{}{})
	}

	// send announce msg to all peer which support this protocol
	allPeers, err := d.host.PeerProtocols([]protocol.ID{protoID})
	if err != nil {
		return err
	}
	if allPeers == nil || len(allPeers) == 0 {
		return nil
	}
	msg := &pb.DiscoveryMsg{
		Type: pb.DiscoveryMsg_Announce,
		PInfos: []*pb.PeerInfo{
			{
				Pid:  d.host.ID().ToString(),
				Addr: "",
			},
		},
	}
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		d.logger.Errorf("marshal discovery msg failed, %s", err.Error())
		return err
	}
	for i := range allPeers {
		peerProto := allPeers[i]
		rPid := peerProto.PID
		go func() {
			e := d.host.SendMsg(protoID, rPid, msgBytes)
			if e != nil {
				d.logger.Warnf("send discovery announce msg failed, %s", err.Error())
			}
		}()
	}
	return nil
}

func (d *ProtocolBasedDiscovery) sendFindReqMsgToOthers(protocol protocol.ID, querySize int) {
	// get all peers who support this protocol
	peersFound := d.host.PeerStore().AllSupportProtocolPeers(protocol)
	peersFoundLen := len(peersFound)
	if peersFoundLen == 0 {
		d.logger.Debugf("no peer support protocol %s", protocol)
		return
	}
	// create discovery msg with find-request type
	pInfos := make([]*pb.PeerInfo, peersFoundLen)
	for i := range peersFound {
		pInfos[i] = &pb.PeerInfo{Pid: peersFound[i].ToString()}
	}
	msg := &pb.DiscoveryMsg{
		Type:   pb.DiscoveryMsg_FindReq,
		PInfos: pInfos,
		Size_:  uint32(querySize),
	}
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		d.logger.Errorf("marshal discovery msg failed, %s", err.Error())
		return
	}
	// send msg to peers found
	for i := range peersFound {
		err = d.host.SendMsg(protocol, peersFound[i], msgBytes)
		if err != nil {
			d.logger.Debugf("send discovery find request msg failed, %s, peer:%s", err.Error(), peersFound[i])
			return
		}
	}
}

func (d *ProtocolBasedDiscovery) findPeersTask(ctx context.Context, serviceName string, opts ...discovery.Option) {
	defer d.findingMap.Delete(serviceName)
	// apply options
	os := &options{Options: discovery.Options{Opts: make(map[interface{}]interface{})}}
	if err := os.applyDiscoveryOptions(opts...); err != nil {
		d.logger.Errorf("apply options failed, %s", err.Error())
		return
	}
	querySize := os.size
	if querySize == 0 {
		querySize = DefaultQuerySize
	}
	timeout := os.timeout
	if timeout == 0 {
		timeout = d.defaultQueryTimeout
	}

	// create protocol ID
	protoID := d.createProtocolIDWithServiceName(serviceName)
	// run a loop with a ticker
	ticker := time.NewTicker(time.Second)
	if timeout > 0 {
		// if timout option was set, use a timer to control loop exit ether
		timer := time.NewTimer(timeout)
		for {
			select {
			case <-timer.C:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if d.host.ConnMgr().PeerCount() >= d.host.ConnMgr().MaxPeerCountAllowed() {
					// if count of peer connected reach the max value, ignore
					continue
				}
				// send finding request msg to others
				d.sendFindReqMsgToOthers(protoID, querySize)
				ticker.Reset(d.findingTickerInterval)
			}
		}
	} else {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if d.host.ConnMgr().PeerCount() >= d.host.ConnMgr().MaxPeerCountAllowed() {
					// if count of peer connected reach the max value, ignore
					continue
				}
				// send finding request msg to others
				d.sendFindReqMsgToOthers(protoID, querySize)
				ticker.Reset(d.findingTickerInterval)
			}
		}
	}
}

// FindPeers run a loop task to find peers, and addresses of peers found will be push to result chan.
// If you want to quit finding task, the ctx should be canceled.
func (d *ProtocolBasedDiscovery) FindPeers(ctx context.Context, serviceName string, opts ...discovery.Option) (<-chan ma.Multiaddr, error) {
	serviceName = strings.TrimSpace(serviceName)
	// create finding chan
	findingC := make(chan ma.Multiaddr)
	_, ok := d.findingMap.LoadOrStore(serviceName, findingC)
	if ok {
		return nil, ErrFinding
	}

	go d.findPeersTask(ctx, serviceName, opts...)

	return findingC, nil
}
