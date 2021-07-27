/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocoldiscovery

// if you want to run discovery test just uncomment .

/*
import (
	"context"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/discovery"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/util"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/logger"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/tlssupport"
	"chainmaker.org/chainmaker/common/crypto"
	"chainmaker.org/chainmaker/common/crypto/asym"
	"chainmaker.org/chainmaker/common/helper"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

var (
	chainIds = []string{
		"chain1",
		"chain2",
		"chain3",
		"chain4",
	}

	log = logger.NewLogPrinter("TEST")
)

func listenFindingC(ctx context.Context, idx int, h host.Host, c <-chan ma.Multiaddr) {
	for {
		select {
		case <-ctx.Done():
			return
		case ai := <-c:
			addr, pid := util.GetNetAddrAndPidFromNormalMultiAddr(ai)
			if pid == "" {
				log.Errorf("[Discovery%d] peer id not contains in addr", idx)
				continue
			}
			if h.ConnMgr().PeerCount() >= h.ConnMgr().MaxPeerCountAllowed() || h.ID() == pid || h.ConnMgr().IsConnected(pid) {
				continue
			}
			log.Infof("[Discovery%d] find new peer.(pid: %s, addr: %s)", idx, pid, addr.String())
			_, _ = h.Dial(ai)
		}
	}
}

func TestProtocolBasedDiscovery(t *testing.T) {
	hostCount := 20

	sks := make([]crypto.PrivateKey, hostCount)
	addrs := make([]ma.Multiaddr, hostCount)
	pids := make([]peer.ID, hostCount)
	hosts := make([]host.Host, hostCount)

	commonSeeds := make(map[peer.ID]ma.Multiaddr)
	emptySeeds := make(map[peer.ID]ma.Multiaddr)

	discoveries := make([]discovery.Discoverer, hostCount)
	cancelFuncs := make([]context.CancelFunc, hostCount)
	findCs := make([]<-chan ma.Multiaddr, hostCount)

	chainPeer := make(map[string]map[peer.ID]struct{})
	peerChains := make(map[peer.ID]map[string]struct{})
	peerToPeers := make(map[peer.ID]map[peer.ID]struct{})
	for i := 0; i < hostCount; i++ {
		sk, err := asym.GenerateKeyPair(crypto.RSA2048)
		require.Nil(t, err)
		sks[i] = sk
		pidStr, err := helper.CreateLibp2pPeerIdWithPrivateKey(sk)
		require.Nil(t, err)
		pid := peer.ID(pidStr)
		pids[i] = pid
		addr := util.CreateMultiAddrWithPidAndNetAddr(pid, ma.StringCast("/ip4/127.0.0.1/tcp/"+strconv.Itoa(9000+i)))
		addrs[i] = addr
		peerChains[pid] = make(map[string]struct{})
		peerToPeers[pid] = make(map[peer.ID]struct{})
		if i == 0 {
			commonSeeds[pid] = addr
			for j := 0; j < len(chainIds); j++ {
				chainPeer[chainIds[j]] = make(map[peer.ID]struct{})
				chainPeer[chainIds[j]][pid] = struct{}{}
				peerChains[pid][chainIds[j]] = struct{}{}
			}
		} else {
			rand.Seed(time.Now().UnixNano())
			for j := 0; j < len(chainIds); j++ {
				r := rand.Intn(len(chainIds))
				chainPeer[chainIds[r]][pid] = struct{}{}
				peerChains[pid][chainIds[r]] = struct{}{}
			}
		}
	}

	for i := 0; i < hostCount; i++ {
		for chainId := range peerChains[pids[i]] {
			for id := range chainPeer[chainId] {
				peerToPeers[pids[i]][id] = struct{}{}
			}
		}
		peerToPeers[pids[i]][pids[0]] = struct{}{}
		peerToPeers[pids[i]][pids[i]] = struct{}{}
	}

	wg := sync.WaitGroup{}
	wg.Add(hostCount)

	for i := 0; i < hostCount; i++ {
		seeds := commonSeeds
		if i == 0 {
			seeds = emptySeeds
		}
		h, _, _, err := tlssupport.CreateHostWithCrypto(i, "127.0.0.1", sks[i], seeds, log)
		require.Nil(t, err)
		err = h.Start()
		require.Nil(t, err)
		hosts[i] = h

		go func(idx int) {
			count := hostCount - 1
			if idx > 0 {
				count = len(peerToPeers[pids[idx-1]]) - 1
			}
			log.Infof("[%d] total count: %d", idx, count)
			for {
				if h.ConnMgr().PeerCount() >= count {
					wg.Done()
					log.Infof("[%d] finish all, count: %d", idx, count)
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
		}(i + 1)

		dis, err := NewProtocolBasedDiscovery(h, WithFindingTickerInterval(time.Second), WithLogger(logger.NewLogPrinter("D"+strconv.Itoa(i+1))))
		require.Nil(t, err)
		discoveries[i] = dis
		for chainId := range peerChains[pids[i]] {
			err = dis.Announce(nil, chainId)
			require.Nil(t, err)
			ctx, ctxCancel := context.WithCancel(context.Background())
			cancelFuncs[i] = ctxCancel
			findC, err := dis.FindPeers(ctx, chainId)
			require.Nil(t, err)
			findCs[i] = findC

			go listenFindingC(ctx, i+1, h, findC)
		}

	}
	finishC := make(chan struct{})
	go func() {
		wg.Wait()
		close(finishC)
	}()
	timer := time.NewTimer(30 * time.Second)
	select {
	case <-timer.C:
		t.Fatal("timeout")
	case <-finishC:
		break
	}
	log.Infof("PASS!")
}*/
