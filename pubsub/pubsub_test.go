/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"fmt"
	"testing"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/logger"
	"chainmaker.org/chainmaker/net-liquid/tlssupport"
	"github.com/stretchr/testify/require"
)

const msg = "Hello!My first PubSub program demo."

var (
	chainIds = []string{
		"chain1",
		"chain2",
		"chain3",
	}

	topics = []string{
		"topic1",
		"topic2",
		"topic3",
	}

	ip = "0.0.0.0"

	log = logger.NewLogPrinter("TEST")
)

func TestNewChainPubSub(t *testing.T) {
	h, _, _, err := tlssupport.CreateHostRandom(0, ip, nil, log)
	require.Nil(t, err)
	ps := NewChainPubSub(chainIds[0], log)
	err = ps.AttachHost(h)
	require.Nil(t, err)
	err = h.Start()
	require.Nil(t, err)
	_ = h.Stop()
}

func TestChainPubSubAllMetadataOnlyPeers(t *testing.T) {
	h, _, _, err := tlssupport.CreateHostRandom(1, ip, nil, log)
	require.Nil(t, err)
	ps := NewChainPubSub(chainIds[0], log)
	err = ps.AttachHost(h)
	require.Nil(t, err)
	err = h.Start()
	require.Nil(t, err)
	ps.AllMetadataOnlyPeers()
	_ = h.Stop()
}

func TestChainPubSubSubscribeAndUnsubscribe(t *testing.T) {
	h, _, _, err := tlssupport.CreateHostRandom(2, ip, nil, log)
	require.Nil(t, err)
	ps := NewChainPubSub(chainIds[0], log)
	err = ps.AttachHost(h)
	require.Nil(t, err)
	err = h.Start()
	require.Nil(t, err)
	ps.Subscribe(topics[0], func(publisher peer.ID, topic string, msg []byte) {
		fmt.Printf("receive msg from topic -> publisher:%s, topic:%s, msg: %s", publisher, topic, string(msg))
	})
	ps.Unsubscribe(topics[0])
	_ = h.Stop()
}

func TestChainPubSubPublish(t *testing.T) {
	h, _, _, err := tlssupport.CreateHostRandom(3, ip, nil, log)
	require.Nil(t, err)
	ps := NewChainPubSub(chainIds[0], log)
	err = ps.AttachHost(h)
	require.Nil(t, err)
	err = h.Start()
	require.Nil(t, err)
	ps.Publish(topics[0], []byte(msg))
	_ = h.Stop()
}

//
//func TestChainPubSubMessageBroadcast(t *testing.T) {
//	sendCount := 100
//	nodeCount := 20
//
//	sks := make([]crypto.PrivateKey, nodeCount)
//	addrs := make([]ma.Multiaddr, nodeCount)
//	pids := make([]peer.ID, nodeCount)
//	hosts := make([]host.Host, nodeCount)
//	pubsubs := make([]broadcast.PubSub, nodeCount)
//	msgReceivedLog := make([][]bool, nodeCount)
//	seeds := make(map[peer.ID]ma.Multiaddr)
//	for i := 0; i < nodeCount; i++ {
//		seq := i + 10
//		sk, err := asym.GenerateKeyPair(crypto.RSA2048)
//		require.Nil(t, err)
//		sks[i] = sk
//		pidStr, err := helper.CreateLibp2pPeerIdWithPrivateKey(sk)
//		require.Nil(t, err)
//		pid := peer.ID(pidStr)
//		pids[i] = pid
//		addr := util.CreateMultiAddrWithPidAndNetAddr(pid, ma.StringCast("/ip4/127.0.0.1/tcp/"+strconv.Itoa(9000+seq)))
//		addrs[i] = addr
//		seeds[pid] = addr
//		msgReceivedLog[i] = make([]bool, sendCount)
//	}
//
//	for i := 0; i < nodeCount; i++ {
//		//avoid use same port
//		seq := i + 10
//		h, _, _, err := tlssupport.CreateHostWithCrypto(seq, ip, sks[i], seeds, logger.NewLogPrinter("HOST_"+strconv.Itoa(i+1)))
//		require.Nil(t, err)
//		err = h.Start()
//		require.Nil(t, err)
//		hosts[i] = h
//
//		seqStr := strconv.Itoa(i + 1)
//		ps := NewChainPubSub(
//			chainIds[0],
//			logger.NewLogPrinter("PS"+seqStr),
//			//WithGossipSize(1),
//			WithDegreeLow(1),
//			WithDegreeDesired(2),
//			WithDegreeHigh(3),
//			WithAppMsgCacheMaxSize(100),
//			WithAppMsgCacheTimeout(1*time.Minute),
//			WithMetadataCacheMaxSize(500),
//			WithMetadataCacheTimeout(5*time.Minute),
//		)
//		err = ps.AttachHost(hosts[i])
//		require.Nil(t, err)
//		pubsubs[i] = ps
//		idx := i
//		ps.Subscribe(topics[0], func(publisher peer.ID, topic string, msg []byte) {
//			num := getNumber(msg)
//			msgReceivedLog[idx][num] = true
//		})
//	}
//
//	time.Sleep(3 * time.Second)
//
//	for i := 0; i < sendCount; i++ {
//		pubsubs[0].Publish(topics[0], []byte(msg+strconv.Itoa(i)))
//	}
//	timeoutTimer := time.NewTimer(time.Minute)
//	ticker := time.NewTicker(time.Second)
//	for {
//		select {
//		case <-timeoutTimer.C:
//			t.Fatal("timeout")
//		case <-ticker.C:
//			printNotRevice(msgReceivedLog...)
//			if allSuccess(msgReceivedLog...) {
//				return
//			}
//		}
//	}
//}
//
//func TestChainPubsubMessageCount(t *testing.T) {
//	sendCount := 3000
//	nodeCount := 7
//
//	sks := make([]crypto.PrivateKey, nodeCount)
//	addrs := make([]ma.Multiaddr, nodeCount)
//	pids := make([]peer.ID, nodeCount)
//	hosts := make([]host.Host, nodeCount)
//	pubsubs := make([]broadcast.PubSub, nodeCount)
//	msgReceivedLog := make([][]int, nodeCount)
//	seeds := make(map[peer.ID]ma.Multiaddr)
//	for i := 0; i < nodeCount; i++ {
//		seq := i + 100
//		sk, err := asym.GenerateKeyPair(crypto.RSA2048)
//		require.Nil(t, err)
//		sks[i] = sk
//		pidStr, err := helper.CreateLibp2pPeerIdWithPrivateKey(sk)
//		require.Nil(t, err)
//		pid := peer.ID(pidStr)
//		pids[i] = pid
//		addr := util.CreateMultiAddrWithPidAndNetAddr(pid, ma.StringCast("/ip4/127.0.0.1/tcp/"+strconv.Itoa(9000+seq)))
//		addrs[i] = addr
//		seeds[pid] = addr
//		msgReceivedLog[i] = make([]int, sendCount)
//	}
//
//	for i := 0; i < nodeCount; i++ {
//		seq := i + 100
//		h, _, _, err := tlssupport.CreateHostWithCrypto(seq, ip, sks[i], seeds, logger.NewLogPrinter("HOST_"+strconv.Itoa(i+1)))
//		require.Nil(t, err)
//		err = h.Start()
//		require.Nil(t, err)
//		hosts[i] = h
//
//		seqStr := strconv.Itoa(i + 1)
//		ps := NewChainPubSub(
//			chainIds[0],
//			logger.NewLogPrinter("PS_"+seqStr),
//			WithGossipSize(2),
//			WithDegreeLow(1),
//			WithDegreeDesired(2),
//			WithDegreeHigh(3),
//			WithAppMsgCacheMaxSize(sendCount*10),
//			WithAppMsgCacheTimeout(2*time.Minute),
//			WithMetadataCacheMaxSize(sendCount*10),
//			WithMetadataCacheTimeout(5*time.Minute),
//		)
//		err = ps.AttachHost(hosts[i])
//		require.Nil(t, err)
//		pubsubs[i] = ps
//	}
//
//	time.Sleep(3 * time.Second)
//	for i := 0; i < nodeCount; i++ {
//		idx := i
//		pubsubs[i].Subscribe(topics[0], func(publisher peer.ID, topic string, msg []byte) {
//			num := getNumber(msg)
//			msgReceivedLog[idx][num] = msgReceivedLog[idx][num] + 1
//		})
//	}
//
//	time.Sleep(3 * time.Second)
//
//	for i := 0; i < sendCount; i++ {
//		pubsubs[0].Publish(topics[0], []byte(msg+strconv.Itoa(i)))
//	}
//
//	timeoutTimer := time.NewTimer(time.Minute)
//	ticker := time.NewTicker(time.Second)
//	for {
//		select {
//		case <-timeoutTimer.C:
//			t.Fatal("timeout")
//		case <-ticker.C:
//			printNotReviceInt(msgReceivedLog...)
//			if allSuccessInt(msgReceivedLog...) {
//				return
//			}
//		}
//	}
//}
//
//func getNumber(msg []byte) int {
//	result, _ := strconv.Atoi(strings.Split(string(msg), ".")[1])
//	return result
//}
//
//func printNotRevice(hx ...[]bool) {
//	for i := range hx {
//		if i == 0 {
//			continue
//		}
//		print("host"+strconv.Itoa(i+1), hx[i])
//	}
//}
//
//func allSuccess(hx ...[]bool) bool {
//	for i := range hx {
//		if i == 0 {
//			continue
//		}
//		for _, v := range hx[i] {
//			if !v {
//				return false
//			}
//		}
//	}
//	return true
//}
//
//func printNotReviceInt(hx ...[]int) {
//	for i := range hx {
//		if i == 0 {
//			continue
//		}
//		printInt("host"+strconv.Itoa(i+1), hx[i])
//	}
//}
//
//func allSuccessInt(hx ...[]int) bool {
//	for i := range hx {
//		if i == 0 {
//			continue
//		}
//		for _, v := range hx[i] {
//			if v == 0 {
//				return false
//			}
//		}
//	}
//	printRepeatInfo(hx...)
//	return true
//}
//
//func printRepeatInfo(hx ...[]int) {
//	for i := range hx {
//		if i == 0 {
//			continue
//		}
//		result := make([]string, 0)
//		for _, v := range hx[i] {
//			if v > 1 {
//				result = append(result, strconv.Itoa(v))
//			}
//		}
//		fmt.Println(strings.Join(result, ","))
//	}
//}
//
//func printInt(name string, h []int) {
//	result := make([]string, 0)
//	result = append(result, name)
//	for index, v := range h {
//		if v == 0 {
//			result = append(result, strconv.Itoa(index))
//		}
//	}
//	fmt.Println(strings.Join(result, ","))
//}
//
//func TestChainPubsubMessageBroadcastCases(t *testing.T) {
//	nodeCount := 7
//	var err error
//	var pids = make([]peer.ID, nodeCount, nodeCount)
//	var addrs = make([]ma.Multiaddr, nodeCount, nodeCount)
//	var hosts = make([]host.Host, nodeCount, nodeCount)
//	for i := 0; i < 7; i++ {
//		seq := i + 200
//		hosts[i], pids[i], addrs[i], err = tlssupport.CreateHostRandom(seq, "127.0.0.1", nil, log)
//		require.Nil(t, err)
//	}
//	seeds := make([]map[peer.ID]ma.Multiaddr, nodeCount, nodeCount)
//
//	// node1 link node2,node7
//	seeds0 := map[peer.ID]ma.Multiaddr{
//		pids[1]: addrs[1],
//		pids[6]: addrs[6],
//	}
//	seeds[0] = seeds0
//
//	// node2 link node1,node3,node4,node5,node6
//	seeds1 := map[peer.ID]ma.Multiaddr{
//		pids[0]: addrs[0],
//		pids[2]: addrs[2],
//		pids[3]: addrs[3],
//		pids[4]: addrs[4],
//		pids[5]: addrs[5],
//	}
//	seeds[1] = seeds1
//
//	// node3 link node2,node7
//	seeds2 := map[peer.ID]ma.Multiaddr{
//		pids[1]: addrs[1],
//		pids[6]: addrs[6],
//	}
//	seeds[2] = seeds2
//
//	// node4 link node2
//	seeds3 := map[peer.ID]ma.Multiaddr{
//		pids[1]: addrs[1],
//	}
//	seeds[3] = seeds3
//
//	// node5 link node2
//	seeds4 := map[peer.ID]ma.Multiaddr{
//		pids[1]: addrs[1],
//	}
//	seeds[4] = seeds4
//
//	// node6 link node2
//	seeds5 := map[peer.ID]ma.Multiaddr{
//		pids[1]: addrs[1],
//	}
//	seeds[5] = seeds5
//
//	// node7 link node1,node3
//	seeds6 := map[peer.ID]ma.Multiaddr{
//		pids[0]: addrs[0],
//		pids[2]: addrs[2],
//	}
//	seeds[6] = seeds6
//
//	pubsubs := make([]broadcast.PubSub, nodeCount, nodeCount)
//	for i := 0; i < nodeCount; i++ {
//		h := hosts[i]
//		err = h.Start()
//		require.Nil(t, err)
//
//		for id, mA := range seeds[i] {
//			directAddr := util.CreateMultiAddrWithPidAndNetAddr(id, mA)
//			h.AddDirectPeer(directAddr)
//		}
//
//		seqStr := strconv.Itoa(i + 1)
//		ps := NewChainPubSub(
//			chainIds[0],
//			logger.NewLogPrinter("PS"+seqStr),
//			//WithGossipSize(1),
//			//WithDegreeLow(1),
//			//WithDegreeDesired(2),
//			//WithDegreeHigh(3),
//			//WithAppMsgCacheMaxSize(100),
//			//WithAppMsgCacheTimeout(1*time.Minute),
//			//WithMetadataCacheMaxSize(500),
//			//WithMetadataCacheTimeout(5*time.Minute),
//		)
//		err = ps.AttachHost(hosts[i])
//		require.Nil(t, err)
//		pubsubs[i] = ps
//		//idx := i
//		//ps.Subscribe(topics[0], func(topic string, msg []byte) {
//		//	num := getNumber(msg)
//		//	msgReceivedLog[idx][num] = true
//		//	fmt.Printf("PS%s receive msg from topic -> topic:%s, msg:%s\n", seqStr, topic, string(msg))
//		//})
//	}
//
//	resMap := map[int]int{
//		0: 0,
//		1: 0,
//		2: 0,
//		3: 0,
//		4: 0,
//		5: 0,
//		6: 0,
//	}
//
//	resetResMap := func() {
//		for i := range resMap {
//			resMap[i] = 0
//		}
//	}
//
//	wg := sync.WaitGroup{}
//	createSubMsgHandler := func(idx int) handler.SubMsgHandler {
//		seqStr := strconv.Itoa(idx + 1)
//		return func(publisher peer.ID, topic string, msg []byte) {
//			num := getNumber(msg)
//			log.Infof("PS%s receive msg from topic -> publisher:%s, topic:%s, msg:%s", seqStr, publisher, topic, string(msg))
//			resMap[idx] = num
//			wg.Done()
//		}
//	}
//
//	// node1 sub topic2,3
//	pubsubs[0].Subscribe(topics[1], createSubMsgHandler(0))
//	pubsubs[0].Subscribe(topics[2], createSubMsgHandler(0))
//
//	// node2 sub topic1,3
//	pubsubs[1].Subscribe(topics[0], createSubMsgHandler(1))
//	pubsubs[1].Subscribe(topics[2], createSubMsgHandler(1))
//
//	// node3 sub topic1
//	pubsubs[2].Subscribe(topics[0], createSubMsgHandler(2))
//	// node4 sub topic1
//	pubsubs[3].Subscribe(topics[0], createSubMsgHandler(3))
//	// node5 sub topic1
//	pubsubs[4].Subscribe(topics[0], createSubMsgHandler(4))
//	// node6 sub topic1
//	pubsubs[5].Subscribe(topics[0], createSubMsgHandler(5))
//
//	// node7 sub topic3
//	pubsubs[6].Subscribe(topics[2], createSubMsgHandler(6))
//
//	time.Sleep(5 * time.Second)
//
//	signalC := make(chan struct{}, 1)
//	// case1
//	// node2 send a msg to topic1
//	wg.Add(4)
//	pubsubs[1].Publish(topics[0], []byte(msg+"1"))
//	go func() {
//		wg.Wait()
//		signalC <- struct{}{}
//	}()
//	timer := time.NewTimer(10 * time.Second)
//	select {
//	case <-timer.C:
//		t.Fatalf("case1 timeout")
//	case <-signalC:
//		require.True(t, resMap[0] == 0)
//		require.True(t, resMap[1] == 0)
//		require.True(t, resMap[2] == 1)
//		require.True(t, resMap[3] == 1)
//		require.True(t, resMap[4] == 1)
//		require.True(t, resMap[5] == 1)
//		require.True(t, resMap[6] == 0)
//		fmt.Printf("==== case1 pass ====\n")
//	}
//
//	// case2
//	// node2 send a msg to topic2
//	resetResMap()
//	wg = sync.WaitGroup{}
//	wg.Add(1)
//	pubsubs[1].Publish(topics[1], []byte(msg+"2"))
//	go func() {
//		wg.Wait()
//		signalC <- struct{}{}
//	}()
//	timer = time.NewTimer(5 * time.Second)
//	select {
//	case <-timer.C:
//		t.Fatalf("case2 timeout")
//	case <-signalC:
//		require.True(t, resMap[0] == 2)
//		require.True(t, resMap[1] == 0)
//		require.True(t, resMap[2] == 0)
//		require.True(t, resMap[3] == 0)
//		require.True(t, resMap[4] == 0)
//		require.True(t, resMap[5] == 0)
//		require.True(t, resMap[6] == 0)
//		fmt.Printf("==== case2 pass ====\n")
//	}
//
//	// case3
//	// node3 send a msg to topic3
//	resetResMap()
//	wg = sync.WaitGroup{}
//	wg.Add(3)
//	pubsubs[2].Publish(topics[2], []byte(msg+"3"))
//	go func() {
//		wg.Wait()
//		signalC <- struct{}{}
//	}()
//	timer = time.NewTimer(5 * time.Second)
//	select {
//	case <-timer.C:
//		t.Fatalf("case3 timeout")
//	case <-signalC:
//		require.True(t, resMap[0] == 3)
//		require.True(t, resMap[1] == 3)
//		require.True(t, resMap[2] == 0)
//		require.True(t, resMap[3] == 0)
//		require.True(t, resMap[4] == 0)
//		require.True(t, resMap[5] == 0)
//		require.True(t, resMap[6] == 3)
//		fmt.Printf("==== case3 pass ====\n")
//	}
//}
