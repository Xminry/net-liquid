/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package host

import (
	"chainmaker.org/chainmaker/common/crypto/asym"
	"context"
	"crypto/tls"
	"crypto/x509"
	"strconv"
	"testing"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/protocol"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/logger"
	"chainmaker.org/chainmaker/common/helper"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

var (
	addrsTcp = []ma.Multiaddr{
		ma.StringCast("/ip4/127.0.0.1/tcp/8081"),
		ma.StringCast("/ip4/0.0.0.0/tcp/8082"),
		ma.StringCast("/ip4/127.0.0.1/tcp/8083"),
		ma.StringCast("/ip4/127.0.0.1/tcp/8084"),
	}
	addr2TargetTcp = ma.StringCast("/ip4/127.0.0.1/tcp/8082")
)

func CreateHostTCP(idx int, seeds map[peer.ID]ma.Multiaddr) (host.Host, error) {
	certPool := x509.NewCertPool()
	for i := range certPEMs {
		certPool.AppendCertsFromPEM(certPEMs[i])
	}
	sk, err := asym.PrivateKeyFromPEM(keyPEMs[idx], nil)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEMs[idx], keyPEMs[idx])
	if err != nil {
		return nil, err
	}
	hostCfg := &HostConfig{
		TlsCfg: &tls.Config{
			Certificates:       []tls.Certificate{tlsCert},
			InsecureSkipVerify: true,
			ClientAuth:         tls.RequireAnyClientCert,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				tlsCertBytes := rawCerts[0]
				cert, err := x509.ParseCertificate(tlsCertBytes)
				if err != nil {
					return err
				}
				_, err = cert.Verify(x509.VerifyOptions{Roots: certPool})
				if err != nil {
					return err
				}
				return nil
			},
		},
		LoadPidFunc: func(certificates []*x509.Certificate) (peer.ID, error) {
			pid, err := helper.GetLibp2pPeerIdFromCertDer(certificates[0].Raw)
			if err != nil {
				return "", err
			}
			return peer.ID(pid), err
		},
		SendStreamPoolInitSize:    10,
		SendStreamPoolCap:         50,
		PeerReceiveStreamMaxCount: 100,
		ListenAddresses:           []ma.Multiaddr{addrsTcp[idx]},
		DirectPeers:               seeds,
		MsgCompress:               false,
		Insecurity:                false,
		PrivateKey:                sk,
	}

	return hostCfg.NewHost(TcpNetwork, context.Background(), logger.NewLogPrinter("HOST"+strconv.Itoa(idx)))
}

func TestHostTCP(t *testing.T) {
	// create host1
	host1, err := CreateHostTCP(0, map[peer.ID]ma.Multiaddr{pidList[1]: ma.Join(addr2TargetTcp, ma.StringCast("/p2p/"+pidList[1].ToString()))})
	require.Nil(t, err)

	// create host2
	host2, err := CreateHostTCP(1, map[peer.ID]ma.Multiaddr{pidList[0]: ma.Join(addrsTcp[0], ma.StringCast("/p2p/"+pidList[0].ToString()))})
	require.Nil(t, err)

	// register notifee
	connectC := make(chan struct{}, 2)
	disconnectC := make(chan struct{})
	protocolSupportC := make(chan struct{})
	protocolUnsupportedC := make(chan struct{})
	notifeeBundle := &host.NotifieeBundle{
		PeerConnectedFunc: func(id peer.ID) {
			connectC <- struct{}{}
		},
		PeerDisconnectedFunc: func(id peer.ID) {
			disconnectC <- struct{}{}
		},
		PeerProtocolSupportedFunc: func(protocolID protocol.ID, pid peer.ID) {
			protocolSupportC <- struct{}{}
		},
		PeerProtocolUnsupportedFunc: func(protocolID protocol.ID, pid peer.ID) {
			protocolUnsupportedC <- struct{}{}
		},
	}
	host1.Notify(notifeeBundle)
	host2.Notify(notifeeBundle)

	// start hosts
	err = host1.Start()
	require.Nil(t, err)
	err = host2.Start()
	require.Nil(t, err)

	// wait for connection established between host1 and host2
	timer := time.NewTimer(10 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-timer.C:
			t.Fatal("connection establish timeout")
		case <-connectC:
		}
	}

	// register msg payload handler
	receiveC := make(chan struct{})
	err = host1.RegisterMsgPayloadHandler(testProtocolID, func(senderPID peer.ID, msgPayload []byte) {
		receiveC <- struct{}{}
	})
	require.Nil(t, err)

	err = host2.RegisterMsgPayloadHandler(testProtocolID, func(senderPID peer.ID, msgPayload []byte) {
		receiveC <- struct{}{}
	})
	require.Nil(t, err)

	timer = time.NewTimer(5 * time.Second)
	for i := 0; i < 4; i++ {
		select {
		case <-timer.C:
			t.Fatal("push protocol supported timeout")
		case <-protocolSupportC:

		}
	}

	// host1 send msg to host2
	err = host1.SendMsg(testProtocolID, pidList[1], []byte(msg))
	require.Nil(t, err)
	timer = time.NewTimer(5 * time.Second)
	select {
	case <-timer.C:
		t.Fatal("host1 send msg to host2 timeout")
	case <-receiveC:

	}

	// host2 send msg to host1
	err = host2.SendMsg(testProtocolID, pidList[0], []byte(msg))
	require.Nil(t, err)
	timer = time.NewTimer(5 * time.Second)
	select {
	case <-timer.C:
		t.Fatal("host2 send msg to host1 timeout")
	case <-receiveC:

	}

	bl := host1.IsPeerSupportProtocol(host2.ID(), testProtocolID)
	require.True(t, bl)

	// unregister msg payload handler
	err = host2.UnregisterMsgPayloadHandler(testProtocolID)
	require.Nil(t, err)
	timer = time.NewTimer(5 * time.Second)
	select {
	case <-timer.C:
		t.Fatal("push protocol unsupported timeout")
	case <-protocolUnsupportedC:

	}

	bl = host1.IsPeerSupportProtocol(host2.ID(), testProtocolID)
	require.True(t, !bl)

	// stop host2
	err = host2.Stop()
	require.Nil(t, err)

	timer = time.NewTimer(5 * time.Second)
	select {
	case <-timer.C:
		t.Fatal("peer disconnect notify timeout")
	case <-disconnectC:

	}

	// stop host1
	err = host1.Stop()
	require.Nil(t, err)
}
