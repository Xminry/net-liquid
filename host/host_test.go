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

const msg = "Hello!My first LIQUID program demo."
const testProtocolID = "/test"

var (
	addrs = []ma.Multiaddr{
		ma.StringCast("/ip4/127.0.0.1/tcp/8081"),
		ma.StringCast("/ip4/0.0.0.0/tcp/8082"),
		ma.StringCast("/ip4/127.0.0.1/tcp/8083"),
		ma.StringCast("/ip4/127.0.0.1/tcp/8084"),
	}
	addr2Target = ma.StringCast("/ip4/127.0.0.1/tcp/8082")

	keyPEMs = [][]byte{
		[]byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIF4Sy4KANZHi8uU4YkmymbcbF3HHJnGgSjV/0iNOSdy3oAoGCCqGSM49\nAwEHoUQDQgAEKwemRhrzv5GSSmsy4EREhnQJ4jocauyWnD1dXUx9X8c4VwhG5hWQ\n7oc+cMyz6rXPKTrUxKD50V+OB0FVkpY7vA==\n-----END EC PRIVATE KEY-----\n"),
		[]byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIimV5TA1i8QWlp5nD5r5KmpueJV1hplp5y7Of4CYquzoAoGCCqGSM49\nAwEHoUQDQgAESZXYY4gziokaliXX5JkwT+idTCCwesjuJtTupABuhIqu7o2jt1V0\nNNWVvpShIM+878BaSb2v2TllwVoOYmfzPg==\n-----END EC PRIVATE KEY-----\n"),
		[]byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBOdWWD5V7dgz/q9PaQ3lyXddMuscws80fnI8Spo0PFYoAoGCCqGSM49\nAwEHoUQDQgAELUQWoVacLUfxlCHIc3OaosHj0MnnwV61i6z9ltBHLGB3vltuW29V\nt+vTgK2QregXLQUyzsS/w5dlpPyjwbMyrg==\n-----END EC PRIVATE KEY-----\n"),
		[]byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEINgBe8DaaKCq1lEaFZESgsO7P/AKY4/JAQP2AuSo5/Z7oAoGCCqGSM49\nAwEHoUQDQgAEIKj+wEWSH9bW62aBjhZInMasjkRg1zO7HYZhU4vxFZf8CPEYsCMJ\nuuCW9H0pmpKBBF316n3Gr/d7OdhL6QVBbA==\n-----END EC PRIVATE KEY-----\n"),
	}

	certPEMs = [][]byte{
		[]byte("-----BEGIN CERTIFICATE-----\nMIIDFTCCArugAwIBAgIDBOOCMAoGCCqGSM49BAMCMIGKMQswCQYDVQQGEwJDTjEQ\nMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEfMB0GA1UEChMWd3gt\nb3JnMS5jaGFpbm1ha2VyLm9yZzESMBAGA1UECxMJcm9vdC1jZXJ0MSIwIAYDVQQD\nExljYS53eC1vcmcxLmNoYWlubWFrZXIub3JnMB4XDTIwMTIwODA2NTM0M1oXDTI1\nMTIwNzA2NTM0M1owgZYxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAw\nDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQKExZ3eC1vcmcxLmNoYWlubWFrZXIub3Jn\nMRIwEAYDVQQLEwljb25zZW5zdXMxLjAsBgNVBAMTJWNvbnNlbnN1czEudGxzLnd4\nLW9yZzEuY2hhaW5tYWtlci5vcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQr\nB6ZGGvO/kZJKazLgRESGdAniOhxq7JacPV1dTH1fxzhXCEbmFZDuhz5wzLPqtc8p\nOtTEoPnRX44HQVWSlju8o4IBADCB/TAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgw\nBgYEVR0lADApBgNVHQ4EIgQgqzFBKQ6cAvTThFgrn//B/SDhAFEDfW5Y8MOE7hvY\nBf4wKwYDVR0jBCQwIoAgNSQ/cRy5t8Q1LpMfcMVzMfl0CcLZ4Pvf7BxQX9sQiWcw\nUQYDVR0RBEowSIIOY2hhaW5tYWtlci5vcmeCCWxvY2FsaG9zdIIlY29uc2Vuc3Vz\nMS50bHMud3gtb3JnMS5jaGFpbm1ha2VyLm9yZ4cEfwAAATAvBguBJ1iPZAsej2QL\nBAQgMDAxNjQ2ZTY3ODBmNGIwZDhiZWEzMjNlZThjMjQ5MTUwCgYIKoZIzj0EAwID\nSAAwRQIgNVNGr+G8dbYnzmmNMr9GCSUEC3TUmRcS4uOd5/Sw4mECIQDII1R7dCcx\n02YrxI8jEQZhmWeZ5FJhnSG6p6H9pCIWDQ==\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\nMIIDFjCCArugAwIBAgIDAdGZMAoGCCqGSM49BAMCMIGKMQswCQYDVQQGEwJDTjEQ\nMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEfMB0GA1UEChMWd3gt\nb3JnMi5jaGFpbm1ha2VyLm9yZzESMBAGA1UECxMJcm9vdC1jZXJ0MSIwIAYDVQQD\nExljYS53eC1vcmcyLmNoYWlubWFrZXIub3JnMB4XDTIwMTIwODA2NTM0M1oXDTI1\nMTIwNzA2NTM0M1owgZYxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAw\nDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQKExZ3eC1vcmcyLmNoYWlubWFrZXIub3Jn\nMRIwEAYDVQQLEwljb25zZW5zdXMxLjAsBgNVBAMTJWNvbnNlbnN1czEudGxzLnd4\nLW9yZzIuY2hhaW5tYWtlci5vcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARJ\nldhjiDOKiRqWJdfkmTBP6J1MILB6yO4m1O6kAG6Eiq7ujaO3VXQ01ZW+lKEgz7zv\nwFpJva/ZOWXBWg5iZ/M+o4IBADCB/TAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgw\nBgYEVR0lADApBgNVHQ4EIgQgH0PY7Oic1NRq5O64ag3g12d5vI5jqEWW9+MzOOrE\nnhEwKwYDVR0jBCQwIoAg8Y/Vs9Pj8uezY+di51n3+oexybSkYvop/L7UIAVYbSEw\nUQYDVR0RBEowSIIOY2hhaW5tYWtlci5vcmeCCWxvY2FsaG9zdIIlY29uc2Vuc3Vz\nMS50bHMud3gtb3JnMi5jaGFpbm1ha2VyLm9yZ4cEfwAAATAvBguBJ1iPZAsej2QL\nBAQgZjVhODUwYTAzYjFlNDU0NzkzOTg5NzIxYzVjMTc3NjMwCgYIKoZIzj0EAwID\nSQAwRgIhAKvDGBl+17dcTMdOjRW3VTTaGNlQiZepRXYarmAdX3PiAiEA6F6cZjsT\nEpSBfal9mUGlxJNNHhYIxs2SlSL4of4GTBA=\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\nMIIDFTCCArugAwIBAgIDCJoJMAoGCCqGSM49BAMCMIGKMQswCQYDVQQGEwJDTjEQ\nMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEfMB0GA1UEChMWd3gt\nb3JnMy5jaGFpbm1ha2VyLm9yZzESMBAGA1UECxMJcm9vdC1jZXJ0MSIwIAYDVQQD\nExljYS53eC1vcmczLmNoYWlubWFrZXIub3JnMB4XDTIwMTIwODA2NTM0M1oXDTI1\nMTIwNzA2NTM0M1owgZYxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAw\nDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQKExZ3eC1vcmczLmNoYWlubWFrZXIub3Jn\nMRIwEAYDVQQLEwljb25zZW5zdXMxLjAsBgNVBAMTJWNvbnNlbnN1czEudGxzLnd4\nLW9yZzMuY2hhaW5tYWtlci5vcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQt\nRBahVpwtR/GUIchzc5qiwePQyefBXrWLrP2W0EcsYHe+W25bb1W369OArZCt6Bct\nBTLOxL/Dl2Wk/KPBszKuo4IBADCB/TAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgw\nBgYEVR0lADApBgNVHQ4EIgQgEnC2getHs64R4n9VVe1A66N41/5HH63o63aV8Iqq\nk2EwKwYDVR0jBCQwIoAg0Y9lHSxXCu9i0Wd5MPoZTIFB+XClOYnSoKyC90WAif0w\nUQYDVR0RBEowSIIOY2hhaW5tYWtlci5vcmeCCWxvY2FsaG9zdIIlY29uc2Vuc3Vz\nMS50bHMud3gtb3JnMy5jaGFpbm1ha2VyLm9yZ4cEfwAAATAvBguBJ1iPZAsej2QL\nBAQgNzNiMWM4MWJkZjA2NDllNjk4YmI4MTVlNWI3NzM2YmIwCgYIKoZIzj0EAwID\nSAAwRQIhAODEcNO5jIBT+Dd4Fcsxz1ML8pzIzcWlPDeeuD6nfbQMAiARIw6KvJMu\nH9A4TrVomaX3eP0ttXTYwhdqu+5JeA+j2Q==\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\nMIIDFTCCArugAwIBAgIDAg4CMAoGCCqGSM49BAMCMIGKMQswCQYDVQQGEwJDTjEQ\nMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEfMB0GA1UEChMWd3gt\nb3JnNC5jaGFpbm1ha2VyLm9yZzESMBAGA1UECxMJcm9vdC1jZXJ0MSIwIAYDVQQD\nExljYS53eC1vcmc0LmNoYWlubWFrZXIub3JnMB4XDTIwMTIwODA2NTM0M1oXDTI1\nMTIwNzA2NTM0M1owgZYxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAw\nDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQKExZ3eC1vcmc0LmNoYWlubWFrZXIub3Jn\nMRIwEAYDVQQLEwljb25zZW5zdXMxLjAsBgNVBAMTJWNvbnNlbnN1czEudGxzLnd4\nLW9yZzQuY2hhaW5tYWtlci5vcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQg\nqP7ARZIf1tbrZoGOFkicxqyORGDXM7sdhmFTi/EVl/wI8RiwIwm64Jb0fSmakoEE\nXfXqfcav93s52EvpBUFso4IBADCB/TAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgw\nBgYEVR0lADApBgNVHQ4EIgQg+OLUREO24tHaUDNz5k2t4FYnm3sY2AMqmIfRk3ns\n6Q4wKwYDVR0jBCQwIoAgucqtaCpx/s+2C0wkXKeYip0W3ShUqYrPEP418+yFwcQw\nUQYDVR0RBEowSIIOY2hhaW5tYWtlci5vcmeCCWxvY2FsaG9zdIIlY29uc2Vuc3Vz\nMS50bHMud3gtb3JnNC5jaGFpbm1ha2VyLm9yZ4cEfwAAATAvBguBJ1iPZAsej2QL\nBAQgM2U1NmNhYTZkNjI2NDM2NWJjN2IxZTEyYmM3ZDljMjYwCgYIKoZIzj0EAwID\nSAAwRQIgYseIev8uXoorRTvz+lDou5GTcnWEvz3yeawlMRMBbDkCIQC2SD9oCjus\n7U2f6ujxCbediFaOo1YdBj1GNSaGfqSFbg==\n-----END CERTIFICATE-----\n"),
	}

	pidList = []peer.ID{
		"QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4",
		"QmeyNRs2DwWjcHTpcVHoUSaDAAif4VQZ2wQDQAUNDP33gH",
		"QmXf6mnQDBR9aHauRmViKzSuZgpumkn7x6rNxw1oqqRr45",
		"QmRRWXJpAVdhFsFtd9ah5F4LDQWFFBDVKpECAF8hssqj6H",
	}
)

func CreateHost(idx int, seeds map[peer.ID]ma.Multiaddr) (host.Host, error) {
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
		ListenAddresses:           []ma.Multiaddr{addrs[idx]},
		DirectPeers:               seeds,
		MsgCompress:               false,
		PrivateKey:                sk,
	}

	return hostCfg.NewHost(TcpNetwork, context.Background(), logger.NewLogPrinter("HOST"+strconv.Itoa(idx)))
}

func TestHost(t *testing.T) {
	// create host1
	host1, err := CreateHost(0, map[peer.ID]ma.Multiaddr{pidList[1]: ma.Join(addr2Target, ma.StringCast("/p2p/"+pidList[1].ToString()))})
	require.Nil(t, err)

	// create host2
	host2, err := CreateHost(1, map[peer.ID]ma.Multiaddr{pidList[0]: ma.Join(addrs[0], ma.StringCast("/p2p/"+pidList[0].ToString()))})
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
