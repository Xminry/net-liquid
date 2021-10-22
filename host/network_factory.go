/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package host

import (
	"context"
	"errors"

	cmTls "chainmaker.org/chainmaker/common/v2/crypto/tls"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
	"chainmaker.org/chainmaker/net-liquid/host/quic"
	"chainmaker.org/chainmaker/net-liquid/host/tcp"
	api "chainmaker.org/chainmaker/protocol/v2"
	ma "github.com/multiformats/go-multiaddr"
)

// NetworkType is the type of transport layer.
type NetworkType string

const (
	// UnknownNetwork type
	UnknownNetwork NetworkType = "UNKNOWN"
	// QuicNetwork type
	QuicNetwork NetworkType = "QUIC"
	// TcpNetwork type
	TcpNetwork NetworkType = "TCP"
)

var (
	// ErrUnknownNetworkType will be returned if network type is unsupported.
	ErrUnknownNetworkType = errors.New("unknown network type")
)

// Option of network instance.
type Option func(cfg *networkConfig) error

type networkConfig struct {
	ctx  context.Context
	lPid peer.ID

	tlsCfg      *cmTls.Config
	loadPidFunc types.LoadPeerIdFromCMTlsCertFunc
	enableTls   bool
}

func (c *networkConfig) apply(opt ...Option) error {
	for _, o := range opt {
		if err := o(c); err != nil {
			return err
		}
	}
	return nil
}

// WithCtx designate ctx given as the context of network.
func WithCtx(ctx context.Context) Option {
	return func(c *networkConfig) error {
		c.ctx = ctx
		return nil
	}
}

// WithLocalPID designate the local peer.ID of network.
func WithLocalPID(pid peer.ID) Option {
	return func(c *networkConfig) error {
		c.lPid = pid
		return nil
	}
}

// WithTlcCfg set the configuration for TLS.
func WithTlcCfg(cfg *cmTls.Config) Option {
	return func(c *networkConfig) error {
		c.tlsCfg = cfg
		return nil
	}
}

// WithLoadPidFunc set a types.LoadPeerIdFromTlsCertFunc for loading peer.ID from x509 certs.
func WithLoadPidFunc(loadPidFunc types.LoadPeerIdFromCMTlsCertFunc) Option {
	return func(c *networkConfig) error {
		c.loadPidFunc = loadPidFunc
		return nil
	}
}

// WithEnableTls make tls usable.
func WithEnableTls(enable bool) Option {
	return func(c *networkConfig) error {
		c.enableTls = enable
		return nil
	}
}

// newQuicNetwork create a network with quic transport.
func newQuicNetwork(cfg *networkConfig, logger api.Logger) (network.Network, error) {
	if cfg.tlsCfg == nil {
		return nil, errors.New("tls config is required")
	}
	ctx := cfg.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return quic.NewNetwork(ctx, logger,
		quic.WithTlsCfg(cfg.tlsCfg),
		quic.WithLoadPidFunc(cfg.loadPidFunc),
		quic.WithLocalPeerId(cfg.lPid),
	)
}

// newTcpNetwork create a network with tcp transport.
func newTcpNetwork(cfg *networkConfig, logger api.Logger) (network.Network, error) {
	ctx := cfg.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return tcp.NewNetwork(ctx, logger,
		tcp.WithTlsCfg(cfg.tlsCfg),
		tcp.WithLoadPidFunc(cfg.loadPidFunc),
		tcp.WithEnableTls(cfg.enableTls),
		tcp.WithLocalPeerId(cfg.lPid),
	)
}

// newNetwork create a network instance.
func newNetwork(typ NetworkType, logger api.Logger, opt ...Option) (network.Network, error) {
	cfg := &networkConfig{}
	if err := cfg.apply(opt...); err != nil {
		return nil, err
	}

	switch typ {
	case QuicNetwork:
		// Quic
		return newQuicNetwork(cfg, logger)
	case TcpNetwork:
		// TCP
		return newTcpNetwork(cfg, logger)
	default:
		return nil, ErrUnknownNetworkType
	}
}

// ConfirmNetworkTypeByAddr return a network type supported that for the address.
// If the format of address is wrong, or it is an unsupported address, return UnknownNetwork.
func ConfirmNetworkTypeByAddr(addr ma.Multiaddr) NetworkType {
	netType := UnknownNetwork
	switch {
	case tcp.CanListen(addr):
		netType = TcpNetwork
	case quic.CanListen(addr):
		netType = QuicNetwork
	default:

	}
	return netType
}
