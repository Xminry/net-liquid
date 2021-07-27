/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package host

import (
	"context"
	"crypto/tls"
	"errors"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/types"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/host/quic"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/host/tcp"
	api "chainmaker.org/chainmaker/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/tjfoc/gmsm/gmtls"
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
	ctx         context.Context
	tlsCfg      *tls.Config
	loadPidFunc types.LoadPeerIdFromTlsCertFunc
	enableTls   bool

	qTlsCfg      *tls.Config
	loadPidFuncQ types.LoadPeerIdFromQTlsCertFunc

	gmTlsServerCfg *gmtls.Config
	gmTlsClientCfg *gmtls.Config
	loadPidFuncGm  types.LoadPeerIdFromGMTlsCertFunc
	useGMTls       bool
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

// WithTlcCfg set the configuration for TLS.
func WithTlcCfg(cfg *tls.Config) Option {
	return func(c *networkConfig) error {
		c.tlsCfg = cfg
		return nil
	}
}

// WithLoadPidFunc set a types.LoadPeerIdFromTlsCertFunc for loading peer.ID from x509 certs.
func WithLoadPidFunc(loadPidFunc types.LoadPeerIdFromTlsCertFunc) Option {
	return func(c *networkConfig) error {
		c.loadPidFunc = loadPidFunc
		return nil
	}
}

// WithQTlsCfg set the configuration for quic TLS.
func WithQTlsCfg(cfg *tls.Config) Option {
	return func(c *networkConfig) error {
		c.qTlsCfg = cfg
		return nil
	}
}

// WithLoadPidFuncQ set a types.LoadPeerIdFromQTlsCertFunc for loading peer.ID from qx509 certs.
func WithLoadPidFuncQ(loadPidFunc types.LoadPeerIdFromQTlsCertFunc) Option {
	return func(c *networkConfig) error {
		c.loadPidFuncQ = loadPidFunc
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

// WithGMTlcServerCfg set the configuration for GM TLS server.
func WithGMTlcServerCfg(cfg *gmtls.Config) Option {
	return func(c *networkConfig) error {
		c.gmTlsServerCfg = cfg
		return nil
	}
}

// WithGMTlcClientCfg set the configuration for GM TLS client.
func WithGMTlcClientCfg(cfg *gmtls.Config) Option {
	return func(c *networkConfig) error {
		c.gmTlsClientCfg = cfg
		return nil
	}
}

// WithLoadPidFuncGm set a types.LoadPeerIdFromGMTlsCertFunc for loading peer.ID from gmx509 certs.
func WithLoadPidFuncGm(loadPidFuncGm types.LoadPeerIdFromGMTlsCertFunc) Option {
	return func(c *networkConfig) error {
		c.loadPidFuncGm = loadPidFuncGm
		return nil
	}
}

// WithGMTls make gm tls usable.
func WithGMTls(enable bool) Option {
	return func(c *networkConfig) error {
		c.useGMTls = enable
		return nil
	}
}

// newQuicNetwork create a network with quic transport.
func newQuicNetwork(cfg *networkConfig, logger api.Logger) (network.Network, error) {
	if cfg.qTlsCfg == nil {
		return nil, errors.New("qtls.config is required")
	}
	ctx := cfg.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return quic.NewNetwork(ctx, logger, quic.WithTlsCfg(cfg.qTlsCfg), quic.WithLoadPidFunc(cfg.loadPidFuncQ))
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
		tcp.WithGMTls(cfg.useGMTls),
		tcp.WithLoadPidFuncGm(cfg.loadPidFuncGm),
		tcp.WithGMTlsServerCfg(cfg.gmTlsServerCfg),
		tcp.WithGMTlsClientCfg(cfg.gmTlsClientCfg),
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
// If the format of address is wrong or it is a unsupported address, return UnknownNetwork.
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
