/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcast

import (
	"chainmaker.org/chainmaker/net-liquid/core/handler"
	"chainmaker.org/chainmaker/net-liquid/core/host"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
)

// PubSub provides the functions of broadcasting and subscribing messages to the network.
type PubSub interface {
	// AllMetadataOnlyPeers return a list of peer.ID who communicates with us in a metadata-only link.
	AllMetadataOnlyPeers() []peer.ID
	// Subscribe register a sub-msg handler for handling the msg listened from the topic given.
	Subscribe(topic string, msgHandler handler.SubMsgHandler)
	// Unsubscribe cancels listening the topic given and unregister the sub-msg handler registered for this topic.
	Unsubscribe(topic string)
	// Publish will push a msg to the network of the topic given.
	Publish(topic string, msg []byte)
	// ProtocolID return the protocol.ID of the PubSub service.
	// The protocol id will be registered in host.RegisterMsgPayloadHandler method.
	ProtocolID() protocol.ID
	// ProtocolMsgHandler return a function which type is handler.MsgPayloadHandler.
	// It will be registered in host.Host.RegisterMsgPayloadHandler method.
	ProtocolMsgHandler() handler.MsgPayloadHandler
	// HostNotifiee return an implementation of host.Notifiee interface.
	// It will be registered in host.Host.Notify method.
	HostNotifiee() host.Notifiee
	// AttachHost will set up the host given to PubSub service.
	AttachHost(h host.Host) error
	// ID return the local peer id.
	ID() peer.ID
	// Stop the pub-sub service.
	Stop() error
	// SetBlackPeer add a peer id into the blacklist of PubSub.
	SetBlackPeer(pid peer.ID)
	// RemoveBlackPeer remove a peer id from the blacklist of PubSub.
	RemoveBlackPeer(pid peer.ID)
}
