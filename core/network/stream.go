/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package network

import "io"

type stream interface {
	io.Closer
	Stat

	Conn() Conn
}

// SendStream is an interface defined a way to send data.
type SendStream interface {
	stream
	io.Writer
}

// ReceiveStream is an interface defined a way to receive data.
type ReceiveStream interface {
	stream
	io.Reader
}

// Stream is an interface defined both ways to send and receive data.
type Stream interface {
	SendStream
	ReceiveStream
}
