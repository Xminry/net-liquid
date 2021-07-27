/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package quic

import "github.com/xiaotianfork/quic-go"

const (
	// ErrCodeCloseConn is a quic.ApplicationErrorCode means the connection closed.
	ErrCodeCloseConn quic.ApplicationErrorCode = 0
	// ErrCodeCloseStream is a quic.StreamErrorCode means the stream closed.
	ErrCodeCloseStream quic.StreamErrorCode = 0
	// ErrMsgCloseConn is a message for connection closing.
	ErrMsgCloseConn = "closed"
)
