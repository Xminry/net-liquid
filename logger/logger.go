/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logger

import api "chainmaker.org/chainmaker/protocol/v2"

// NilLogger is a nil implementation of Logger interface.
// It will log nothing.
var NilLogger = &nilLogger{}

// Logger is an interface of net logger.
//type Logger interface {
//	Debug(args ...interface{})
//	Debugf(format string, args ...interface{})
//	Error(args ...interface{})
//	Errorf(format string, args ...interface{})
//	Info(args ...interface{})
//	Infof(format string, args ...interface{})
//	Panic(args ...interface{})
//	Panicf(format string, args ...interface{})
//	Warn(args ...interface{})
//	Warnf(format string, args ...interface{})
//}

var _ api.Logger = (*nilLogger)(nil)

type nilLogger struct{}

func (n *nilLogger) Debug(args ...interface{}) {}

func (n *nilLogger) Debugf(format string, args ...interface{}) {}

func (n *nilLogger) Error(args ...interface{}) {}

func (n *nilLogger) Errorf(format string, args ...interface{}) {}

func (n *nilLogger) Info(args ...interface{}) {}

func (n *nilLogger) Infof(format string, args ...interface{}) {}

func (n *nilLogger) Panic(args ...interface{}) {}

func (n *nilLogger) Panicf(format string, args ...interface{}) {}

func (n *nilLogger) Warn(args ...interface{}) {}

func (n *nilLogger) Warnf(format string, args ...interface{}) {}

func (n *nilLogger) Debugw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) Errorw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) Fatal(args ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) Fatalf(format string, args ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) Infow(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) Panicw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) Warnw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (n *nilLogger) DebugDynamic(getStr func() string) {
	panic("implement me")
}

func (n *nilLogger) InfoDynamic(getStr func() string) {
	panic("implement me")
}
