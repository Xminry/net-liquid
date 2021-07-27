/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package basic

// Starter provide a way to start up.
type Starter interface {
	Start() error
}

// Stopper provide a way to stop working.
type Stopper interface {
	Stop() error
}

// Switcher provide a starter and a stopper.
type Switcher interface {
	Starter
	Stopper
}
