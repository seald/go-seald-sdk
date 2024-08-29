//go:build !android && !ios

package main

import "C"

import (
	"io"
)

var logWriter io.Writer = nil

func init() {
}
