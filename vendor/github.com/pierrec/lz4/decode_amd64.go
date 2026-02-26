//go:build !appengine && gc && !noasm
// +build !appengine,gc,!noasm

package lz4

//go:noescape
func decodeBlock(dst, src []byte) int
