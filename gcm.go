// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes6

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"reflect"
	"unsafe"
)

// copy of crypto/cipher
type gcmAble interface {
	NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
}

// copy of crypto/cipher with reduced minimum tagSize
func NewGCMWithTagSize(cipher cipher.Block, tagSize int) (cipher.AEAD, error) {
	return newGCMWithNonceAndTagSize(cipher, gcmStandardNonceSize, tagSize)
}

// inspired by crypto/cipher with reduced minimum tagSize
func newGCMWithNonceAndTagSize(cipher cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
		return nil, errors.New("cipher: incorrect tag size given to GCM")
	}

	if nonceSize <= 0 {
		return nil, errors.New("cipher: the nonce can't have zero length, or the security of the key will be immediately compromised")
	}

	if cipher, ok := cipher.(gcmAble); ok {
		cipherType := reflect.TypeOf(cipher)
		switch cipherType.String() {
		case "*aes.aesCipherGCM":
			// a := (*aesCipherGCM)(unsafe.Pointer(reflect.ValueOf(cipher).Pointer())) // alternative
			a := (*((*[2]*aesCipherGCM)(unsafe.Pointer(&cipher))))[1] // this is a bit hacky
			return a.NewGCM(nonceSize, tagSize)
		case "*aes8.aesCipherGCM":
			return cipher.NewGCM(nonceSize, tagSize)
		default:
			return nil, fmt.Errorf("type not supported: %s", cipherType)
		}
	} else {
		return nil, fmt.Errorf("type is not gcmAble")
	}
}

//go:linkname errOpen crypto/cipher.errOpen
var errOpen error

//go:linkname sliceForAppend crypto/cipher.sliceForAppend
func sliceForAppend(in []byte, n int) (head, tail []byte)
