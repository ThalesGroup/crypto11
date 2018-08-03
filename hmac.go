// Copyright 2018 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"context"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/youtube/vitess/go/pools"
	"hash"
)

const (
	NFCK_VENDOR_NCIPHER = 0xde436972
	CKM_NCIPHER         = (pkcs11.CKM_VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)

	// CKM_NC_MD5_HMAC_KEY_GEN is the nShield-specific HMACMD5 key-generation mechanism
	CKM_NC_MD5_HMAC_KEY_GEN = (CKM_NCIPHER + 0x6)

	// CKM_NC_SHA_1_HMAC_KEY_GEN is the nShield-specific HMACSHA1 key-generation mechanism
	CKM_NC_SHA_1_HMAC_KEY_GEN = (CKM_NCIPHER + 0x3)

	// CKM_NC_SHA224_HMAC_KEY_GEN is the nShield-specific HMACSHA224 key-generation mechanism
	CKM_NC_SHA224_HMAC_KEY_GEN = (CKM_NCIPHER + 0x24)

	// CKM_NC_SHA256_HMAC_KEY_GEN is the nShield-specific HMACSHA256 key-generation mechanism
	CKM_NC_SHA256_HMAC_KEY_GEN = (CKM_NCIPHER + 0x25)

	// CKM_NC_SHA384_HMAC_KEY_GEN is the nShield-specific HMACSHA384 key-generation mechanism
	CKM_NC_SHA384_HMAC_KEY_GEN = (CKM_NCIPHER + 0x26)

	// CKM_NC_SHA512_HMAC_KEY_GEN is the nShield-specific HMACSHA512 key-generation mechanism
	CKM_NC_SHA512_HMAC_KEY_GEN = (CKM_NCIPHER + 0x27)
)

type hmacImplementation struct {
	// PKCS#11 session to use
	session *PKCS11Session

	size int

	blockSize int

	// Cleanup function
	cleanup func()
}

type hmacInfo struct {
	size      int
	blockSize int
	general   bool
}

var hmacInfos = map[int]*hmacInfo{
	pkcs11.CKM_MD5_HMAC:                {20, 64, false},
	pkcs11.CKM_MD5_HMAC_GENERAL:        {20, 64, true},
	pkcs11.CKM_SHA_1_HMAC:              {20, 64, false},
	pkcs11.CKM_SHA_1_HMAC_GENERAL:      {20, 64, true},
	pkcs11.CKM_SHA224_HMAC:             {28, 64, false},
	pkcs11.CKM_SHA224_HMAC_GENERAL:     {28, 64, true},
	pkcs11.CKM_SHA256_HMAC:             {32, 64, false},
	pkcs11.CKM_SHA256_HMAC_GENERAL:     {32, 64, true},
	pkcs11.CKM_SHA384_HMAC:             {48, 64, false},
	pkcs11.CKM_SHA384_HMAC_GENERAL:     {48, 64, true},
	pkcs11.CKM_SHA512_HMAC:             {64, 128, false},
	pkcs11.CKM_SHA512_HMAC_GENERAL:     {64, 128, true},
	pkcs11.CKM_SHA512_224_HMAC:         {28, 128, false},
	pkcs11.CKM_SHA512_224_HMAC_GENERAL: {28, 128, true},
	pkcs11.CKM_SHA512_256_HMAC:         {32, 128, false},
	pkcs11.CKM_SHA512_256_HMAC_GENERAL: {32, 128, true},
	pkcs11.CKM_RIPEMD160_HMAC:          {20, 64, false},
	pkcs11.CKM_RIPEMD160_HMAC_GENERAL:  {20, 64, true},
}

// NewHMAC returns a new HMAC hash using the given PKCS#11 mechanism
// and key.
// length specifies the output size, for _GENERAL mechanisms.
//
// If the mechanism is not in the built-in list of known mechanisms then the
// Size() function will return whatever length was, even if it is wrong.
// BlockSize() will always return 0 in this case.
//
// The Reset() method is not implemented, and Sum() may only be called once.
// The former limitation may be lifted in future but the latter is fundamental
// and will not change.
func (key *PKCS11SecretKey) NewHMAC(mech int, length int) (h hash.Hash, err error) {
	// TODO refactor with newBlockModeCloser
	sessionPool := pool.Get(key.Slot)
	if sessionPool == nil {
		err = fmt.Errorf("crypto11: no session for slot %d", key.Slot)
		return
	}
	ctx := context.Background()
	if instance.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), instance.cfg.PoolWaitTimeout)
		defer cancel()
	}
	var session pools.Resource
	if session, err = sessionPool.Get(ctx); err != nil {
		return
	}
	var hi hmacImplementation
	hi.session = session.(*PKCS11Session)
	hi.cleanup = func() {
		sessionPool.Put(session)
		hi.session = nil
	}
	var params []byte
	if info, ok := hmacInfos[mech]; ok {
		hi.blockSize = info.blockSize
		if info.general {
			hi.size = length
			params = ulongToBytes(uint(length))
		} else {
			hi.size = info.size
		}
	} else {
		hi.size = length
	}
	mechDescription := []*pkcs11.Mechanism{pkcs11.NewMechanism(uint(mech), params)}
	if err = hi.session.Ctx.SignInit(hi.session.Handle, mechDescription, key.Handle); err != nil {
		hi.cleanup()
		return
	}
	h = &hi
	return
}

func (hi *hmacImplementation) Write(p []byte) (n int, err error) {
	if err = hi.session.Ctx.SignUpdate(hi.session.Handle, p); err != nil {
		return
	}
	n = len(p)
	return
}

func (hi *hmacImplementation) Sum(b []byte) []byte {
	var result []byte
	var err error
	result, err = hi.session.Ctx.SignFinal(hi.session.Handle)
	hi.cleanup()
	if err != nil {
		panic(err)
	}
	return append(b, result...)
}

func (hi *hmacImplementation) Reset() {
	panic("Reset not implemented")
}

func (hi *hmacImplementation) Size() int {
	return hi.size
}

func (hi *hmacImplementation) BlockSize() int {
	return hi.blockSize
}
