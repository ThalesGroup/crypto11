// Copyright 2016, 2017 Thales e-Security, Inc
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
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS11Session contains a reference to a loaded PKCS#11 RSA session handle.
type PKCS11Session struct {
	Handle pkcs11.SessionHandle
}

// Map of slot IDs to session pools
var sessionPools map[uint]chan *PKCS11Session = map[uint]chan *PKCS11Session{}

// Mutex protecting sessionPools
var sessionPoolMutex sync.Mutex

// Create a new session for a given slot
func newSession(slot uint) (*PKCS11Session, error) {
	session, err := libHandle.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &PKCS11Session{session}, nil

}

// Run a function with a session
//
// setupSessions must have been called for the slot already, otherwise
// there will be a panic.
func withSession(slot uint, f func(session *PKCS11Session) error) error {
	var session *PKCS11Session
	var err error
	sessionPool := sessionPools[slot]
	select {
	case session = <-sessionPool:
		// nop
	default:
		if session, err = newSession(slot); err != nil {
			return err
		}
	}
	defer func() {
		// TODO better would be to close the session if the pool is full
		sessionPool <- session
	}()
	return f(session)
}

// Create the session pool for a given slot if it does not exist
// already.
func setupSessions(slot uint, max int) error {
	sessionPoolMutex.Lock()
	defer sessionPoolMutex.Unlock()
	if max <= 0 {
		max = 1024 // could be configurable
	}
	if _, ok := sessionPools[slot]; !ok {
		sessionPools[slot] = make(chan *PKCS11Session, max)
	}
	return nil
}
