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
	"context"

	"github.com/miekg/pkcs11"
	"github.com/vitessio/vitess/go/pools"
)

// pkcs11Session wraps a PKCS#11 session handle so we can use it in a resource pool.
type pkcs11Session struct {
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
}

// Close is required to satisfy the pools.Resource interface. It closes the session, but swallows any
// errors that occur.
func (s pkcs11Session) Close() {
	// We cannot return an error, so we swallow it
	_ = s.ctx.CloseSession(s.handle)
}

// withSession executes a function with a session. If the function returns pkcs11.CKR_USER_NOT_LOGGED_IN,
// the user is logged in and the function is called for a second time.
func (c *Context) withSession(f func(session *pkcs11Session) error) error {

	session, err := c.getSession()
	if err != nil {
		return err
	}

	err = f(session)
	if err != nil {
		// if a request required login, then try to login
		if perr, ok := err.(pkcs11.Error); ok && perr == pkcs11.CKR_USER_NOT_LOGGED_IN {
			if err = c.ctx.Login(session.handle, pkcs11.CKU_USER, c.cfg.Pin); err != nil {
				// Another thread may have successfully logged in
				if perr2, ok := err.(pkcs11.Error); !ok || perr2 != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
					return err
				}
			}
			// retry after login
			return f(session)
		}

		return err
	}

	return nil
}

// getSession retrieves a session from the pool, respecting the timeout defined in the Context config.
// Callers are responsible for putting this session back in the pool.
func (c *Context) getSession() (*pkcs11Session, error) {
	ctx := context.Background()

	if c.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.cfg.PoolWaitTimeout)
		defer cancel()
	}

	resource, err := c.pool.Get(ctx)
	if err != nil {
		return nil, err
	}

	return resource.(*pkcs11Session), nil
}

// resourcePoolFactoryFunc is called by the resource pool when a new session is needed.
func (c *Context) resourcePoolFactoryFunc() (pools.Resource, error) {
	session, err := c.ctx.OpenSession(c.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &pkcs11Session{c.ctx, session}, nil
}
