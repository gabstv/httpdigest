// The httpdigest package provides an implementation of http.RoundTripper that
// resolves a HTTP Digest Authentication (https://tools.ietf.org/html/rfc2617).
// At the moment, this only implements the MD5 and "auth" portions of the RFC.
// This package was created initially to cover a monero-wallet-rpc call using
// digest authentication.
//
// Example (monero-wallet-rpc with digest):
//
//  package main
//
//  import (
//  	//"net/http"
//  	"fmt"
//
//  	"github.com/gabstv/go-monero/walletrpc"
//  	"github.com/gabstv/httpdigest"
//  )
//
//  func main() {
//  	t := httpdigest.New("john", "doe")
//
//  	// to do a normal http request:
//  	//
//  	// cl := &http.Client{
//  	// 	Transport: t,
//  	// }
//  	// req, _ := http.NewRequest(http.MethodGet, "url", nil)
//  	// resp, err := cl.Do(req)
//
//  	client := walletrpc.New(walletrpc.Config{
//  		Address:   "http://127.0.0.1:29567/json_rpc",
//  		Transport: t,
//  	})
//
//  	balance, unlocked, err := client.Getbalance()
//
//  	if err != nil {
//  		panic(err)
//  	}
//  	fmt.Println("balance", walletrpc.XMRToDecimal(balance))
//  	fmt.Println("unlocked balance", walletrpc.XMRToDecimal(unlocked))
//  }
//
package httpdigest

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strings"

	"github.com/dgraph-io/ristretto"
)

var (
	Debug  bool
	isTest bool
)

// Transport is an implementation of http.RoundTripper that can handle http
// digest authentication.
type Transport struct {
	Username  string
	Password  string
	Transport http.RoundTripper
	// Generator function for cnonce. If not specified, the transport will
	// generate one automatically.
	CnonceGen func() string
}

// NewTransport creates a new digest transport using the http.DefaultTransport.
// You may change the underlying transport if needed (i.e: handling self-signed
// certificates).
func New(username, password string) *Transport {
	return &Transport{
		Username:  username,
		Password:  password,
		Transport: http.DefaultTransport,
		CnonceGen: func() string {
			return ""
		},
	}
}

// RoundTrip makes a request expecting a 401 response that will require digest
// authentication. If a 401 is received, it creates the credentials it needs and
// makes a follow-up request.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport == nil {
		return nil, fmt.Errorf("underlying transport is nil")
	}
	if t.CnonceGen == nil {
		return nil, fmt.Errorf("cnounce generator is nil")
	}

	// We need to do a fresh auth request
	resp, err := t.doAuthRequest(req)
	if err != nil {
		return nil, err
	}

	chal, err := ParseWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))
	if err != nil {
		return nil, err
	}

	// using either a cached or new challenge to hash the digest
	// for this request
	authh, err := chal.Digest(DigestInput{
		DigestURI: req.URL.RequestURI(),
		Method:    req.Method,
		Cnonce:    t.CnonceGen(),
		Username:  t.Username,
		Password:  t.Password,
	})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authh)

	if Debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			log.Println("dump request error", err)
		} else {
			fmt.Printf("dump request: \n%v\n\n\n", string(dump))
		}
	}

	resp, err = t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if Debug {
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Println("dump response error", err)
		} else {
			fmt.Printf("dump response: \n%v\n\n\n", string(dump))
		}
	}

	return resp, nil
}

// doAuthRequest takes the original client request, clones it,
// and performs the digest auth request.
// The returned response Body is already drained and closed.
func (t *Transport) doAuthRequest(req *http.Request) (*http.Response, error) {
	// clone the request
	authReq := &http.Request{}
	*authReq = *req
	authReq.Header = make(http.Header)
	for k, v := range req.Header {
		authReq.Header[k] = v
	}
	authReq.URL = new(url.URL)
	*authReq.URL = *req.URL

	// clone the body
	if req.Body != nil {
		var err error
		// It is more efficient to call GetBody if it is defined,
		// as this could avoid duplicating the underlying bytes
		// of the body
		if req.GetBody != nil {
			authReq.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		} else {
			// Otherwise we are falling back on duplicating
			// the bytes for the body content
			save := req.Body
			save, req.Body, err = drainBody(req.Body)
			if err != nil {
				return nil, err
			}
			authReq.Body = save
		}
	}

	// make a request, if we get 401, then we digest the challenge
	if Debug {
		dump, err := httputil.DumpRequestOut(authReq, true)
		if err != nil {
			log.Println("dump request error", err)
		} else {
			fmt.Printf("dump request: \n%v\n\n\n", string(dump))
		}
	}
	resp, err := t.Transport.RoundTrip(authReq)
	if err != nil {
		return nil, err
	}
	if Debug {
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Println("dump response error", err)
		} else {
			fmt.Printf("dump response: \n%v\n\n\n", string(dump))
		}
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	// we read the body of the response because otherwise the authentication
	// might fail (fails on monero-wallet-rpc)
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()

	return resp, nil
}

// Client returns an HTTP client that uses the digest transport.
func (t *Transport) Client() (*http.Client, error) {
	if t.Transport == nil {
		return nil, fmt.Errorf("underlying transport is nil")
	}
	return &http.Client{Transport: t}, nil
}

// CachedTransport is an implementation of http.RoundTripper that can handle http
// digest authentication. It wraps Transport and caches digest authentication
// for reuse in the next request.
type CachedTransport struct {
	*Transport
	authCache *ristretto.Cache
}

// NewCached creates a new digest CachedTransport using the http.DefaultTransport.
// You may change the underlying transport if needed (i.e: handling self-signed
// certificates).
// A cache is consulted for reuse of digest auth strings to different request URIs.
// A call to Close should be made when the transport is no longer needed, to free
// cache resources.
func NewCached(username, password string) (*CachedTransport, error) {
	authCache, err := ristretto.NewCache(&ristretto.Config{
		MaxCost:     50,      // cache up to this many host+user+pass auth creds
		NumCounters: 50 * 10, // expected max items * 10
		BufferItems: 64,      // per docs
		Metrics:     isTest,
	})
	if err != nil {
		return nil, fmt.Errorf("error configuring auth cache: %v", err)
	}

	t := &CachedTransport{
		Transport: New(username, password),
		authCache: authCache,
	}

	runtime.SetFinalizer(t, func(t *CachedTransport) { t.authCache.Close() })

	return t, nil
}

// Close the cached transport and free cache resources
func (t *CachedTransport) Close() {
	runtime.SetFinalizer(t, nil)
	t.authCache.Close()
}

// ClearCache will clear all currently cached digest auth credentials,
// causing the next request to perform digest auth again
func (t *CachedTransport) ClearCache() {
	t.authCache.Clear()
}

// SetTransport sets the underlying transport to something other than
// the default http.DefaultTransport
func (t *CachedTransport) SetTransport(r http.RoundTripper) {
	if r == nil {
		r = http.DefaultTransport
	}
	t.Transport.Transport = r
}

// Client returns an HTTP client that uses the digest CachedTransport.
func (t *CachedTransport) Client() (*http.Client, error) {
	if t.Transport.Transport == nil {
		return nil, fmt.Errorf("underlying transport is nil")
	}
	return &http.Client{Transport: t}, nil
}

// RoundTrip makes a request expecting a 401 response that will require digest
// authentication. If a 401 is received, it creates the credentials it needs and
// makes a follow-up request.
// Credentials are cached and reused for subsequent requests until they are
// no longer valid, in which case auth will be performed again.
func (t *CachedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport.Transport == nil {
		return nil, fmt.Errorf("underlying transport is nil")
	}
	if t.CnonceGen == nil {
		return nil, fmt.Errorf("cnounce generator is nil")
	}

	var (
		chal   *WWWAuth
		err    error
		cached bool
	)
	// Check the cache for an existing challenge
	cacheKey := strings.Join([]string{req.URL.Hostname(), t.Username, t.Password}, ",")
	if t.authCache != nil {
		if val, found := t.authCache.Get(cacheKey); found && val != nil {
			chal = val.(*WWWAuth)
			cached = true
		}
	}

	if chal == nil {
		// We need to do a fresh auth request
		resp, err := t.doAuthRequest(req)
		if err != nil {
			return nil, err
		}

		chal, err = ParseWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return nil, err
		}

		if t.authCache != nil {
			t.authCache.Set(cacheKey, chal, 1)
		}
	}

	// using either a cached or new challenge to hash the digest
	// for this request
	authh, err := chal.Digest(DigestInput{
		DigestURI: req.URL.RequestURI(),
		Method:    req.Method,
		Cnonce:    t.CnonceGen(),
		Username:  t.Username,
		Password:  t.Password,
	})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authh)

	if Debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			log.Println("dump request error", err)
		} else {
			fmt.Printf("dump request: \n%v\n\n\n", string(dump))
		}
	}

	resp, err := t.Transport.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// If the request used a cached challenge and failed the
	// auth, clear the cache and retry from scratch
	if resp.StatusCode == http.StatusUnauthorized && cached {
		t.authCache.Del(cacheKey)
		req.Header.Del("Authorization")
		if req.Body != nil && req.GetBody != nil {
			req.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		}
		return t.RoundTrip(req)
	}

	if Debug {
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Println("dump response error", err)
		} else {
			fmt.Printf("dump response: \n%v\n\n\n", string(dump))
		}
	}

	return resp, nil
}
