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
)

var Debug bool

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

	// clone the request
	req2 := &http.Request{}
	*req2 = *req
	req2.Header = make(http.Header)
	for k, v := range req.Header {
		req2.Header[k] = v
	}
	req2.URL = new(url.URL)
	*req2.URL = *req.URL

	// clone the body
	if req.Body != nil {
		var err error
		// It is more efficient to call GetBody if it is defined,
		// as this could avoid duplicating the underlying bytes
		// of the body
		if req.GetBody != nil {
			req2.Body, err = req.GetBody()
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
			req2.Body = save
		}
	}

	// make a request, if we get 401, then we digest the challenge
	if Debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			log.Println("dump request error", err)
		} else {
			fmt.Printf("dump request: \n%v\n\n\n", string(dump))
		}
	}
	resp, err := t.Transport.RoundTrip(req)
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

	challengeh, err := ParseWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))
	if err != nil {
		return nil, err
	}
	authh, err := challengeh.Digest(DigestInput{
		DigestURI: req.URL.RequestURI(),
		Cnonce:    t.CnonceGen(),
		Method:    req.Method,
		Username:  t.Username,
		Password:  t.Password,
	})
	if err != nil {
		return nil, err
	}
	req2.Header.Set("Authorization", authh)

	if Debug {
		dump, err := httputil.DumpRequestOut(req2, true)
		if err != nil {
			log.Println("dump request error", err)
		} else {
			fmt.Printf("dump request: \n%v\n\n\n", string(dump))
		}
	}

	resp2, err := t.Transport.RoundTrip(req2)

	if err != nil {
		return nil, err
	}

	if Debug {
		dump, err := httputil.DumpResponse(resp2, true)
		if err != nil {
			log.Println("dump response error", err)
		} else {
			fmt.Printf("dump response: \n%v\n\n\n", string(dump))
		}
	}

	return resp2, nil
}

// Client returns an HTTP client that uses the digest transport.
func (t *Transport) Client() (*http.Client, error) {
	if t.Transport == nil {
		return nil, fmt.Errorf("underlying transport is nil")
	}
	return &http.Client{Transport: t}, nil
}
