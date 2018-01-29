package httpdigest

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type WWWAuth struct {
	Realm     string
	Domain    string
	Nonce     string
	Opaque    string
	Stale     string
	Algorithm string
	Qop       string
}

func ParseWWWAuthenticate(entry string) (wwwa *WWWAuth, err error) {
	entry = strings.TrimSpace(entry)
	if !strings.HasPrefix(entry, "Digest ") {
		return nil, fmt.Errorf("bad challenge '%s'", entry)
	}
	dkeys := parseDigest(entry)
	wwwa = &WWWAuth{
		Realm:     dkeys["realm"],
		Domain:    dkeys["domain"],
		Nonce:     dkeys["nonce"],
		Opaque:    dkeys["opaque"],
		Stale:     dkeys["stale"],
		Algorithm: dkeys["algorithm"],
		Qop:       dkeys["qop"],
	}
	//TODO: catch bad algorithm
	return wwwa, nil
}

type DigestInput struct {
	Username  string
	Password  string
	DigestURI string
	// nonce-count
	// The nc-value is the hexadecimal
	// count of the number of requests (including the current request)
	// that the client has sent with the nonce value in this request.  For
	// example, in the first request sent in response to a given nonce
	// value, the client sends "nc=00000001".  The purpose of this
	// directive is to allow the server to detect request replays by
	// maintaining its own copy of this count - if the same nc-value is
	// seen twice, then the request is a replay.
	NonceCount uint
	Cnonce     string
	Method     string
}

func (a *WWWAuth) Digest(inp DigestInput) (auth string, err error) {
	if inp.NonceCount == 0 {
		inp.NonceCount++
	}
	// Qop may be separated by comma because the server can support more than one
	// implementation
	qopsplit := strings.Split(a.Qop, ",")
	for _, qop := range qopsplit {
		switch qop {
		case "auth":
			return a.digestAuth(inp)
		}
	}
	return "", fmt.Errorf("digest not implemented ('%s')", a.Qop)
}

func (a *WWWAuth) digestAuth(inp DigestInput) (auth string, err error) {

	h1, err := a.ha1(inp)
	if err != nil {
		return "", err
	}
	h2 := md5hex("%s:%s", inp.Method, inp.DigestURI)
	cnonce := inp.Cnonce
	if cnonce == "" {
		cnonce = newCnonce()
	}
	response := md5hex("%s:%s:%08x:%s:%s:%s", h1, a.Nonce, inp.NonceCount, cnonce, "auth", h2)

	rvs := make([]string, 0)
	rvs = append(rvs, fmt.Sprintf("username=%v", strconv.Quote(inp.Username)))
	rvs = append(rvs, fmt.Sprintf("realm=%v", strconv.Quote(a.Realm)))
	rvs = append(rvs, fmt.Sprintf("nonce=%v", strconv.Quote(a.Nonce))) //TODO: ommit of no nonce
	rvs = append(rvs, fmt.Sprintf("uri=%v", strconv.Quote(inp.DigestURI)))
	rvs = append(rvs, fmt.Sprintf("cnonce=%v", strconv.Quote(cnonce)))
	rvs = append(rvs, fmt.Sprintf("nc=%08x", inp.NonceCount))
	rvs = append(rvs, fmt.Sprintf("qop=%s", "auth"))
	rvs = append(rvs, fmt.Sprintf("response=%v", strconv.Quote(response)))
	rvs = append(rvs, fmt.Sprintf("algorithm=%v", strconv.Quote(a.Algorithm)))
	if a.Opaque != "" {
		rvs = append(rvs, fmt.Sprintf("opaque=%v", strconv.Quote(a.Opaque)))
	}

	return "Digest " + strings.Join(rvs, ", "), nil
}

func (a *WWWAuth) ha1(inp DigestInput) (ha1 string, err error) {
	switch a.Algorithm {
	case "", "MD5":
		return md5hex("%s:%s:%s", inp.Username, a.Realm, inp.Password), nil
	case "MD5-sess":
		return md5hex("%s:%s:%08x", md5hex("%s:%s:%s", inp.Username, a.Realm, inp.Password), a.Nonce, inp.NonceCount), nil
	}
	return "", fmt.Errorf("not implemented")
}

// Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce="enL+8AmWO9KIVm9fEKxwIQ==",stale=false
func parseDigest(rawDigest string) map[string]string {
	var state int
	var quote bool
	var backq int
	var key, val bytes.Buffer
	keys := make(map[string]string)
	for _, r := range rawDigest[7:] {
		if state == 0 {
			if r == '=' {
				state = 1
			} else {
				key.WriteRune(r)
			}
		} else if state == 1 {
			if r == '"' {
				if backq%2 == 0 {
					// valid quote
					quote = !quote
				}
				val.WriteRune(r)
				backq = 0
			} else if r == '\\' {
				backq++
				val.WriteRune(r)
			} else if r == ',' {
				if quote {
					val.WriteRune(r)
				} else {
					if strings.HasPrefix(val.String(), "\"") {
						v2, _ := strconv.Unquote(val.String())
						keys[strings.TrimSpace(key.String())] = v2
					} else {
						keys[strings.TrimSpace(key.String())] = strings.TrimSpace(val.String())
					}
					quote = false
					backq = 0
					state = 0
					key.Reset()
					val.Reset()
				}
			} else {
				backq = 0
				val.WriteRune(r)
			}
		}
	}
	if key.String() != "" {
		if strings.HasPrefix(val.String(), "\"") {
			v2, _ := strconv.Unquote(val.String())
			keys[strings.TrimSpace(key.String())] = v2
		} else {
			keys[strings.TrimSpace(key.String())] = strings.TrimSpace(val.String())
		}
	}
	return keys
}
