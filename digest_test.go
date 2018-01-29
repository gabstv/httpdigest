package httpdigest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// john:doe
//WWW-authenticate:Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce="E/fIX+Kmic5GyK1ydhPoFA==",stale=false

func TestDigestAuthMD5(t *testing.T) {
	d := `Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce="E/fIX+Kmic5GyK1ydhPoFA==",stale=false`
	wwwa, err := ParseWWWAuthenticate(d)
	assert.NoError(t, err)
	auth0, err := wwwa.Digest(DigestInput{
		DigestURI: "/json_rpc",
		Cnonce:    "MWI5ZjNlNTc3ZDBhNTUxMWU1NGZmYmI3YzE5YWQ4ODE=",
		Method:    "POST",
		Username:  "john",
		Password:  "doe",
	})
	assert.NoError(t, err)
	expected := `Digest username="john", realm="monero-rpc", nonce="E/fIX+Kmic5GyK1ydhPoFA==", uri="/json_rpc", cnonce="MWI5ZjNlNTc3ZDBhNTUxMWU1NGZmYmI3YzE5YWQ4ODE=", nc=00000001, qop=auth, response="639f9031211b1b7b9cfbabe9e0a7fd44", algorithm="MD5"`
	assert.Equal(t, expected, auth0)
}
