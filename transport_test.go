package httpdigest

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/abbot/go-http-auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	isTest = true
}

func TestRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	client, err := New("john", "hello").Client()
	require.NoError(t, err)

	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	client, err = New("bad", "hello").Client()
	require.NoError(t, err)

	resp, err = client.Get(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 401, resp.StatusCode)
}

func TestRoundTripCache(t *testing.T) {
	srv := newTestServer(t)

	table := []struct {
		name    string
		request func(*http.Client) (*http.Response, error)
		expect  string
	}{
		{
			name: "get",
			request: func(client *http.Client) (*http.Response, error) {
				return client.Get(srv.URL)
			},
			expect: "Hello, john!",
		},
		{
			name: "post",
			request: func(client *http.Client) (*http.Response, error) {
				body := bytes.NewReader([]byte(`{"foo":"bar"}`))
				return client.Post(srv.URL, "application/json", body)
			},
			expect: `{"foo":"bar"}`,
		},
	}

	assertBody := func(t *testing.T, resp *http.Response, expect string) {
		t.Helper()
		data, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, expect, string(data))
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ts, err := NewCached("john", "hello")
			require.NoError(t, err)
			defer ts.Close()

			client, err := ts.Client()
			require.NoError(t, err)

			// uncached
			resp, err := tt.request(client)
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, uint64(1), ts.authCache.Metrics.Misses())
			assert.Equal(t, uint64(0), ts.authCache.Metrics.Hits())
			assertBody(t, resp, tt.expect)

			// cached
			resp, err = tt.request(client)
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, uint64(1), ts.authCache.Metrics.Misses())
			assert.Equal(t, uint64(1), ts.authCache.Metrics.Hits())
			assertBody(t, resp, tt.expect)

			// force cache flush
			srv.rejectNext = true
			resp, err = tt.request(client)
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, uint64(2), ts.authCache.Metrics.Misses(), "cache misses")
			assert.Equal(t, uint64(2), ts.authCache.Metrics.Hits(), "cache hits")
			assertBody(t, resp, tt.expect)

			// cached again
			resp, err = tt.request(client)
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, uint64(2), ts.authCache.Metrics.Misses())
			assert.Equal(t, uint64(3), ts.authCache.Metrics.Hits())
			assertBody(t, resp, tt.expect)

			// invalid
			ts.Username = "foo"
			resp, err = tt.request(client)
			require.NoError(t, err)
			require.Equal(t, 401, resp.StatusCode)
			assert.Equal(t, uint64(3), ts.authCache.Metrics.Misses())
			assert.Equal(t, uint64(3), ts.authCache.Metrics.Hits())

			// still cached
			ts.Username = "john"
			resp, err = tt.request(client)
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, uint64(3), ts.authCache.Metrics.Misses())
			assert.Equal(t, uint64(4), ts.authCache.Metrics.Hits())
			assertBody(t, resp, tt.expect)
		})
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	srv := newTestServer(b)

	doReq := func(t testing.TB, client *http.Client) {
		t.Helper()

		resp, err := client.Get(srv.URL)
		require.NoError(b, err)
		require.Equal(b, 200, resp.StatusCode)
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}

	b.ResetTimer()

	b.Run("uncached", func(b *testing.B) {
		ts := New("john", "hello")
		client, err := ts.Client()
		require.NoError(b, err)

		resp, err := client.Get(srv.URL)
		require.NoError(b, err)
		require.Equal(b, 200, resp.StatusCode)

		b.ResetTimer()

		b.Run("single", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				doReq(b, client)
			}
		})

		b.Run("parallel", func(b *testing.B) {
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					doReq(b, client)
				}
			})
		})
	})

	b.Run("cached", func(b *testing.B) {
		tsCached, err := NewCached("john", "hello")
		require.NoError(b, err)
		clientCached, err := tsCached.Client()
		require.NoError(b, err)

		resp, err := clientCached.Get(srv.URL)
		require.NoError(b, err)
		require.Equal(b, 200, resp.StatusCode)

		b.ResetTimer()

		b.Run("single", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				doReq(b, clientCached)
			}
		})

		b.Run("parallel", func(b *testing.B) {
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					doReq(b, clientCached)
				}
			})
		})
	})
}

func newTestServer(t testing.TB) *testServer {
	t.Helper()
	srv := &testServer{}
	authenticator := auth.NewDigestAuthenticator("example.com", srv.Secret)
	authenticator.IgnoreNonceCount = true
	srv.Server = httptest.NewServer(authenticator.Wrap(srv.AuthHandler))
	t.Cleanup(srv.Close)
	return srv
}

type testServer struct {
	*httptest.Server
	rejectNext bool
}

func (s *testServer) Secret(user, realm string) string {
	if s.rejectNext {
		s.rejectNext = false
		return ""
	}

	if user == "john" {
		// password is "hello"
		return "b98e16cbc3d01734b264adba7baa3bf9"
	}
	return ""
}

func (s *testServer) AuthHandler(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	if r.Method == http.MethodPost {
		io.Copy(w, r.Body)
	} else {
		fmt.Fprintf(w, "Hello, %s!", r.Username)
	}
}
