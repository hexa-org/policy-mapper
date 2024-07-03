package sessionSupport

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "net/http/cookiejar"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/gorilla/mux"
    "github.com/stretchr/testify/assert"
    log "golang.org/x/exp/slog"
)

type testServer struct {
    *httptest.Server
}

func newTestServer(t *testing.T, h http.Handler) *testServer {
    ts := httptest.NewTLSServer(h)

    jar, err := cookiejar.New(nil)
    if err != nil {
        t.Fatal(err)
    }
    ts.Client().Jar = jar

    ts.Client().CheckRedirect = func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse
    }

    return &testServer{ts}
}

func (ts *testServer) execute(t *testing.T, urlPath string) (http.Header, string) {
    rs, err := ts.Client().Get(ts.URL + urlPath)
    if err != nil {
        t.Fatal(err)
    }

    defer rs.Body.Close()
    body, err := io.ReadAll(rs.Body)
    if err != nil {
        t.Fatal(err)
    }

    return rs.Header, string(body)
}

func extractTokenFromCookie(c string) string {
    parts := strings.Split(c, ";")
    return strings.SplitN(parts[0], "=", 2)[1]
}

func TestSession(t *testing.T) {
    mgr := NewSessionManager()

    router := mux.NewRouter()

    mgr.SetSessionMiddleware(router)

    router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        log.Info("Checking login start")
        mgr.StartLogin("astate", "anonce", r)
        _, _ = w.Write([]byte("values encoded"))
        w.WriteHeader(http.StatusOK)
    })

    router.HandleFunc("/checkstate", func(w http.ResponseWriter, r *http.Request) {
        log.Info("Checking state")
        sid, state, nonce := mgr.GetState(r)
        assert.NotEmpty(t, sid)
        assert.Equal(t, "astate", state)
        assert.Equal(t, "anonce", nonce)

        mgr.StoreLoginSession("abc123", "suzy@example.com", "12345", r)
        w.WriteHeader(http.StatusOK)
    })

    router.HandleFunc("/checksession", func(w http.ResponseWriter, r *http.Request) {
        log.Info("Checking login session")
        session, err := mgr.Session(r)
        assert.NoError(t, err)
        assert.NotNil(t, session)
        _, state, _ := mgr.GetState(r)
        assert.Empty(t, state)
        assert.Equal(t, "suzy@example.com", session.Email)
        assert.Equal(t, "12345", session.Sub)
        assert.Equal(t, "abc123", session.RawToken)

        assert.True(t, mgr.ValidateSession(w, r))
        w.WriteHeader(http.StatusOK)
    })

    router.HandleFunc("/checklogout", func(w http.ResponseWriter, r *http.Request) {
        log.Info("Performing logout")
        assert.True(t, mgr.ValidateSession(w, r))

        err := mgr.Logout(r)
        assert.NoError(t, err, "Check logout ok")
        // w.WriteHeader(http.StatusOK)
    })

    router.HandleFunc("/checkloggedout", func(w http.ResponseWriter, r *http.Request) {
        log.Info("Confirm logged out")
        assert.False(t, mgr.ValidateSession(w, r))

        session, err := mgr.Session(r)
        assert.Nil(t, session)
        assert.Error(t, err, fmt.Sprintf("session id %s not found", KeySessionId))
        w.WriteHeader(http.StatusOK)
    })

    ts := newTestServer(t, router)
    defer ts.Close()

    header, body := ts.execute(t, "/login")
    token1 := extractTokenFromCookie(header.Get("Set-Cookie"))
    fmt.Println("Token1\n" + token1)

    fmt.Printf("Body:\n%s\n", body)

    _, body = ts.execute(t, "/checkstate")

    ctx, err := mgr.GetScs().Load(context.Background(), token1)
    assert.NoError(t, err)
    assert.NotNil(t, ctx)
    session := mgr.GetScs().GetString(ctx, KeySessionId)
    assert.NotEmpty(t, session)

    header2, _ := ts.execute(t, "/checksession")
    token2 := extractTokenFromCookie(header2.Get("Set-Cookie"))
    ctx2, err := mgr.GetScs().Load(context.Background(), token2)
    assert.NoError(t, err)
    email := mgr.GetScs().GetString(ctx2, KeyEmail)
    assert.Equal(t, "suzy@example.com", email)

    _, _ = ts.execute(t, "/checklogout")

    header3, _ := ts.execute(t, "/checkloggedout")
    headerValue := header3.Get("Set-Cookie")
    assert.Empty(t, headerValue)
}
