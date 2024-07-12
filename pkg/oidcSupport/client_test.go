package oidcSupport

import (
    "embed"
    "errors"
    "fmt"
    "io"
    "net/http"
    "net/http/cookiejar"
    "net/http/httptest"
    "net/url"
    "os"
    "testing"

    "github.com/gorilla/mux"
    "github.com/hexa-org/policy-mapper/pkg/oauth2support"

    "github.com/hexa-org/policy-mapper/pkg/mockOidcSupport"
    "github.com/hexa-org/policy-mapper/pkg/sessionSupport"
    "github.com/stretchr/testify/assert"
)

//go:embed resources/templates/*
var resources embed.FS

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

func newMockServer(t *testing.T) *mockOidcSupport.MockAuthServer {
    claims := map[string]interface{}{}
    mockAuth := mockOidcSupport.NewMockAuthServer("aClient", "secret", claims)
    mockerAddr := mockAuth.Server.URL
    mockUrlJwks, err := url.JoinPath(mockerAddr, "/jwks")
    assert.NoError(t, err)
    _ = os.Setenv(oauth2support.EnvOAuthJwksUrl, mockUrlJwks)
    _ = os.Setenv(oauth2support.EnvOAuthJwksUrl, mockUrlJwks)
    _ = os.Setenv(EnvOidcClientId, "aClient")
    _ = os.Setenv(EnvOidcClientSecret, "secret")
    _ = os.Setenv(EnvOidcProviderUrl, mockerAddr)
    return mockAuth
}

func (ts *testServer) execute(t *testing.T, urlPath string) (*http.Response, string) {
    destUrl := urlPath
    checkUrl, _ := url.Parse(urlPath)
    if checkUrl.Host == "" {
        destUrl = ts.URL + urlPath
    }
    rs, err := ts.Client().Get(destUrl)
    if err != nil {
        t.Fatal(err)
    }

    defer rs.Body.Close()
    body, err := io.ReadAll(rs.Body)
    if err != nil {
        t.Fatal(err)
    }

    return rs, string(body)
}

func TestOidcLogin(t *testing.T) {
    router := mux.NewRouter()
    _ = os.Setenv(EnvOidcEnabled, "true")
    mockAuth := newMockServer(t)
    sessionHandler := sessionSupport.NewSessionManager()
    _ = os.Setenv(EnvOidcRedirectUrl, "/redirect")
    oidcHandler, err := NewOidcClientHandler(sessionHandler, resources)
    assert.Nil(t, err)
    oidcHandler.InitHandlers(router)

    router.HandleFunc("/integrations", oidcHandler.HandleSessionScope(func(w http.ResponseWriter, r *http.Request) {
        log.Info("Integrations called")
        sessionInfo, err := sessionHandler.Session(r)
        assert.Nil(t, err)
        assert.Equal(t, sessionInfo.Email, "alice@example.com")
        w.WriteHeader(http.StatusOK)
    }, []string{}))

    ts := newTestServer(t, router)
    oidcHandler.ClientConfig.RedirectURL = ts.URL + "/redirect"
    defer ts.Close()
    defer mockAuth.Shutdown()

    log.Info("Attempting to access /integrations - should be redirected to root")
    resp, body := ts.execute(t, "/integrations")
    assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
    assert.Equal(t, "<a href=\"/\">Temporary Redirect</a>.\n\n", body)
    log.Debug("Body:\n", body)

    location, err := resp.Location()
    assert.Nil(t, err)
    assert.Equal(t, "/", location.Path)

    log.Info("Redirecting to root /")
    resp, body = ts.execute(t, location.String())
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Contains(t, body, "<a href=\"/authorize\" class=\"login\">Login using OIDC</a>")

    log.Info("Attempting to access /authorize")
    resp, body = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err := resp.Location()
    assert.Nil(t, err)

    assert.Contains(t, authorizeLocation.String(), oidcHandler.ClientConfig.Endpoint.AuthURL)

    log.Info("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, body = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    redirectLocation, err := resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    log.Debug("Attempting to access callback: " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

    log.Info("Attempting to access /integrations")
    redirectLocation, err = resp.Location()

    assert.Contains(t, redirectLocation.String(), "/integrations")
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    log.Info("Testing logout")

    client := ts.Client()
    serverUrl, _ := url.Parse(ts.Server.URL)
    cookies := client.Jar.Cookies(serverUrl)
    assert.Greater(t, len(cookies), 0)
    hexaCookie := cookies[0]
    assert.Equal(t, sessionSupport.HexaCookie, hexaCookie.Name)
    resp, body = ts.execute(t, "/logout")

    cookiesAfter := client.Jar.Cookies(serverUrl)
    assert.Nil(t, cookiesAfter)
    assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
}

func TestOidcDisabled(t *testing.T) {
    router := mux.NewRouter()
    _ = os.Setenv(EnvOidcEnabled, "false")

    sessionHandler := sessionSupport.NewSessionManager()
    _ = os.Setenv(EnvOidcRedirectUrl, "/redirect")
    oidcHandler, err := NewOidcClientHandler(sessionHandler, resources)
    assert.Nil(t, err)
    oidcHandler.InitHandlers(router)

    integrationsCalled := false
    rootCalled := false

    router.HandleFunc("/integrations", oidcHandler.HandleSessionScope(func(w http.ResponseWriter, r *http.Request) {
        log.Info("Integrations called")
        integrationsCalled = true
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("success!"))
    }, []string{}))

    router.HandleFunc("/", oidcHandler.HandleSessionScope(func(w http.ResponseWriter, r *http.Request) {
        log.Info("Root")
        rootCalled = true
        http.Redirect(w, r, "/integrations", http.StatusTemporaryRedirect)
    }, []string{}))

    ts := newTestServer(t, router)

    defer ts.Close()

    log.Info("Attempting to access root(/) - should be redirected to /integrations")
    resp, body := ts.execute(t, "/")
    assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
    assert.True(t, rootCalled)
    redirectLocation, err := resp.Location()
    assert.Nil(t, err)
    assert.Equal(t, "/integrations", redirectLocation.Path)

    log.Info("Attempting to access integrations) - should be ok")
    resp, body = ts.execute(t, "/integrations")
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    // fmt.Println("Body:\n", body)
    assert.True(t, integrationsCalled)
    assert.Equal(t, "success!", body)
}

func TestOidcNegative(t *testing.T) {
    router := mux.NewRouter()
    _ = os.Setenv(EnvOidcEnabled, "true")
    mockAuth := newMockServer(t)
    sessionHandler := sessionSupport.NewSessionManager()
    _ = os.Setenv(EnvOidcRedirectUrl, "/redirect")
    oidcHandler, err := NewOidcClientHandler(sessionHandler, resources)
    assert.Nil(t, err)
    oidcHandler.InitHandlers(router)

    router.HandleFunc("/integrations", oidcHandler.HandleSessionScope(func(w http.ResponseWriter, r *http.Request) {
        log.Info("Integrations called")
        sessionInfo, err := sessionHandler.Session(r)
        assert.Nil(t, err)
        assert.Equal(t, sessionInfo.Email, "alice@example.com")
        w.WriteHeader(http.StatusOK)
    }, []string{}))

    ts := newTestServer(t, router)
    oidcHandler.ClientConfig.RedirectURL = ts.URL + "/redirect"
    defer ts.Close()
    defer mockAuth.Shutdown()

    // ----------
    log.Info("Authorization Req Flow - Code error")
    resp, _ := ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err := resp.Location()
    assert.Nil(t, err)
    stateOut := authorizeLocation.Query().Get("state")
    assert.Contains(t, authorizeLocation.String(), oidcHandler.ClientConfig.Endpoint.AuthURL)

    mockAuth.TriggerError = mockOidcSupport.ErrorState

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    redirectLocation, err := resp.Location()
    stateBack := redirectLocation.Query().Get("state")
    assert.Nil(t, err)
    assert.NotEqual(t, stateOut, stateBack, "state should be wrong")
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    log.Debug("Attempting to access callback: " + redirectLocation.String())
    resp, body := ts.execute(t, redirectLocation.String())
    assert.Contains(t, body, "Session state and request state mismatch")
    fmt.Println(body)
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    // ----------
    log.Info("Authorization Req Flow - Nonce error")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)
    stateOut = authorizeLocation.Query().Get("state")
    assert.Contains(t, authorizeLocation.String(), oidcHandler.ClientConfig.Endpoint.AuthURL)

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    mockAuth.TriggerError = mockOidcSupport.ErrorNonce
    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    log.Debug("Attempting to access callback: " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "nonce was not matched")

    // ----------
    log.Info("Authorization Req Flow - Invalid Aud")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)
    stateOut = authorizeLocation.Query().Get("state")
    assert.Contains(t, authorizeLocation.String(), oidcHandler.ClientConfig.Endpoint.AuthURL)

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)
    mockAuth.TriggerError = mockOidcSupport.ErrorAudience

    log.Debug("Attempting to access callback (wrong Audience): " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "Could not validate OIDC ID Token")

    // ----------
    log.Info("Authorization Req Flow - Invalid Code")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)
    mockAuth.TriggerError = mockOidcSupport.ErrorBadCode

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    log.Debug("Attempting to access callback (wrong Audience): " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "error on token exchange")

    // ----------
    log.Info("Authorization Req Flow - Invalid Session")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    // delete session cookies to cause invalid session error
    client := ts.Client()
    serverUrl, _ := url.Parse(ts.Server.URL)
    cookies := client.Jar.Cookies(serverUrl)
    assert.Greater(t, len(cookies), 0)
    hexaCookie := cookies[0]
    hexaCookie.MaxAge = -1

    client.Jar.SetCookies(serverUrl, []*http.Cookie{hexaCookie})
    log.Debug("Attempting to access callback (wrong Audience): " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "Invalid session state/nonce detected")

    // ----------
    log.Info("Authorization Req Flow - Missing token")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    mockAuth.TriggerError = mockOidcSupport.ErrorMissingToken
    log.Debug("Attempting to access callback (wrong Audience): " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "Missing ID token in provider response")

    // ----------
    log.Info("Authorization Req Flow - Token parse error")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    mockAuth.TriggerError = mockOidcSupport.ErrorBadTokenForm
    log.Debug("Attempting to access callback (wrong Audience): " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "json: cannot unmarshal array")

    // ----------
    log.Info("Authorization Req Flow - Unauthorized")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)

    mockAuth.TriggerError = mockOidcSupport.ErrorUnauthorized

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

    // This time should work
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    log.Info("Trigger authorization error at token exchange")
    mockAuth.TriggerError = mockOidcSupport.ErrorUnauthorized

    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    log.Debug("Attempting to access callback: " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "cannot fetch token: 401 Unauthorized")

    // ----------
    log.Info("Authorization Req Flow - Forbidden")
    resp, _ = ts.execute(t, "/authorize")
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    authorizeLocation, err = resp.Location()
    assert.Nil(t, err)

    mockAuth.TriggerError = mockOidcSupport.ErrorForbidden

    log.Debug("Redirecting to Mock authorizer at: " + authorizeLocation.String())
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusForbidden, resp.StatusCode)

    // This time should work
    resp, _ = ts.execute(t, authorizeLocation.String())
    assert.Equal(t, http.StatusFound, resp.StatusCode)

    log.Info("Trigger authorization error at token exchange")
    mockAuth.TriggerError = mockOidcSupport.ErrorForbidden

    redirectLocation, err = resp.Location()
    assert.Nil(t, err)
    assert.Contains(t, redirectLocation.String(), oidcHandler.ClientConfig.RedirectURL)

    log.Debug("Attempting to access callback: " + redirectLocation.String())
    resp, body = ts.execute(t, redirectLocation.String())
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    assert.Contains(t, body, "cannot fetch token: 403 Forbidden")

}

func TestOidcConfiguration(t *testing.T) {
    _ = os.Unsetenv(EnvOidcRedirectUrl)

    _ = os.Unsetenv(EnvOidcProviderUrl)
    _ = os.Unsetenv(EnvOidcRedirectUrl)

    _ = os.Setenv(EnvOidcEnabled, "true")
    _ = os.Setenv(oauth2support.EnvOAuthJwksUrl, "https://mock.com/jwks")
    _ = os.Setenv(oauth2support.EnvOAuthClientId, "aClient")
    _ = os.Setenv(oauth2support.EnvOAuthClientSecret, "secret")
    sessionHandler := sessionSupport.NewSessionManager()
    oidcHandler, err := NewOidcClientHandler(sessionHandler, resources)

    assert.Error(t, err, "missing OIDC provider URL (HEXA_OIDC_PROVIDER_URL)")
    assert.NotNil(t, oidcHandler)
    assert.False(t, oidcHandler.Enabled)

    mockAuth := newMockServer(t)
    defer mockAuth.Shutdown()
    _ = os.Unsetenv(EnvOidcClientId) // Force config to fall back to OAuth settings
    _ = os.Unsetenv(EnvOidcClientSecret)
    oidcHandler, err = NewOidcClientHandler(sessionHandler, resources)
    assert.NoError(t, err)
    assert.Equal(t, "aClient", oidcHandler.ClientConfig.ClientID)
    assert.Equal(t, "secret", oidcHandler.ClientConfig.ClientSecret)
    assert.Equal(t, "/redirect", oidcHandler.ClientConfig.RedirectURL)

    _ = os.Unsetenv(oauth2support.EnvOAuthClientSecret)
    _ = os.Unsetenv(oauth2support.EnvOAuthClientId)
    _ = os.Unsetenv(EnvOidcClientId)

    oidcHandler, err = NewOidcClientHandler(sessionHandler, resources)
    assert.Error(t, err, fmt.Errorf("missing %s environment variable", EnvOidcClientId))

    _ = os.Setenv(EnvOidcClientId, "aClient")
    _ = os.Unsetenv(EnvOidcClientSecret)

    oidcHandler, err = NewOidcClientHandler(sessionHandler, resources)
    assert.Error(t, err, fmt.Errorf("missing %s environment variable", EnvOidcClientSecret))

    _ = os.Setenv(EnvOidcClientSecret, "secret")
    _ = os.Setenv(EnvOidcProviderUrl, "noWhereToGo.com/")
    oidcHandler, err = NewOidcClientHandler(sessionHandler, resources)
    assert.Error(t, err)
    var urlError *url.Error
    isUrlError := errors.As(err, &urlError)
    assert.True(t, isUrlError)

    _ = os.Setenv(EnvOidcProviderUrl, "http://localnohost/")
    oidcHandler, err = NewOidcClientHandler(sessionHandler, resources)
    assert.Error(t, err)

}
