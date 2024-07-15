package oidcSupport

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "io/fs"
    "net/http"
    "net/url"
    "os"
    "strings"

    "github.com/coreos/go-oidc/v3/oidc"
    "github.com/gorilla/mux"
    "github.com/hexa-org/policy-mapper/pkg/oauth2support"
    "github.com/hexa-org/policy-mapper/pkg/sessionSupport"
    "github.com/hexa-org/policy-mapper/pkg/websupport"
    "golang.org/x/exp/slog"
    "golang.org/x/oauth2"
)

const (
    EnvOidcProviderName = "HEXA_OIDC_PROVIDER_NAME"
    EnvOidcEnabled      = "HEXA_OIDC_ENABLED"
    EnvOidcClientId     = "HEXA_OIDC_CLIENT_ID"
    EnvOidcClientSecret = "HEXA_OIDC_CLIENT_SECRET"
    EnvOidcProviderUrl  = "HEXA_OIDC_PROVIDER_URL"
    EnvOidcRedirectUrl  = "HEXA_OIDC_REDIRECT_URL"
    EnvOidcLoginPath    = "HEXA_OIDC_LOGIN_PATH"  // HEXA_OIDC_LOGIN_URL is the handler path that will be used to start a login flow to the OIDC provider (default: /login)
    EnvOidcLogoutPath   = "HEXA_OIDC_LOGOUT_PATH" // HEXA_OIDC_LOGOUT_PATH is the path used to cancel the local session (default: /logout)
    DefOidcProviderName = "OpenID Login"
    DefOidcRedirectPath = "/redirect"
    DefOidcLoginPath    = "/"
    DefOidcLogoutPath   = "/logout"
)

type Handler func(http.ResponseWriter, *http.Request) error

type OidcClientHandler struct {
    ClientConfig   *oauth2.Config
    OidcConfig     *oidc.Config
    Verifier       *oidc.IDTokenVerifier
    Provider       *oidc.Provider
    LogoutPath     string
    LoginPath      string
    AuthPath       string
    Enabled        bool
    SessionHandler sessionSupport.SessionManager
    Middleware     func(handler Handler) Handler
    ErrorHandler   func(handler func(w http.ResponseWriter, r *http.Request) error) http.Handler
    MainPage       string
    ProviderName   string
    Resources      fs.FS
}

var log = slog.Default().With("module", "oidcClient")

var disabledHandler = &OidcClientHandler{Enabled: false, SessionHandler: sessionSupport.NewSessionManager()}

func NewOidcClientHandler(sessionHandler sessionSupport.SessionManager, resources fs.FS) (*OidcClientHandler, error) {
    enabled := os.Getenv(EnvOidcEnabled)
    if enabled == "" || !strings.EqualFold(enabled[0:1], "t") {
        log.Warn(fmt.Sprintf("OIDC Authentication (%s) is not enabled", EnvOidcEnabled))
        if sessionHandler != nil {
            disabledHandler.SessionHandler = sessionHandler
        }
        return disabledHandler, nil
    }
    clientId := os.Getenv(EnvOidcClientId)
    clientSecret := os.Getenv(EnvOidcClientSecret)
    providerUrl := os.Getenv(EnvOidcProviderUrl)
    redirectUrl := os.Getenv(EnvOidcRedirectUrl)
    if redirectUrl == "" {
        log.Warn("OIDC Redirect URL not configured, defaulting to relative path: " + DefOidcRedirectPath)
        log.Warn("Using relative redirect URL would need to configured with a wildcard mask which carries additional risk!")

        redirectUrl = DefOidcRedirectPath
    }
    loginUrl := os.Getenv(EnvOidcLoginPath)
    if loginUrl == "" {
        loginUrl = DefOidcLoginPath
    }
    logoutUrl := os.Getenv(EnvOidcLogoutPath)
    if logoutUrl == "" {
        logoutUrl = DefOidcLogoutPath
    }

    if clientId == "" {
        clientId = os.Getenv(oauth2support.EnvOAuthClientId)
        if clientId == "" {
            return disabledHandler, fmt.Errorf("missing %s environment variable", EnvOidcClientId)
        }
        log.Info("Using OAuth ClientId instead of OIDC ClientID", "clientId", clientId)
    }
    if clientSecret == "" {
        clientSecret = os.Getenv(oauth2support.EnvOAuthClientSecret)
        if clientSecret == "" {
            return disabledHandler, fmt.Errorf("missing %s environment variable", EnvOidcClientSecret)
        }
    }
    if providerUrl == "" {
        err := fmt.Errorf("missing OIDC provider URL (%s)", EnvOidcProviderUrl)
        log.Error("OIDC Not Configured: " + err.Error())
        return disabledHandler, err
    }

    providerName := os.Getenv(EnvOidcProviderName)
    if providerName == "" {
        providerName = DefOidcProviderName
    }
    // http: // 127.0.0.1:8080/realms/Hexa-Orchestrator-Realm/.well-known/openid-configuration
    provider, err := oidc.NewProvider(context.Background(), providerUrl)
    if err != nil {
        return disabledHandler, err
    }

    log.Info("OIDC Configured", "providerUrl", providerUrl, "clientId", clientId, "redirecturl", redirectUrl)

    clientConfig := &oauth2.Config{
        ClientID:     clientId,
        ClientSecret: clientSecret,
        RedirectURL:  redirectUrl,
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }
    oidcConfig := &oidc.Config{
        ClientID: clientConfig.ClientID,
    }
    verifier := provider.Verifier(oidcConfig)

    o := &OidcClientHandler{ClientConfig: clientConfig,
        OidcConfig:     oidcConfig,
        Verifier:       verifier,
        Provider:       provider,
        Enabled:        true,
        LoginPath:      loginUrl,
        AuthPath:       "/authorize",
        LogoutPath:     logoutUrl,
        ProviderName:   providerName,
        Resources:      resources,
        SessionHandler: sessionHandler,
    }
    // errorHandling is a middleware that centralises error handling.
    // this prevents a lot of duplication and prevents issues where a missing
    // return causes an error to be printed, but functionality to otherwise continue
    // see https://blog.golang.org/error-handling-and-go
    errorHandling := func(handler func(w http.ResponseWriter, r *http.Request) error) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if err := handler(w, r); err != nil {
                var errorString = "Something went wrong! Please try again."
                // var errorCode int = 500

                if v, ok := err.(HumanReadableError); ok {
                    errorString = v.HumanError()
                }

                w.WriteHeader(http.StatusBadRequest)
                model := websupport.Model{Map: map[string]interface{}{"resource": "login", "error": err.Error(), "humanerror": errorString, "session": sessionSupport.SessionInfo{}}}
                _ = websupport.ModelAndView(w, o.Resources, "login", model)

                // log.Warn(err.Error())

                return
            }
        })
    }
    o.ErrorHandler = errorHandling

    return o, nil
}

// InitHandlers initalizes the SessionHandler middleware and configures the login/logout/authorize endpoints if enabled
func (o *OidcClientHandler) InitHandlers(router *mux.Router) {
    o.SessionHandler.SetSessionMiddleware(router)
    if o.Enabled {

        handleFunc := func(path string, handler Handler) {
            router.Handle(path, o.ErrorHandler(handler))
        }
        handleFunc(o.LoginPath, o.HandleLogin)
        handleFunc(o.AuthPath, o.HandleAuthorize)
        handleFunc(o.LogoutPath, o.HandleLogout)
        redirectUrl, err := url.Parse(o.ClientConfig.RedirectURL)
        if err != nil {
            panic(err)
        }
        handleFunc(redirectUrl.Path, o.HandleOAuth2Callback)
    }
}

func (o *OidcClientHandler) HandleSessionScope(next http.HandlerFunc, _ []string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if o.Enabled {
            // if not subject is set, then there is no valid session
            if o.SessionHandler.ValidateSession(w, r) {
                // TODO Check scopes
                next.ServeHTTP(w, r)
            }
            http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        } else {
            next.ServeHTTP(w, r)
        }
    }
}

// HandleLogin is a Handler that shows a login button. In production, if the frontend is served / generated
// by Go, it should use html/template to prevent XSS attacks.
func (o *OidcClientHandler) HandleLogin(w http.ResponseWriter, _ *http.Request) (err error) {
    model := websupport.Model{Map: map[string]interface{}{"resource": "login", "authurl": o.AuthPath, "humanError": "", "error": ""}}
    _ = websupport.ModelAndView(w, o.Resources, "login", model)

    return
}

func (o *OidcClientHandler) HandleLogout(w http.ResponseWriter, r *http.Request) (err error) {
    session, err := o.SessionHandler.Session(r)
    if err == nil && session != nil {
        log.Info("Session logged out", "session", session.Session)
        _ = o.SessionHandler.Logout(r) // Kill the local session
    }
    // TODO Implement logout to OP (e.g to force re-authentication)

    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
    return
}

// HandleAuthorize is a Handler that redirects the user to Twitch for login, and provides the 'state'
// parameter which protects against login CSRF.
func (o *OidcClientHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) (err error) {
    state := randString(16)
    nonce := randString(16)
    sessionVal := o.SessionHandler.StartLogin(state, nonce, r)

    log.Info("Initiating login", "session", sessionVal)
    http.Redirect(w, r, o.ClientConfig.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.SetAuthURLParam("claims", `{"id_token":{"email":null,"roles":null}}`), oauth2.SetAuthURLParam("prompt", "login")), http.StatusFound)

    return
}

// HandleOAuth2Callback is a Handler for oauth's 'redirect_uri' endpoint;
// it validates the state token and retrieves an OAuth token from the request parameters.
func (o *OidcClientHandler) HandleOAuth2Callback(w http.ResponseWriter, r *http.Request) (err error) {
    sessionVal, state, nonce := o.SessionHandler.GetState(r)

    if sessionVal == "" || state == "" || nonce == "" {
        log.Warn("State cookie not found", "session", sessionVal)
        return AnnotateError(
            fmt.Errorf("session state missing on redirect"),
            "Invalid session state/nonce detected, check cookie settings and try again.",
            http.StatusBadRequest,
        )
    }
    queryState := r.URL.Query().Get("state")
    if queryState != state {
        log.Warn("State mismatch on redirect", "session", sessionVal)
        return AnnotateError(
            fmt.Errorf("session state and request state mismatch on redirect"),
            "Invalid session state detected, please try again.",
            http.StatusBadRequest,
        )
    }

    token, err := o.ClientConfig.Exchange(context.Background(), r.FormValue("code"))
    if err != nil {
        log.Warn(fmt.Sprintf("Error exchanging code for token: %s", err), "session", sessionVal)
        return AnnotateError(
            err,
            "OIDC Provider returned error on token exchange, please try again.",
            http.StatusBadRequest,
        )
    }

    log.Debug(fmt.Sprintf("Access token: %s\n", token.AccessToken))

    rawIDToken, ok := token.Extra("id_token").(string)
    if !ok {
        log.Warn("Raw ID token missing from token exchange response", "session", sessionVal)
        return AnnotateError(
            fmt.Errorf("OIDC Provider response missing ID Token"),
            "Missing ID token in provider response, please try again.",
            http.StatusBadRequest,
        )
    }

    idToken, err := o.Verifier.Verify(context.Background(), rawIDToken)
    if err != nil {
        return AnnotateError(
            err,
            "Could not validate OIDC ID Token, please try again.",
            http.StatusBadRequest,
        )
    }

    if idToken.Nonce != nonce {
        log.Warn("Nonce mismatch", "session", sessionVal)
        return AnnotateError(
            fmt.Errorf("nonce was not matched"),
            "An error validating authorization, please try again",
            http.StatusBadRequest)
    }

    var claims struct {
        Iss   string   `json:"iss"`
        Sub   string   `json:"sub"`
        Aud   []string `json:"aud"`
        Exp   int32    `json:"exp"`
        Iat   int32    `json:"iat"`
        Nonce string   `json:"cookieOauthNonce"`
        Email string   `json:"email"`
    }

    if err := idToken.Claims(&claims); err != nil {
        // TODO Not clear how an error can occur as validate already traps JSON errors. Ignore?
        return AnnotateError(
            err,
            "Could not parse ID token claims, please try again.",
            http.StatusBadRequest,
        )
    }

    o.SessionHandler.StoreLoginSession(rawIDToken, claims.Email, claims.Sub, r)

    log.Info("Session started", "session", sessionVal, "email", claims.Email, "sub", claims.Sub)

    mainPage := o.MainPage
    if mainPage == "" {
        mainPage = "/integrations"
    }
    http.Redirect(w, r, mainPage, http.StatusTemporaryRedirect)

    return
}

// ParseIdTokenClaims parses a raw token into a claims struct specified by claims
func (o *OidcClientHandler) ParseIdTokenClaims(rawIDToken string, claims interface{}) (err error) {
    idToken, err := o.Verifier.Verify(context.Background(), rawIDToken)
    if err != nil {
        return err
    }

    return idToken.Claims(&claims)
}

// HumanReadableError represents error information
// that can be fed back to a human user.
//
// This prevents internal state that might be sensitive
// being leaked to the outside world.
//
// It's also useful because raw error strings rarely make much
// sense to a human.
type HumanReadableError interface {
    HumanError() string
    HTTPCode() int
}

// HumanReadableWrapper implements HumanReadableError
type HumanReadableWrapper struct {
    ToHuman string
    Code    int
    error
}

func (h HumanReadableWrapper) HumanError() string { return h.ToHuman }
func (h HumanReadableWrapper) HTTPCode() int      { return h.Code }

// AnnotateError wraps an error with a message that is intended for a human end-user to read,
// plus an associated HTTP error code.
func AnnotateError(err error, annotation string, _ int) error {
    if err == nil {
        return nil
    }
    return HumanReadableWrapper{ToHuman: annotation, error: err}
}

func randString(nByte int) string {
    b := make([]byte, nByte)
    if _, err := io.ReadFull(rand.Reader, b); err != nil {
        panic(err)
    }
    return base64.RawURLEncoding.EncodeToString(b)
}
