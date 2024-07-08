package mockOidcSupport

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "encoding/json"
    "fmt"
    "testing"

    "net"
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "time"

    "github.com/MicahParks/jwkset"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "github.com/gorilla/mux"
    "github.com/hexa-org/policy-mapper/pkg/healthsupport"
    "golang.org/x/exp/slog"

    "github.com/hexa-org/policy-mapper/pkg/websupport"
)

var log = slog.Default().With("module", "MockOidcServer")

const (
    ErrorWrongKey     = "WrongKey"
    ErrorMissingToken = "NoIdToken"
    ErrorExpiredToken = "ExpiredToken"
    ErrorScope        = "Scope"
    ErrorState        = "State"
    ErrorNonce        = "Nonce"
    ErrorAudience     = "Audience"
    ErrorUnauthorized = "BadClient"
    ErrorForbidden    = "Forbidden"
    ErrorBadCode      = "code"
    ErrorBadTokenForm = "badToken"
)

type MockAuthServer struct {
    Issuer       string
    clientID     string
    secret       string
    claims       map[string]interface{}
    signingKey   SigningKey
    badKey       SigningKey
    Server       *httptest.Server
    Nonce        string
    TriggerError string
    T            *testing.T
}

type SigningKey struct {
    key *rsa.PrivateKey
    id  string
}

func NewMockAuthServer(clientID, secret string, claims map[string]interface{}) *MockAuthServer {
    k, _ := rsa.GenerateKey(rand.Reader, 2048)
    kWrong, _ := rsa.GenerateKey(rand.Reader, 2048)

    authServer := &MockAuthServer{
        signingKey: SigningKey{
            key: k,
            id:  "some-key-id",
        },
        badKey: SigningKey{
            key: kWrong,
            id:  "some-bad-key-id",
        },
        clientID: clientID,
        secret:   secret,
        claims:   claims,
    }
    serveMux := http.NewServeMux()
    serveMux.HandleFunc("/.well-known/openid-configuration", authServer.handleWellKnown)
    serveMux.HandleFunc("/authorize", authServer.handleAuthorize)
    serveMux.HandleFunc("/token", authServer.handleToken)
    serveMux.HandleFunc("/jwks", authServer.handleJWKS)
    serveMux.HandleFunc("/health", healthsupport.HealthHandlerFunction)

    authServer.Server = httptest.NewServer(serveMux)
    authServer.Issuer = authServer.Server.URL

    healthUrl := authServer.Server.URL + "/health"
    _ = healthsupport.WaitForHealthyWithClient(authServer.Server.Config, http.DefaultClient, healthUrl)
    return authServer
}

func (as *MockAuthServer) Shutdown() {
    log.Info("Shutting down Mock OAuth Server...")
    as.Server.CloseClientConnections()
    as.Server.Close()
    log.Info(" OAuth shutdown complete.")
}

func (as *MockAuthServer) handleWellKnown(rw http.ResponseWriter, _ *http.Request) {
    wellKnownConfig := struct {
        Issuer                string `json:"issuer,omitempty"`
        AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
        TokenEndpoint         string `json:"token_endpoint,omitempty"`
        JWKSEndpoint          string `json:"jwks_uri,omitempty"`
    }{
        Issuer:                as.Issuer,
        AuthorizationEndpoint: fmt.Sprintf("%s/authorize", as.Issuer),
        TokenEndpoint:         fmt.Sprintf("%s/token", as.Issuer),
        JWKSEndpoint:          fmt.Sprintf("%s/jwks", as.Issuer),
    }
    _ = json.NewEncoder(rw).Encode(wellKnownConfig)
}

func (as *MockAuthServer) handleAuthorize(rw http.ResponseWriter, r *http.Request) {
    if as.CheckTest(ErrorUnauthorized) {
        rw.WriteHeader(http.StatusUnauthorized)
        return
    }
    if as.CheckTest(ErrorForbidden) {
        rw.WriteHeader(http.StatusForbidden)
        return
    }
    state := r.URL.Query().Get("state")
    if as.CheckTest(ErrorState) {
        state = "wrongState"
    }
    redirect := r.URL.Query().Get("redirect_uri")
    nonce := r.URL.Query().Get("nonce")
    if state != "" && nonce != "" {
        as.Nonce = nonce // this gets used when the ID token is generated.
        if as.CheckTest(ErrorNonce) {
            as.Nonce = "badNonce"
        }
    }
    redirectURI, _ := url.Parse(redirect)
    q := redirectURI.Query()
    if as.CheckTest(ErrorBadCode) {
        q.Set("code", "99")
    } else {
        q.Set("code", "42")
    }

    q.Set("state", state)
    redirectURI.RawQuery = q.Encode()
    rw.Header().Set("Content-Type", "application/x-www-form-urlencoded")

    http.Redirect(rw, r, redirectURI.String(), http.StatusFound)
}

func (as *MockAuthServer) handleToken(rw http.ResponseWriter, r *http.Request) {
    if as.CheckTest(ErrorUnauthorized) {
        http.Error(rw, "Client credential required", http.StatusUnauthorized)
        return
    }
    if as.CheckTest(ErrorForbidden) {
        http.Error(rw, "Invalid access", http.StatusForbidden)

        return
    }
    _ = r.ParseForm()
    scope := r.FormValue("scope")
    var scopes []string
    if scope != "" {
        scopes = strings.Split(scope, " ")
    }
    var token string
    var err error

    grantType := r.FormValue("grant_type")
    switch grantType {
    case "client_credentials":
        username, secret, ok := r.BasicAuth()

        if !ok {
            log.Error(fmt.Sprintf("Error: token request missing/incorrect authorization from %s", r.RemoteAddr))
            http.Error(rw, "Client credential required", http.StatusUnauthorized)
            return
        }
        if !strings.EqualFold(as.clientID, username) || as.secret != secret {
            log.Error(fmt.Sprintf("Error: token request authenticaiton failure from: %s, %s", username, r.RemoteAddr))
            http.Error(rw, "Client credential required", http.StatusUnauthorized)
            return
        }
        log.Info(fmt.Sprintf("Issuing token/client_credentials response to: %s, %s", username, r.RemoteAddr))
        token, err = as.BuildJWT(60, scopes, []string{"orchestrator", as.clientID}, "", false)
    case "authorize", "authorization_code":
        if r.FormValue("code") != "42" {
            http.Error(rw, fmt.Sprintf("invalid authorization code"), http.StatusBadRequest)
            return
        }

        log.Info(fmt.Sprintf("Issuing token/authorize response to: %s", r.RemoteAddr))
        token, err = as.BuildJWT(2, nil, []string{"orchestrator", as.clientID}, as.Nonce, false)
    }

    if err != nil {
        http.Error(rw, fmt.Sprintf("unable to build token: %s", err), http.StatusInternalServerError)
        return
    }

    idToken := token
    if as.CheckTest(ErrorBadTokenForm) {
        idToken, err = as.BuildJWT(2, nil, []string{"orchestrator", as.clientID}, as.Nonce, true)
    }

    refresh, err := as.BuildJWT(60, []string{"refresh"}, []string{"orchestrator", as.clientID}, "", false)

    resp := struct {
        AccessToken  string `json:"access_token,omitempty"`
        TokenType    string `json:"token_type"`
        ExpiresIn    int    `json:"expires_in"`
        RefreshToken string `json:"refresh_token,omitempty"`
        Scope        string `json:"scope"`
        IDToken      string `json:"id_token,omitempty"`
    }{
        AccessToken:  token,
        TokenType:    "Bearer",
        ExpiresIn:    2,
        RefreshToken: refresh,
        IDToken:      idToken,
    }

    if as.CheckTest(ErrorMissingToken) {
        // resp.AccessToken = ""
        resp.IDToken = ""
    }

    rw.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(rw).Encode(resp)
}

func (as *MockAuthServer) handleJWKS(rw http.ResponseWriter, _ *http.Request) {
    rw.Header().Set("Content-Type", "application/json")
    _, err := rw.Write(as.Jwks())

    if err != nil {
        log.Error("unable to encode jwks: ", err.Error())
    }
}

func (as *MockAuthServer) Jwks() []byte {

    publicKey := as.signingKey.key.Public()

    jwkstore := jwkset.NewMemoryStorage()

    // Create the JWK options.
    metadata := jwkset.JWKMetadataOptions{
        KID: as.signingKey.id,
    }
    jwkOptions := jwkset.JWKOptions{
        Metadata: metadata,
    }

    jwkSet, _ := jwkset.NewJWKFromKey(publicKey, jwkOptions)

    _ = jwkstore.KeyWrite(context.Background(), jwkSet)
    jsonKey, _ := jwkstore.JSONPublic(context.Background())

    resp, _ := jsonKey.MarshalJSON()
    return resp
}

type AccessTokenData struct {
    *jwt.RegisteredClaims
    Scope string `json:"scope"`
    Nonce string `json:"nonce"`
    Email string `json:"email"`
}

type MalformedTokenData struct {
    *jwt.RegisteredClaims
    Scope string   `json:"scope"`
    Nonce []string `json:"nonce"`
    Email string   `json:"email"`
}

func (as *MockAuthServer) BuildJWT(expireSecs int64, scopes []string, audience []string, nonce string, malformed bool) (string, error) {
    issuedAt := time.Now()
    if expireSecs == 0 {
        expireSecs = 60
    }

    expiresAt := issuedAt.Add(time.Duration(expireSecs) * time.Second)
    if as.CheckTest(ErrorExpiredToken) {
        expiresAt = issuedAt              // token expires immediately
        time.Sleep(time.Millisecond * 10) // wait to ensure expired
    }

    var scopeString string
    if scopes != nil {
        scopeString = strings.Join(scopes, " ")
    } else {
        scopeString = "orchestrator"
    }
    if as.CheckTest(ErrorScope) {
        scopeString = "badscope"
    }

    type BadTokenData struct {
    }
    var claims jwt.Claims
    if malformed {
        claims = MalformedTokenData{
            &jwt.RegisteredClaims{
                Issuer:    as.Issuer,
                Audience:  audience,
                Subject:   as.clientID,
                ExpiresAt: jwt.NewNumericDate(expiresAt),
                IssuedAt:  jwt.NewNumericDate(issuedAt),
                ID:        uuid.NewString(),
            },

            scopeString,
            []string{nonce},
            "alice@example.com",
        }
    } else {
        setNonce := nonce
        if as.CheckTest(ErrorNonce) {
            setNonce = "badNonceValue"
        }
        setAudience := audience
        if as.CheckTest(ErrorAudience) {
            setAudience = []string{"badAudience"}
        }
        claims = AccessTokenData{
            &jwt.RegisteredClaims{
                Issuer:    as.Issuer,
                Audience:  setAudience,
                Subject:   as.clientID,
                ExpiresAt: jwt.NewNumericDate(expiresAt),
                IssuedAt:  jwt.NewNumericDate(issuedAt),
                ID:        uuid.NewString(),
            },

            scopeString,
            setNonce,
            "alice@example.com",
        }

    }

    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

    token.Header["typ"] = "at+jwt"
    token.Header["kid"] = as.signingKey.id

    signKey := as.signingKey.key
    if as.CheckTest(ErrorWrongKey) {
        signKey = as.badKey.key
    }

    raw, err := token.SignedString(signKey)
    if err != nil {
        return "", fmt.Errorf("failed to sign claims: %w", err)
    }

    return raw, nil
}

type MockResourceServer struct {
    Server *http.Server
}

func NewMockResourceServer(path string, wrapperFunc http.HandlerFunc) *MockResourceServer {
    listener, _ := net.Listen("tcp", "localhost:0")

    resServer := &MockResourceServer{}

    server := websupport.Create(listener.Addr().String(), func(router *mux.Router) {
        router.HandleFunc(path, wrapperFunc)
    }, websupport.Options{})

    resServer.Server = server

    go websupport.Start(server, listener)

    return resServer
}

func (as *MockResourceServer) Shutdown() {
    log.Info("Shutting down Mock Resource Server...")
    err := as.Server.Close()
    if err != nil {
        log.Error(err.Error())
    }
    err = as.Server.Shutdown(context.Background())
    if err != nil {
        log.Error(err.Error())
    }
    log.Info(" OAuth shutdown complete.")
}

func HandleHello(w http.ResponseWriter, r *http.Request) {
    subject := r.Header.Get("X-Subject")
    if subject != "" {
        _, _ = w.Write([]byte(fmt.Sprintf("Hello %s!", subject)))
        return
    }
    _, _ = w.Write([]byte("Hello World!"))
}

func (as *MockAuthServer) CheckTest(errorType string) bool {
    if as.TriggerError == errorType {
        as.TriggerError = ""
        return true
    }
    return false
}
