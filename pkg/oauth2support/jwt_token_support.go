package oauth2support

import (
    "context"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "net/http"
    "os"
    "strings"

    log "golang.org/x/exp/slog"

    "github.com/MicahParks/jwkset"
    "github.com/MicahParks/keyfunc/v3"
    "github.com/golang-jwt/jwt/v5"
    "github.com/hexa-org/policy-mapper/pkg/keysupport"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/clientcredentials"
)

const (
    EnvOAuthJwksUrl  string = "HEXA_TOKEN_JWKSURL"
    EnvTknPubKeyFile string = "HEXA_TKN_PUBKEYFILE"
    EnvJwtAuth       string = "HEXA_JWT_AUTH_ENABLE"
    EnvJwtRealm      string = "HEXA_JWT_REALM"
    EnvJwtAudience   string = "HEXA_JWT_AUDIENCE"
    EnvJwtScope      string = "HEXA_JWT_SCOPE"
    EnvJwtKid        string = "HEXA_JWT_KID"

    EnvOAuthClientId      string = "HEXA_OAUTH_CLIENT_ID"
    EnvOAuthClientSecret  string = "HEXA_OAUTH_CLIENT_SECRET"
    EnvOAuthClientScope   string = "HEXA_OAUTH_CLIENT_SCOPE"
    EnvOAuthTokenEndpoint string = "HEXA_OAUTH_TOKEN_ENDPOINT"

    Header_Email string = "X-JWT-EMAIL"
    Header_Subj  string = "X-JWT-SUBJECT"
)

type ResourceJwtAuthorizer struct {
    jwksUrl string
    realm   string
    enable  bool
    Key     keyfunc.Keyfunc
    Aud     string
}

func NewResourceJwtAuthorizer() (*ResourceJwtAuthorizer, error) {
    enable := os.Getenv(EnvJwtAuth)
    if enable == "true" {
        jwksUrl := os.Getenv(EnvOAuthJwksUrl)
        keyPath := os.Getenv(EnvTknPubKeyFile)

        if jwksUrl == "" && keyPath == "" {
            return nil, errors.New(fmt.Sprintf("One of %s or %s environment variables must be set to validate authorizations", EnvOAuthTokenEndpoint, EnvTknPubKeyFile))
        }

        realm := os.Getenv(EnvJwtRealm)
        if realm == "" {
            log.Warn(fmt.Sprintf("Warning: realm environment value not set (%s)", EnvJwtRealm))
            realm = "UNDEFINED"
        }
        aud := os.Getenv(EnvJwtAudience)
        if aud == "" {
            log.Warn(fmt.Sprintf("Warning: audience environment value not set (%s)", EnvJwtAudience))
        }

        if jwksUrl != "" {
            jwkKeyfunc, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksUrl})
            if err != nil {
                log.Error("Failed to create client JWK set. Error: %s", err)
                return nil, err
            }

            return &ResourceJwtAuthorizer{
                jwksUrl: jwksUrl,
                enable:  true,
                Key:     jwkKeyfunc,
                realm:   realm,
                Aud:     aud,
            }, nil
        }

        jwkKeyfunc, err := getKeyFuncFromFile(os.Getenv(EnvJwtKid), keyPath)
        if err != nil {
            log.Error("Failed to load JWK set from file. Error: %s", err)
            return nil, err
        }

        return &ResourceJwtAuthorizer{
            jwksUrl: jwksUrl,
            enable:  true,
            Key:     jwkKeyfunc,
            realm:   realm,
            Aud:     aud,
        }, nil

    }
    log.Info("JWT Authentication disabled.")
    return &ResourceJwtAuthorizer{enable: false}, nil
}

func getKeyFuncFromFile(name string, path string) (keyfunc.Keyfunc, error) {
    pemBytes, err := os.ReadFile(path)
    if err != nil {
        return nil, errors.New(fmt.Sprintf("Unalbe to load public key (%s): %s", path, err.Error()))
    }

    derBlock, _ := pem.Decode(pemBytes)
    publicKey, err := x509.ParsePKCS1PublicKey(derBlock.Bytes)
    if err != nil {
        return nil, err
    }

    jwk, _ := jwkset.NewJWKFromKey(publicKey, jwkset.JWKOptions{
        Metadata: jwkset.JWKMetadataOptions{
            ALG: "RS256",
            KID: name,
        },
    })

    store := jwkset.NewMemoryStorage()
    _ = store.KeyWrite(context.Background(), jwk)

    options := keyfunc.Options{
        Storage: store,
        Ctx:     context.Background(),
    }

    return keyfunc.New(options)

}

func scopeMatch(scopesAccepted []string, scopesHave []string) bool {
    for _, acceptedScope := range scopesAccepted {
        for _, scope := range scopesHave {
            if strings.EqualFold(scope, acceptedScope) {
                return true
            }

        }
    }
    return false
}

func JwtAuthenticationHandler(next http.HandlerFunc, s *ResourceJwtAuthorizer, scopes []string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if s.enable {
            if r.Header.Get("Authorization") == "" {
                log.Info("Request missing authorization header")
                w.Header().Set("www-authenticate", fmt.Sprintf("Bearer realm=\"%s\"", s.realm))
                w.WriteHeader(http.StatusUnauthorized)
                return
            }

            cred, valid := s.authenticate(w, r, scopes)
            if !valid {
                // Error has already been encoded in the response
                return
            }

            // Encode the subject into the header
            subj, err := cred.Claims.GetSubject()
            if err == nil {
                r.Header.Set("X-Subject", subj)
            }
        }
        next(w, r)
    }
}

type AccessToken struct {
    *jwt.RegisteredClaims
    Email string   `json:"email,omitempty"`
    Scope string   `json:"scope,omitempty"`
    Roles []string `json:"roles,omitempty"`
}

func (s *ResourceJwtAuthorizer) ValidateAuthorization(w http.ResponseWriter, r *http.Request, scopes []string) *AccessToken {
    token, valid := s.authenticate(w, r, scopes)

    if !valid {
        return nil
    }
    return token.Claims.(*AccessToken)
}

func (s *ResourceJwtAuthorizer) authenticate(w http.ResponseWriter, r *http.Request, scopeAccepted []string) (*jwt.Token, bool) {
    authorization := r.Header.Get("Authorization")
    if authorization == "" {
        w.Header().Set("www-authenticate", fmt.Sprintf("Bearer realm=\"%s\"", s.realm))
        w.WriteHeader(http.StatusUnauthorized)
        return nil, false
    }

    parts := strings.Split(authorization, " ")
    if len(parts) < 2 {
        headerMsg := fmt.Sprintf("Bearer realm=\"%s\", error=\"invalid_token\", error_description=\"%s\"", s.realm, "Missing authorization type or value")
        w.Header().Set("www-authenticate", headerMsg)
        w.WriteHeader(http.StatusUnauthorized)
        return nil, false
    }

    if strings.EqualFold(parts[0], "bearer") {
        tokenString := strings.TrimSpace(parts[1])

        token, err := jwt.ParseWithClaims(tokenString, &AccessToken{}, s.Key.Keyfunc)

        if err != nil {
            headerMsg := fmt.Sprintf("Bearer realm=\"%s\", error=\"invalid_token\", error_description=\"%s\"", s.realm, err.Error())
            w.Header().Set("www-authenticate", headerMsg)
            w.WriteHeader(http.StatusUnauthorized)
            // log.Printf("Authorization invalid: [%s]\n", err.Error())
            return nil, false
        }

        if claims, ok := token.Claims.(*AccessToken); ok {
            r.Header.Set(Header_Subj, claims.Subject)
            r.Header.Set(Header_Email, claims.Email)
        }

        // Check Audience
        if s.Aud != "" {
            audMatch := false
            var audStrings []string
            audStrings, err = token.Claims.GetAudience()
            if err != nil {
                log.Info("Error parsing audience from token claims: %s", err.Error())
            }
            for _, aud := range audStrings {
                if strings.EqualFold(aud, s.Aud) {
                    audMatch = true
                }
            }
            if !audMatch {
                headerMsg := fmt.Sprintf("Bearer realm=\"%s\", error=\"invalid_token\", error_description=\"invalid audience\"", s.realm)
                w.Header().Set("www-authenticate", headerMsg)
                w.WriteHeader(http.StatusUnauthorized)
                // log.Printf("Authorization invalid: [%s]\n", err.Error())
                return nil, false
            }
        }

        var scopes []string
        atToken := token.Claims.(*AccessToken)
        scopeString := atToken.Scope
        scopes = strings.Split(scopeString, " ")
        sMatch := true
        if scopeAccepted != nil {
            sMatch = scopeMatch(scopeAccepted, scopes)
        }

        // check roles
        if !sMatch {
            tokenRoles := atToken.Roles
            if tokenRoles != nil && len(tokenRoles) > 0 {
                sMatch = scopeMatch(scopeAccepted, tokenRoles)
            }
        }

        if !sMatch {
            scopesRequired := strings.Join(scopeAccepted, ",")
            headerMsg := fmt.Sprintf("Bearer realm=\"%s\", error=\"insufficient_scope\", error_description=\"requires scope=%s\"", s.realm, scopesRequired)
            w.Header().Set("www-authenticate", headerMsg)
            w.WriteHeader(http.StatusForbidden)
            // log.Printf("Authorization invalid: [%s]\n", err.Error())
            return nil, false
        }
        return token, true
    }

    headerMsg := fmt.Sprintf("Bearer realm=\"%s\", error=\"invalid_token\", error_description=\"%s\"", s.realm, "Bearer token required")
    w.Header().Set("www-authenticate", headerMsg)
    w.WriteHeader(http.StatusUnauthorized)
    return nil, false
}

type HTTPClient interface {
    Get(url string) (resp *http.Response, err error)
    Do(req *http.Request) (*http.Response, error)
}

type jwtClient struct {
    State      string `json:"state"`
    Config     *clientcredentials.Config
    httpClient *http.Client
}

type JwtClientHandler interface {
    GetHttpClient() *http.Client
    GetToken() (*oauth2.Token, error)
}

/*
NewJwtClientHandler opens a new JwtClientHandler which allows an OAuth Client to make calls to a JWT protected
endpoint. Configuration parameters are pulled from environment variables.
*/
func NewJwtClientHandler() JwtClientHandler {
    clientId := os.Getenv(EnvOAuthClientId)
    secret := os.Getenv(EnvOAuthClientSecret)
    tokenUrl := os.Getenv(EnvOAuthTokenEndpoint)
    if tokenUrl == "" {
        log.Error(fmt.Sprintf("Error: Token endpoint (%s) not declared", EnvOAuthTokenEndpoint))
    }

    config := &clientcredentials.Config{
        ClientID:     clientId,
        ClientSecret: secret,
        TokenURL:     tokenUrl,
        AuthStyle:    oauth2.AuthStyle(oauth2.AuthStyleAutoDetect),
    }

    return NewJwtClientHandlerWithConfig(config, nil)
}

/*
NewJwtClientHandlerWithConfig opens a new JwtClientHandler which allows an OAuth Client to make calls to a JWT protected
endpoint. The `config` parameter specifies a client credential for the OAuth2 Client Credential Flow. `httpClientOverride`
is used to override the normal HTTP client and will be inserted to the oauth2 http client.
*/
func NewJwtClientHandlerWithConfig(config *clientcredentials.Config, httpClientOverride *http.Client) JwtClientHandler {
    // Set up an http.Client to use and install self-signed CA if needed
    client := &http.Client{}
    if httpClientOverride != nil {
        client = httpClientOverride
    }
    keysupport.CheckCaInstalled(client)

    return &jwtClient{
        Config:     config,
        httpClient: client,
    }
}

// GetHttpClient returns an http.Client object that can be used to make calls to protected services. The client
// automatically appends the authorization header and handles refresh with the OAuth Token Server as needed.
func (j *jwtClient) GetHttpClient() *http.Client {
    // j.httpClient is a client with the self-signed CA installed if needed
    ctx := context.WithValue(context.Background(), oauth2.HTTPClient, j.httpClient)
    return j.Config.Client(ctx)
}

// GetToken returns a token object providing access to access token and refresh token as needed.
func (j *jwtClient) GetToken() (*oauth2.Token, error) {
    return j.Config.TokenSource(context.Background()).Token()
}
