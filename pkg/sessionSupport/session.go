package sessionSupport

import (
    "fmt"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/alexedwards/scs/v2"
    "github.com/alexedwards/scs/v2/memstore"
    "github.com/google/uuid"
    "github.com/gorilla/mux"
    log "golang.org/x/exp/slog"
)

const (
    EnvOidcEnabled = "HEXA_OIDC_ENABLED"
    KeyHexaState   = "hexa-state"
    KeyHexaNonce   = "hexa-nonce"
    KeyEmail       = "email"
    KeySubject     = "sub"
    KeyIdToken     = "idtoken"
    KeySessionId   = "session-id"
    HexaCookie     = "hexa-cookie"
)

type SessionInfo struct {
    Email    string `json:"email"`
    Sub      string `json:"sub"`
    Session  string `json:"session"`
    RawToken string `json:"idtoken"`
}

type sessionManager struct {
    manager      *scs.SessionManager
    loginEnabled bool
}

type SessionManager interface {
    StartLogin(state string, nonce string, r *http.Request) string
    Session(r *http.Request) (session *SessionInfo, err error)
    StoreLoginSession(rawToken string, email string, sub string, r *http.Request)
    Logout(r *http.Request) (err error)
    GetState(r *http.Request) (session string, state string, nonce string)
    ValidateSession(w http.ResponseWriter, r *http.Request) bool
    SetSessionMiddleware(router *mux.Router)
    GetScs() *scs.SessionManager
}

func NewSessionManager() SessionManager {
    manager := scs.New()
    manager.Store = memstore.NewWithCleanupInterval(15 * time.Minute)

    manager.Lifetime = 1 * time.Hour
    manager.IdleTimeout = 5 * time.Minute
    manager.Cookie.Name = HexaCookie
    manager.Cookie.SameSite = http.SameSiteLaxMode

    // If login is not enabled, we do not want to redirect back to root
    loginEnabled := true
    enabled := os.Getenv(EnvOidcEnabled)
    if enabled == "" || !strings.EqualFold(enabled[0:1], "t") {
        loginEnabled = false
    }
    return &sessionManager{manager: manager, loginEnabled: loginEnabled}
}

// GetScs is intended for testing purposes only
func (s *sessionManager) GetScs() *scs.SessionManager { return s.manager }

func (s *sessionManager) SetSessionMiddleware(router *mux.Router) {
    router.Use(s.manager.LoadAndSave)
}

func (s *sessionManager) ValidateSession(_ http.ResponseWriter, r *http.Request) bool {

    // If sub is not set, we assume the session was not authenticated
    // Note the value of sessionId is just a unique ID for logging purposes
    log.Debug("ValidateSession called")

    if s.loginEnabled {
        sub := s.manager.GetString(r.Context(), KeySubject)
        if sub == "" {
            // http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
            return false
        }
    }
    return true
}

// StartLogin is used by OIDC to start the login authorization flow and store the state and nonce for
// future validation
func (s *sessionManager) StartLogin(state string, nonce string, r *http.Request) string {

    sessionUuid, _ := uuid.NewV7()
    sessionId := sessionUuid.String()
    s.manager.Put(r.Context(), KeySessionId, sessionId)
    s.manager.Put(r.Context(), KeyHexaState, state)
    s.manager.Put(r.Context(), KeyHexaNonce, nonce)

    return sessionId
}

func (s *sessionManager) Session(r *http.Request) (session *SessionInfo, err error) {
    sessionId := s.getSessionIdSafe(r)
    if sessionId == "" {
        return nil, fmt.Errorf("session id %s not found", KeySessionId)
    }
    email := s.manager.GetString(r.Context(), KeyEmail)
    sub := s.manager.GetString(r.Context(), KeySubject)
    rawToken := s.manager.GetString(r.Context(), KeyIdToken)
    return &SessionInfo{
        Email:    email,
        Sub:      sub,
        Session:  sessionId,
        RawToken: rawToken,
    }, nil
}

// getSessionIdSafe returns the Hexa SessionId but traps the panic from SCS if no session exists and returns an empty string if no session
func (s *sessionManager) getSessionIdSafe(r *http.Request) string {
    defer func() {
        if err := recover(); err != nil {
            return
        }
    }()
    sessionId := s.manager.GetString(r.Context(), KeySessionId)
    return sessionId
}

func (s *sessionManager) GetState(r *http.Request) (session string, state string, nonce string) {
    session = s.manager.GetString(r.Context(), KeySessionId)
    state = s.manager.GetString(r.Context(), KeyHexaState)
    nonce = s.manager.GetString(r.Context(), KeyHexaNonce)
    return
}

func (s *sessionManager) StoreLoginSession(rawToken string, email string, sub string, r *http.Request) {
    s.manager.Remove(r.Context(), KeyHexaState)
    // Note We will keep the nonce because it can be checked against ID token
    s.manager.Put(r.Context(), KeyEmail, email)
    s.manager.Put(r.Context(), KeySubject, sub)
    s.manager.Put(r.Context(), KeyIdToken, rawToken)
    return
}

func (s *sessionManager) Logout(r *http.Request) (err error) {
    return s.manager.Destroy(r.Context())
}
