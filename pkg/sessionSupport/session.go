package sessionSupport

import (
    "fmt"
    "net/http"
    "time"

    "github.com/alexedwards/scs/v2"
    "github.com/alexedwards/scs/v2/memstore"
    "github.com/google/uuid"
    "github.com/gorilla/mux"
    log "golang.org/x/exp/slog"
)

const (
    KeyHexaState = "hexa-state"
    KeyHexaNonce = "hexa-nonce"
    KeyEmail     = "email"
    KeySubject   = "sub"
    KeyIdToken   = "idtoken"
    KeySessionId = "session-id"
    HexaCookie   = "hexa-cookie"
)

type SessionInfo struct {
    Email    string `json:"email"`
    Sub      string `json:"sub"`
    Session  string `json:"session"`
    RawToken string `json:"idtoken"`
}

type sessionManager struct {
    manager *scs.SessionManager
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

    return &sessionManager{manager: manager}
}

// GetScs is intended for testing purposes only
func (s *sessionManager) GetScs() *scs.SessionManager { return s.manager }

func (s *sessionManager) SetSessionMiddleware(router *mux.Router) {
    router.Use(s.manager.LoadAndSave)
}

func (s *sessionManager) ValidateSession(w http.ResponseWriter, r *http.Request) bool {

    // If sub is not set, we assume the session was not authenticated
    // Note the value of sessionId is just a unique ID for logging purposes
    log.Debug("ValidateSession called")
    sub := s.manager.GetString(r.Context(), KeySubject)
    if sub == "" {
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        return false
    }
    return true
}

func (s *sessionManager) StartLogin(state string, nonce string, r *http.Request) string {

    sessionUuid, _ := uuid.NewV7()
    sessionId := sessionUuid.String()
    s.manager.Put(r.Context(), KeySessionId, sessionId)
    s.manager.Put(r.Context(), KeyHexaState, state)
    s.manager.Put(r.Context(), KeyHexaNonce, nonce)

    return sessionId
}

func (s *sessionManager) Session(r *http.Request) (session *SessionInfo, err error) {
    sessionId := s.manager.GetString(r.Context(), KeySessionId)
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
