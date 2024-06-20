package tokensupport

import (
    "fmt"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"

    "github.com/hexa-org/policy-mapper/pkg/oauth2support"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
)

type testSuite struct {
    suite.Suite
    keyDir      string
    keyfile     string
    Handler     *TokenHandler
    bundleToken string
    azToken     string
}

func TestTokenGenerator(t *testing.T) {
    path, _ := os.MkdirTemp("", "token-*")

    _ = os.Setenv(EnvTknKeyDirectory, path)
    _ = os.Unsetenv(EnvTknPubKeyFile)
    _ = os.Unsetenv(EnvTknPrivateKeyFile)

    handler, err := GenerateIssuerKeys("authzen", false)
    assert.NoError(t, err, "Check no error generating issuer")
    assert.Equal(t, "authzen", handler.TokenIssuer, "Check issuer set")

    s := testSuite{
        Suite:   suite.Suite{},
        keyDir:  path,
        keyfile: handler.PrivateKeyPath,
        Handler: handler,
    }
    _ = os.Setenv(EnvTknPubKeyFile, filepath.Join(s.keyDir, DefTknPublicKeyFile))
    _ = os.Setenv(oauth2support.EnvJwtAuth, "true")
    _ = os.Setenv(EnvTknIssuer, s.Handler.TokenIssuer)
    _ = os.Setenv(oauth2support.EnvJwtKid, s.Handler.TokenIssuer)
    _ = os.Unsetenv(oauth2support.EnvJwtAudience)

    suite.Run(t, &s)

    s.cleanup()
}

func (s *testSuite) cleanup() {
    _ = os.RemoveAll(s.keyDir)
}

func (s *testSuite) TestGenerateIssuer() {
    assert.Equal(s.T(), s.keyDir, filepath.Clean(s.Handler.KeyDir), "Check key directory")
    assert.NotNil(s.T(), s.Handler.PublicKey, "Public key created")
    dir, err := os.ReadDir(s.keyDir)
    assert.NoError(s.T(), err, "able to read key dir")
    numFiles := len(dir)
    assert.Greater(s.T(), numFiles, 1, "should be at least 2 files")
}

func (s *testSuite) TestLoadExisting() {

    handler2, err := LoadIssuer("authzen")
    assert.NoError(s.T(), err, "No error on load")
    assert.NotNil(s.T(), handler2.PrivateKey, "Check private key loaded")
}

func (s *testSuite) TestIssueAndValidateToken() {
    fmt.Println("Loading validator...")
    _ = os.Unsetenv(EnvTknKeyDirectory)
    _ = os.Unsetenv(EnvTknPrivateKeyFile)

    validator, err := oauth2support.NewResourceJwtAuthorizer()

    assert.NoError(s.T(), err, "No error on load")
    assert.NotNil(s.T(), validator, "Check validator not null")
    assert.NotNil(s.T(), validator.Key, "Keyfunc should not be nil")
    // assert.Equal(s.T(), ModeEnforceAll, validator.Mode, "Check mode is enforce ALL by default")

    fmt.Println("Issuing token...")

    tokenString, err := s.Handler.IssueToken([]string{ScopeBundle}, "test@example.com")
    assert.NoError(s.T(), err, "No error issuing token")
    assert.NotEmpty(s.T(), tokenString, "Token has a value")
    s.bundleToken = tokenString

    tokenString, err = s.Handler.IssueToken([]string{ScopeDecision}, "test@example.com")
    assert.NoError(s.T(), err, "No error issuing token")
    assert.NotEmpty(s.T(), tokenString, "Token has a value")
    fmt.Println("Token issued:\n" + tokenString)
    s.azToken = tokenString // save for the next test

    req, _ := http.NewRequest("GET", "example.com", nil)
    req.Header.Set("Authorization", "Bearer "+tokenString)

    fmt.Println("Validate token...")

    rr := httptest.NewRecorder()
    fmt.Println("  Positive check")
    jwt := validator.ValidateAuthorization(rr, req, []string{ScopeDecision})
    assert.Equal(s.T(), http.StatusOK, rr.Code, "Check status ok")
    email := jwt.Email
    assert.Equal(s.T(), "test@example.com", email, "Check email parsed")

    fmt.Println("  Negative checks")

    // Token should be valid but wrong scope
    rr = httptest.NewRecorder()
    jwt = validator.ValidateAuthorization(rr, req, []string{ScopeBundle})

    assert.Equal(s.T(), http.StatusForbidden, rr.Code, "Check forbidden")

    rr = httptest.NewRecorder()
    // Token not valid
    req.Header.Del("Authorization")
    req.Header.Set("Authorization", "Bearer bleh"+tokenString)
    jwt = validator.ValidateAuthorization(rr, req, []string{ScopeDecision})
    assert.Equal(s.T(), http.StatusUnauthorized, rr.Code, "Check unauthorized")
    assert.Nil(s.T(), jwt, "JWT should be nil")

    // no authorization
    rr = httptest.NewRecorder()
    req.Header.Del("Authorization")
    jwt = validator.ValidateAuthorization(rr, req, []string{ScopeDecision})
    assert.Equal(s.T(), http.StatusUnauthorized, rr.Code, "Check unauthorized")
    assert.Nil(s.T(), jwt, "JWT should be nil")

    // No authorization type
    rr = httptest.NewRecorder()
    req.Header.Set("Authorization", tokenString)
    jwt = validator.ValidateAuthorization(rr, req, []string{ScopeDecision})
    assert.Equal(s.T(), http.StatusUnauthorized, rr.Code, "Check unauthorized")
    assert.Nil(s.T(), jwt, "JWT should be nil")
}

func (s *testSuite) TestValidateMode() {
    fmt.Println("Loading validator...")
    _ = os.Unsetenv(EnvTknKeyDirectory)
    _ = os.Unsetenv(EnvTknPrivateKeyFile)
    // _ = os.Setenv(oauth2support.EnvJwtAuth,"false")
    _ = os.Setenv(EnvTknEnforceMode, ModeEnforceBundle)

    validator, err := oauth2support.NewResourceJwtAuthorizer()
    assert.NoError(s.T(), err, "No error on load")
    assert.NotNil(s.T(), validator, "Check validator not null")
    // assert.Equal(s.T(), ModeEnforceBundle, validator.Mode, "Check mode is enforce BUNDLE")

    fmt.Println("Validate token...")

    fmt.Println("  Positive check")

    fmt.Println("    Anonymous")
    rr := httptest.NewRecorder()
    req, _ := http.NewRequest("GET", "example.com", nil)
    jwt := validator.ValidateAuthorization(rr, req, []string{ScopeDecision})
    assert.Equal(s.T(), http.StatusUnauthorized, rr.Code, "Check status unauthorized")
    assert.Nil(s.T(), jwt, "JWT should be nil")

    fmt.Println("    Az scope token")
    rr = httptest.NewRecorder()
    req.Header.Set("Authorization", "Bearer "+s.azToken)
    jwt = validator.ValidateAuthorization(rr, req, []string{ScopeDecision})
    assert.Equal(s.T(), http.StatusOK, rr.Code, "Check status ok")
    assert.NotNil(s.T(), jwt, "JWT is not nil")

    fmt.Println("    Bundle token")
    rr = httptest.NewRecorder()
    req.Header.Set("Authorization", "Bearer "+s.bundleToken)
    jwt = validator.ValidateAuthorization(rr, req, []string{ScopeBundle})
    assert.Equal(s.T(), http.StatusOK, rr.Code, "Check status ok")
    email := jwt.Email
    assert.Equal(s.T(), "test@example.com", email, "Check email parsed")

    fmt.Println("  Negative checks")

    // Token should be valid but wrong scope
    rr = httptest.NewRecorder()
    req.Header.Set("Authorization", "Bearer "+s.azToken)
    jwt = validator.ValidateAuthorization(rr, req, []string{ScopeBundle})
    assert.Equal(s.T(), http.StatusForbidden, rr.Code, "Check forbidden")

}
