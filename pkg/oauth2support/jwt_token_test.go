package oauth2support

import (
    "encoding/base64"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/http/httptest"
    "net/url"
    "os"
    "path/filepath"
    "runtime"
    "testing"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/hexa-org/policy-mapper/pkg/mockOidcSupport"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/clientcredentials"
)

type testData struct {
    suite.Suite
    MockAuth     *mockOidcSupport.MockAuthServer
    MockResource *mockOidcSupport.MockResourceServer
    cid          string
    audience     string
    secret       string
    claims       map[string]interface{}
    jwtHandler   *ResourceJwtAuthorizer
    config       *clientcredentials.Config
}

func TestResourceServer(t *testing.T) {
    s := testData{}
    log.Println("Starting test servers")
    s.cid = "testClientId"
    s.secret = "testClientSecret"
    s.claims = map[string]interface{}{"roles": []string{"a", "b"}}
    s.audience = "orchestrator"
    s.MockAuth = mockOidcSupport.NewMockAuthServer(s.cid, s.secret, s.claims)
    mockerAddr := s.MockAuth.Server.URL
    mockUrlJwks, err := url.JoinPath(mockerAddr, "/jwks")
    assert.NotEmpty(t, mockUrlJwks)
    _ = os.Setenv(EnvOAuthJwksUrl, mockUrlJwks)
    _ = os.Setenv(EnvJwtRealm, "TEST_REALM")
    _ = os.Setenv(EnvJwtAuth, "true")
    _ = os.Setenv(EnvJwtAudience, s.audience)
    _ = os.Setenv(EnvJwtScope, "orchestrator")
    s.jwtHandler, _ = NewResourceJwtAuthorizer()
    assert.NotNil(t, s.jwtHandler)
    assert.Equal(t, mockUrlJwks, s.jwtHandler.jwksUrl)
    assert.Equal(t, "TEST_REALM", s.jwtHandler.realm)
    assert.NotNil(t, s.jwtHandler.Key)

    helloHandler := JwtAuthenticationHandler(mockOidcSupport.HandleHello, s.jwtHandler, nil)

    assert.NoError(t, err, "Should be a valid url")

    s.MockResource = mockOidcSupport.NewMockResourceServer("/hello", helloHandler)

    authUrl := s.MockAuth.Server.URL + "/token"
    s.config = &clientcredentials.Config{
        ClientID:     s.cid,
        ClientSecret: s.secret,
        TokenURL:     authUrl,
        Scopes:       []string{"orchestrator"},
        AuthStyle:    oauth2.AuthStyle(oauth2.AuthStyleAutoDetect),
    }

    _ = os.Setenv(EnvOAuthClientId, s.cid)
    _ = os.Setenv(EnvOAuthClientSecret, s.secret)
    _ = os.Setenv(EnvOAuthTokenEndpoint, authUrl)
    _ = os.Setenv(EnvOAuthClientScope, "orchestrator")

    defer Cleanup(&s)

    suite.Run(t, &s)

}

func Cleanup(s *testData) {
    log.Println("Shutting down test servers")
    if s.MockAuth != nil && s.MockAuth.Server != nil {
        s.MockAuth.Shutdown()
    }
    if s.MockResource != nil && s.MockResource.Server != nil {
        s.MockResource.Shutdown()
    }
}

func (s *testData) Test1_JWT() {
    tokenString, err := s.MockAuth.BuildJWT(60, nil, []string{"orchestrator"}, "", false)
    assert.NoError(s.T(), err, "Build JWT failed")

    fmt.Println("Test Token: " + tokenString)

    req := httptest.NewRequest("GET", "/hello", nil)
    req.Header.Set("Authorization", "Bearer "+tokenString)

    token, valid := s.jwtHandler.authenticate(httptest.NewRecorder(), req, []string{"orchestrator"})
    assert.True(s.T(), valid, "Token was valid")

    sub, _ := token.Claims.GetSubject()
    assert.Equal(s.T(), "testClientId", sub)
    assert.True(s.T(), token.Valid)
}

func (s *testData) Test2_JWT_Errors() {
    expireTokenString, _ := s.MockAuth.BuildJWT(1, nil, []string{"orchestrator"}, "", false)
    fmt.Println("Test wrong type")
    tokenString := "Basic " + base64.RawURLEncoding.EncodeToString([]byte("testClientId"))
    req := httptest.NewRequest("GET", "/hello", nil)
    req.Header.Set("Authorization", tokenString)

    resp := httptest.NewRecorder()
    token, valid := s.jwtHandler.authenticate(resp, req, []string{"orchestrator"})
    assert.False(s.T(), valid)
    assert.Nil(s.T(), token)
    assert.Equal(s.T(), http.StatusUnauthorized, resp.Code)

    wwwauthheader := resp.Header().Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\", error=\"invalid_token\", error_description=\"Bearer token required\"", wwwauthheader)

    fmt.Println("Testing missing prefix")
    tokenString, _ = s.MockAuth.BuildJWT(60, nil, []string{"orchestrator"}, "", false)
    req2 := httptest.NewRequest("GET", "/hello", nil)
    req2.Header.Set("Authorization", tokenString)
    resp2 := httptest.NewRecorder()
    token, valid = s.jwtHandler.authenticate(resp2, req2, []string{"orchestrator"})
    assert.False(s.T(), valid)
    assert.Nil(s.T(), token)
    assert.Equal(s.T(), http.StatusUnauthorized, resp2.Code)

    wwwauthheader = resp2.Header().Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\", error=\"invalid_token\", error_description=\"Missing authorization type or value\"", wwwauthheader)

    // No authorization
    fmt.Println("Missing Authorization")
    req3 := httptest.NewRequest("GET", "/hello", nil)
    resp3 := httptest.NewRecorder()
    token, valid = s.jwtHandler.authenticate(resp3, req3, nil)
    assert.False(s.T(), valid)
    assert.Nil(s.T(), token)
    assert.Equal(s.T(), http.StatusUnauthorized, resp3.Code)

    wwwauthheader = resp3.Header().Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\"", wwwauthheader)

    // JWT Parse error
    fmt.Println("Invalid JWT error")
    tokenString, _ = s.MockAuth.BuildJWT(60, nil, []string{"orchestrator"}, "", false)
    req4 := httptest.NewRequest("GET", "/hello", nil)
    req4.Header.Set("Authorization", "Bearer Bearer "+tokenString)
    resp4 := httptest.NewRecorder()
    token, valid = s.jwtHandler.authenticate(resp4, req4, []string{"orchestrator"})
    assert.False(s.T(), valid)
    assert.Nil(s.T(), token)
    assert.Equal(s.T(), http.StatusUnauthorized, resp4.Code)

    wwwauthheader = resp4.Header().Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\", error=\"invalid_token\", error_description=\"token is malformed: token contains an invalid number of segments\"", wwwauthheader)

    // testing now expired token.
    fmt.Println("Expired JWT error")
    time.Sleep(time.Second)
    req5 := httptest.NewRequest("GET", "/hello", nil)
    req5.Header.Set("Authorization", "Bearer "+expireTokenString)
    resp5 := httptest.NewRecorder()
    token, valid = s.jwtHandler.authenticate(resp5, req5, nil)
    assert.False(s.T(), valid)
    assert.Nil(s.T(), token)
    assert.Equal(s.T(), http.StatusUnauthorized, resp4.Code)

    wwwauthheader = resp5.Header().Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\", error=\"invalid_token\", error_description=\"token has invalid claims: token is expired\"", wwwauthheader)

    // testing invalid audience
    fmt.Println("Invalid audience error")
    tokenString, _ = s.MockAuth.BuildJWT(60, nil, []string{"wrongwrongwrong"}, "", false)
    req6 := httptest.NewRequest("GET", "/hello", nil)
    req6.Header.Set("Authorization", "Bearer "+tokenString)
    resp6 := httptest.NewRecorder()
    token, valid = s.jwtHandler.authenticate(resp6, req6, nil)
    assert.False(s.T(), valid)
    assert.Nil(s.T(), token)
    assert.Equal(s.T(), http.StatusUnauthorized, resp6.Code)
    wwwauthheader = resp6.Header().Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\", error=\"invalid_token\", error_description=\"invalid audience\"", wwwauthheader)

    // testing invalid scope
    fmt.Println("Invalid scope error")
    tokenString, _ = s.MockAuth.BuildJWT(60, []string{"badScope"}, []string{"orchestrator"}, "", false)
    req7 := httptest.NewRequest("GET", "/hello", nil)
    req7.Header.Set("Authorization", "Bearer "+tokenString)
    resp7 := httptest.NewRecorder()
    token, valid = s.jwtHandler.authenticate(resp7, req7, []string{"orchestrator"})
    assert.False(s.T(), valid)
    assert.Nil(s.T(), token)
    assert.Equal(s.T(), http.StatusForbidden, resp7.Code)
    wwwauthheader = resp7.Header().Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\", error=\"insufficient_scope\", error_description=\"requires scope=orchestrator\"", wwwauthheader)
}

func (s *testData) Test3_JwtHandlerToken() {

    // This call pulls config from environment variables
    jwtHandler := NewJwtClientHandler()

    jwtHandler2 := NewJwtClientHandlerWithConfig(s.config, nil)

    token, err := jwtHandler.GetToken()
    assert.NoError(s.T(), err)
    tokenString := token.AccessToken

    token2, err := jwtHandler2.GetToken()
    assert.NoError(s.T(), err)
    token2String := token2.AccessToken
    assert.NotEqual(s.T(), tokenString, token2String)

    req := httptest.NewRequest("GET", "/hello", nil)
    req.Header.Set("Authorization", "Bearer "+tokenString)
    tokenParsed, valid := s.jwtHandler.authenticate(httptest.NewRecorder(), req, nil)
    assert.True(s.T(), valid, "Token was valid")

    sub, _ := tokenParsed.Claims.GetSubject()
    assert.Equal(s.T(), "testClientId", sub)
    assert.True(s.T(), tokenParsed.Valid)

    /* For now we are not using scopes
       claims := tokenParsed.Claims
       switch v := claims.(type) {
       case jwt.MapClaims:
       	scope := v["scope"]
       	assert.Equal(s.T(), "orchestrator", scope)
       default:
       	assert.Fail(s.T(), "unexpected claim type")
       }

    */

    // check the refresh token
    refresh := token.RefreshToken
    refreshToken, err := jwt.Parse(refresh, s.jwtHandler.Key.Keyfunc)
    assert.NoError(s.T(), err)

    refreshClaims := refreshToken.Claims
    switch v := refreshClaims.(type) {
    case jwt.MapClaims:
        scope := v["scope"]
        assert.Equal(s.T(), "refresh", scope)
    default:
        assert.Fail(s.T(), "unexpected claim type")
    }

}

func (s *testData) Test4_JwtHttpClient() {

    jwtHandler := NewJwtClientHandler()

    client := jwtHandler.GetHttpClient()

    reqUrl := "http://" + s.MockResource.Server.Addr

    defer client.CloseIdleConnections()

    resp, err := client.Get(reqUrl + "/hello")
    assert.NoError(s.T(), err, "No error on retrieval from hello")
    assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
    body, _ := io.ReadAll(resp.Body)
    bodyString := string(body)
    assert.Equal(s.T(), "Hello testClientId!", bodyString)

    respPost, err := client.Post(reqUrl+"/hello", "application/json", nil)
    assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
    assert.Nil(s.T(), err)
    assert.NotNil(s.T(), respPost)
    body, _ = io.ReadAll(respPost.Body)
    bodyString = string(body)
    assert.Equal(s.T(), "Hello testClientId!", bodyString)
}

func (s *testData) Test5_Middleware_Error() {

    reqUrl := "http://" + s.MockResource.Server.Addr

    req, err := http.NewRequest("GET", reqUrl+"/hello", nil)
    assert.NoError(s.T(), err)

    client := http.Client{}
    defer client.CloseIdleConnections()

    resp, err := client.Do(req)
    assert.Nil(s.T(), err)
    assert.NotNil(s.T(), resp)
    assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)

    wwwAuthHeader := resp.Header.Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\"", wwwAuthHeader)

    req.Header.Set("Authorization", "Bearer bla.bla.bla.bla")
    resp, err = client.Do(req)
    assert.Nil(s.T(), err)
    assert.NotNil(s.T(), resp)
    assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
    wwwAuthHeader = resp.Header.Get("WWW-Authenticate")
    assert.Equal(s.T(), "Bearer realm=\"TEST_REALM\", error=\"invalid_token\", error_description=\"token is malformed: token contains an invalid number of segments\"", wwwAuthHeader)
}

func (s *testData) Test6_LoadPubKeyFile() {
    _, file, _, _ := runtime.Caller(0)
    keyfile := filepath.Join(file, "../test/issuer-cert.pem")

    _ = os.Unsetenv(EnvOAuthJwksUrl)
    _ = os.Setenv(EnvTknPubKeyFile, keyfile)
    authorizer, err := NewResourceJwtAuthorizer()
    assert.NoError(s.T(), err)
    assert.NotNil(s.T(), authorizer)
    assert.NotNil(s.T(), authorizer.Key)

    // Test wrong certificate type (in this case TLS cert)
    keyfile = filepath.Join(file, "../test/ca-cert.pem")
    _ = os.Setenv(EnvTknPubKeyFile, keyfile)
    authorizer, err = NewResourceJwtAuthorizer()
    assert.Error(s.T(), err, "asn1: structure error: tags don't match (2 vs {class:0 tag:16 length:853 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false}  @4")
    assert.Nil(s.T(), authorizer)

}
