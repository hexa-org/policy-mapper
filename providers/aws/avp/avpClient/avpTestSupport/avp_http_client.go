package avpTestSupport

import (
    "bytes"
    "fmt"
    "io"
    "log"
    "net/http"

    "github.com/stretchr/testify/mock"
)

type MockVerifiedPermissionsHTTPClient struct {
    mock.Mock
    responseBody map[string][][]byte
    requestBody  map[string][][]byte
    statusCodes  map[string][]int
    called       map[string][]int
}

func NewMockVerifiedPermissionsHTTPClient() *MockVerifiedPermissionsHTTPClient {
    return &MockVerifiedPermissionsHTTPClient{
        Mock:         mock.Mock{},
        responseBody: make(map[string][][]byte),
        requestBody:  make(map[string][][]byte),
        statusCodes:  make(map[string][]int),
        called:       make(map[string][]int),
    }
}

func (m *MockVerifiedPermissionsHTTPClient) Do(req *http.Request) (*http.Response, error) {
    awsServiceOp := req.Header.Get("X-Amz-Target")
    reqKey := m.reqKey(req.Method, req.URL.String(), awsServiceOp)
    reqNum := len(m.called[reqKey])

    for expReqKey, expBodyList := range m.responseBody {
        if reqKey == expReqKey && reqNum < len(expBodyList) {
            return m.sendRequest(req.Method, req.URL.String(), awsServiceOp, req.Body)
        }
    }

    return nil, fmt.Errorf("missing mock response for request - %s Request Num %d", reqKey, reqNum)
}

func (m *MockVerifiedPermissionsHTTPClient) Get(url string) (resp *http.Response, err error) {
    return m.sendRequest(http.MethodGet, url, "", nil)
}

func (m *MockVerifiedPermissionsHTTPClient) Post(url, _ string, body io.Reader) (resp *http.Response, err error) {
    return m.sendRequest(http.MethodPost, url, "", body)
}

func (m *MockVerifiedPermissionsHTTPClient) sendRequest(method, url, awsServiceOp string, body io.Reader) (resp *http.Response, err error) {
    reqKey := m.reqKey(method, url, awsServiceOp)
    if body != nil {
        reqBody, _ := io.ReadAll(body)
        m.requestBody[reqKey] = append(m.requestBody[reqKey], reqBody)
    }

    reqNum := len(m.called[reqKey])
    var responseBody []byte
    responseBody = m.responseBody[reqKey][reqNum]
    statusCode := m.statusCodes[reqKey][reqNum]
    m.called[reqKey] = append(m.called[reqKey], statusCode)
    return &http.Response{StatusCode: statusCode, Body: io.NopCloser(bytes.NewReader(responseBody))}, nil
}

func (m *MockVerifiedPermissionsHTTPClient) AddRequest(method, url, apiOp string, statusCode int, responseBody []byte) {
    serviceOp := "VerifiedPermissions." + apiOp
    m.addRequest(m.reqKey(method, url, serviceOp), statusCode, responseBody)
}

func (m *MockVerifiedPermissionsHTTPClient) addRequest(reqKey string, statusCode int, responseBody []byte) {
    m.statusCodes[reqKey] = append(m.statusCodes[reqKey], statusCode)

    body := responseBody
    if responseBody == nil {
        body = make([]byte, 0)
    }
    m.responseBody[reqKey] = append(m.responseBody[reqKey], body)
}

func (m *MockVerifiedPermissionsHTTPClient) GetRequestBody(method, url, serviceOp string) []byte {
    return m.GetRequestBodyByIndex(method, url, serviceOp, 0)
}

func (m *MockVerifiedPermissionsHTTPClient) GetRequestBodyByIndex(method, url, serviceOp string, reqIndex int) []byte {
    reqKey := m.reqKey(method, url, serviceOp)
    if reqIndex < len(m.requestBody[reqKey]) {
        return m.requestBody[reqKey][reqIndex]
    }
    return nil
}

func (m *MockVerifiedPermissionsHTTPClient) reqKey(method, url, awsServiceOp string) string {
    if awsServiceOp != "" {
        return fmt.Sprintf("%s %s %s", method, url, awsServiceOp)
    }
    return method + " " + url
}

func (m *MockVerifiedPermissionsHTTPClient) VerifyCalled() bool {
    failCount := 0
    for reqKey, expStatusCodes := range m.statusCodes {
        expCount := len(expStatusCodes)
        calledCount := len(m.called[reqKey])
        if expCount == calledCount {
            continue
        }

        log.Println("Expected request not called. Request=", reqKey, "Counts: expected=", expCount, "called=", calledCount)
        failCount++

    }
    return failCount == 0
}