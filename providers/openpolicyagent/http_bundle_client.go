package openpolicyagent

import (
	"bytes"
	"fmt"
	"strings"

	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/hexa-org/policy-mapper/providers/openpolicyagent/compressionsupport"
)

const BundleTypeHttp string = "HTTP"

/*
Do(req *http.Request) (resp *http.Response, err error)
	NewRequest(method, url string, body io.Reader) (req *http.Request, err error)
*/

type HTTPClient interface {
	Get(url string) (resp *http.Response, err error)
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
	Do(request *http.Request) (resp *http.Response, err error)
}

type HTTPBundleClient struct {
	BundleServerURL string
	Authorization   *string
	HttpClient      HTTPClient
}

func (b *HTTPBundleClient) Type() string {
	return BundleTypeHttp
}

func (b *HTTPBundleClient) GetDataFromBundle(path string) ([]byte, error) {

	parse, _ := url.Parse(b.BundleServerURL)

	get, err := b.newRequest(http.MethodGet, fmt.Sprintf("%s://%s/%s", parse.Scheme, parse.Host, "bundles/bundle.tar.gz"), nil, nil)
	if err != nil {
		return nil, err
	}
	defer get.Body.Close()

	gz, gzipErr := compressionsupport.UnGzip(get.Body)
	if gzipErr != nil {
		return nil, fmt.Errorf("unable to ungzip: %w", gzipErr)
	}

	tarErr := compressionsupport.UnTarToPath(bytes.NewReader(gz), path)
	if tarErr != nil {
		return nil, fmt.Errorf("unable to untar to path: %w", tarErr)
	}

	return os.ReadFile(filepath.Join(path, "/bundle/data.json"))
}

// todo - ignoring errors for the moment while spiking

func (b *HTTPBundleClient) PostBundle(bundle []byte) (int, error) {
	// todo - Log out the errors at minimum.
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	formFile, _ := writer.CreateFormFile("bundle", "bundle.tar.gz")
	_, _ = formFile.Write(bundle)
	_ = writer.Close()
	parse, _ := url.Parse(b.BundleServerURL)
	contentType := writer.FormDataContentType()

	resp, err := b.newRequest(http.MethodPost, fmt.Sprintf("%s://%s/bundles", parse.Scheme, parse.Host), &contentType, buf)

	if resp != nil {
		return resp.StatusCode, err
	}
	// resp, err := http.Post(fmt.Sprintf("%s://%s/bundles", parse.Scheme, parse.Host), contentType, buf)
	return http.StatusInternalServerError, err
}

func (b *HTTPBundleClient) newRequest(method, url string, contentType *string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if b.Authorization != nil {
		token := *b.Authorization
		req.Header.Set("Authorization", strings.TrimSpace(token))
	}
	if contentType != nil {
		req.Header.Set("Content-Type", *contentType)
	}

	return b.HttpClient.Do(req)
}
