package openpolicyagent

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"mime/multipart"
	"net/url"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/providers/openpolicyagent/compressionsupport"
)

/*
OpaBundleClient is intended to use the OPA Policy API to directly update and retrieve Policy bundles from an OPA Policy Server instance.
Note: typically OPA servers are configured to poll for updates at some configured common retrieval point. Usage of this bundle is mainly for local
development purposes.
*/
type OpaBundleClient struct {
	OpaServerUrl string
	HttpClient   HTTPClient
}

type OpaDataResponse struct {
	Result []hexapolicy.PolicyInfo `json:"result"`
}

const PolicyDataPath string = "/v1/data/policies"

func (b *OpaBundleClient) GetDataFromBundle(_ string) ([]byte, error) {
	opaUrl, err := url.Parse(b.OpaServerUrl)
	if err != nil {
		return nil, err
	}

	policyDataUrl := opaUrl.JoinPath(PolicyDataPath)
	get, getErr := b.HttpClient.Get(policyDataUrl.String())
	if getErr != nil {
		return nil, getErr
	}
	defer get.Body.Close()
	var resBytes []byte
	if strings.EqualFold("application/json", get.Header.Get("Content-Type")) {
		resBytes, err = io.ReadAll(get.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read application/json body: %w", err)
		}
	} else {
		resBytes, err = compressionsupport.UnGzip(get.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to ungzip: %w", err)
		}
	}

	return resBytes, nil
}

// todo - ignoring errors for the moment while spiking

func (b *OpaBundleClient) PostBundle(bundle []byte) (int, error) {
	// todo - Log out the errors at minimum.
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	formFile, _ := writer.CreateFormFile("bundle", "bundle.tar.gz")
	_, _ = formFile.Write(bundle)
	_ = writer.Close()
	parse, _ := url.Parse(b.OpaServerUrl)
	contentType := writer.FormDataContentType()
	resp, err := b.HttpClient.Post(fmt.Sprintf("%s://%s/bundles", parse.Scheme, parse.Host), contentType, buf)
	return resp.StatusCode, err
}
