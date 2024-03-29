package openpolicyagent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"

	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
	"github.com/hexa-org/policy-mapper/providers/openpolicyagent/compressionsupport"

	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
)

const ProviderTypeOpa string = "opa"

type BundleClient interface {
	GetDataFromBundle(path string) ([]byte, error)
	PostBundle(bundle []byte) (int, error)
	Type() string
}

type OpaProvider struct {
	BundleClientOverride BundleClient
	ResourcesDirectory   string
}

func (o *OpaProvider) Name() string {
	return ProviderTypeOpa
}

func (o *OpaProvider) DiscoverApplications(info policyprovider.IntegrationInfo) ([]policyprovider.ApplicationInfo, error) {
	c, err := o.credentials(info.Key)
	if err != nil {
		return nil, err
	}
	client, err := o.ConfigureClient(info.Key)
	if err != nil {
		return nil, err
	}

	service := fmt.Sprintf("Hexa OPA (%s)", client.Type())
	var apps []policyprovider.ApplicationInfo
	if strings.EqualFold(info.Name, o.Name()) {
		apps = append(apps, policyprovider.ApplicationInfo{
			ObjectID:    c.objectID(),
			Name:        "Bucket " + c.objectID(),
			Description: "Open Policy Agent bundle",
			Service:     service,
		})
	}
	return apps, nil
}

func (o *OpaProvider) GetPolicyInfo(integration policyprovider.IntegrationInfo, _ policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
	key := integration.Key
	client, err := o.ConfigureClient(key)
	if err != nil {
		log.Printf("open-policy-agent, unable to build client: %s", err)
		return nil, fmt.Errorf("invalid client: %w", err)
	}
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	path := filepath.Join(os.TempDir(), fmt.Sprintf("/test-bundle-%d", random.Uint64()))
	data, err := client.GetDataFromBundle(path)
	if err != nil {
		log.Printf("open-policy-agent, unable to read expression file. %s\n", err)
		return nil, err
	}

	var policies hexapolicy.Policies
	unmarshalErr := json.Unmarshal(data, &policies)
	if unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return policies.Policies, nil
}

func (o *OpaProvider) SetPolicyInfo(integration policyprovider.IntegrationInfo, appInfo policyprovider.ApplicationInfo, policyInfos []hexapolicy.PolicyInfo) (int, error) {
	validate := validator.New() // todo - move this up?
	errApp := validate.Struct(appInfo)
	if errApp != nil {
		return http.StatusInternalServerError, fmt.Errorf("invalid app info: %w", errApp)
	}
	errPolicies := validate.Var(policyInfos, "omitempty,dive")
	if errPolicies != nil {
		return http.StatusInternalServerError, fmt.Errorf("invalid policy info: %w", errPolicies)
	}

	key := integration.Key
	client, err := o.ConfigureClient(key)
	if err != nil {
		log.Printf("open-policy-agent, unable to build client: %s", err)
		return http.StatusInternalServerError, fmt.Errorf("invalid client: %w", err)
	}

	var policies []hexapolicy.PolicyInfo
	for _, p := range policyInfos {
		// Set up and update the Meta block...
		now := time.Now()
		meta := p.Meta

		if meta.Created == nil {
			meta.Created = &now
		}
		meta.Modified = &now
		meta.PapId = &appInfo.ObjectID
		meta.ProviderType = ProviderTypeOpa
		if meta.PolicyId == nil {
			// Assign a default policy id based on the resourceId. If not available, use the Pap ObjectID. An alias is appended to ensure uniqueness
			alias := generateAliasOfSize(3)
			resId := *meta.PapId
			if p.Object.ResourceID != "" {
				resId = p.Object.ResourceID
			}
			pid := fmt.Sprintf("%s_%s", resId, alias)
			meta.PolicyId = &pid
		}

		p.Meta = meta
		policies = append(policies, p)
	}
	data, marshalErr := json.Marshal(hexapolicy.Policies{Policies: policies})
	if marshalErr != nil {
		log.Printf("open-policy-agent, unable to create data file. %s\n", marshalErr)
		return http.StatusInternalServerError, marshalErr
	}

	bundle, copyErr := o.MakeDefaultBundle(data)
	if copyErr != nil {
		log.Printf("open-policy-agent, unable to create default bundle. %s\n", copyErr)
		return http.StatusInternalServerError, copyErr
	}
	defer func() {
		if err := recover(); err != nil {
			log.Printf("unable to set policy: %v", err)
		}
	}()
	return client.PostBundle(bundle.Bytes())
}

func (o *OpaProvider) MakeDefaultBundle(data []byte) (bytes.Buffer, error) {
	_, file, _, _ := runtime.Caller(0)
	join := filepath.Join(file, "../resources/bundles/bundle")
	manifest, _ := os.ReadFile(filepath.Join(join, "/.manifest"))
	rego, _ := os.ReadFile(filepath.Join(join, "/policy.rego"))
	rego2, _ := os.ReadFile(filepath.Join(join, "/hexaPolicy.rego"))
	// todo - ignoring errors for the moment while spiking

	tempDir := os.TempDir()
	_ = os.Mkdir(filepath.Join(tempDir, "/bundles"), 0744)
	_ = os.Mkdir(filepath.Join(tempDir, "/bundles/bundle"), 0744)
	_ = os.WriteFile(filepath.Join(tempDir, "/bundles/bundle/.manifest"), manifest, 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "/bundles/bundle/data.json"), data, 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "/bundles/bundle/policy.rego"), rego, 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "/bundles/bundle/hexaPolicy.rego"), rego2, 0644)

	tar, _ := compressionsupport.TarFromPath(filepath.Join(tempDir, "/bundles"))
	var buffer bytes.Buffer
	_ = compressionsupport.Gzip(&buffer, tar)

	return buffer, nil
}

type Credentials struct {
	// ProjectID string             `json:"project_id,omitempty"`
	BundleUrl string             `json:"bundle_url"`
	CACert    string             `json:"ca_cert,omitempty"`
	GCP       *GcpCredentials    `json:"gcp,omitempty"`
	AWS       *AwsCredentials    `json:"aws,omitempty"`
	GITHUB    *GithubCredentials `json:"github,omitempty"`
}

func (c Credentials) objectID() string {
	if c.GCP != nil {
		return c.GCP.BucketName
	}

	if c.AWS != nil {
		return c.AWS.BucketName
	}

	if c.GITHUB != nil {
		return c.GITHUB.Repo
	}

	return base64.StdEncoding.EncodeToString([]byte(c.BundleUrl))
}

type GcpCredentials struct {
	BucketName string          `json:"bucket_name,omitempty"`
	ObjectName string          `json:"object_name,omitempty"`
	Key        json.RawMessage `json:"key,omitempty"`
}

type AwsCredentials GcpCredentials

type GithubCredentials struct {
	Account    string          `json:"account,omitempty"`
	Repo       string          `json:"repo,omitempty"`
	BundlePath string          `json:"bundlePath,omitempty"`
	Key        json.RawMessage `json:"key,omitempty"`
}

func (o *OpaProvider) credentials(key []byte) (Credentials, error) {
	var foundCredentials Credentials
	err := json.NewDecoder(bytes.NewReader(key)).Decode(&foundCredentials)
	if err != nil {
		return Credentials{}, fmt.Errorf("invalid integration key: %w", err)
	}
	// if foundCredentials.ProjectID == "" {
	// 	foundCredentials.ProjectID = "package authz"
	// }
	return foundCredentials, nil
}

func (o *OpaProvider) ConfigureClient(key []byte) (BundleClient, error) {
	// todo - do we need ResourcesDirectory here? Are we using it?
	if o.ResourcesDirectory == "" {
		_, file, _, _ := runtime.Caller(0)
		o.ResourcesDirectory = filepath.Join(file, "../resources")
	}

	creds, err := o.credentials(key)
	if err != nil {
		return nil, err
	}

	if creds.GCP != nil {
		return NewGCPBundleClient(
			creds.GCP.BucketName,
			creds.GCP.ObjectName,
			creds.GCP.Key,
		)
	}

	if creds.AWS != nil {
		return NewAWSBundleClient(
			creds.AWS.BucketName,
			creds.AWS.ObjectName,
			creds.AWS.Key,
			awscommon.AWSClientOptions{},
		)
	}

	if creds.GITHUB != nil {
		return NewGithubBundleClient(
			creds.GITHUB.Account,
			creds.GITHUB.Repo,
			creds.GITHUB.BundlePath,
			creds.GITHUB.Key,
			GithubBundleClientOptions{})
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	if creds.CACert != "" {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(creds.CACert))
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}

	if o.BundleClientOverride != nil {
		return o.BundleClientOverride, nil
	}

	bundleUrl, err := url.Parse(creds.BundleUrl)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error parsing bundleUrl: %s", err.Error()))
	}
	if bundleUrl.Path == "" {
		fmt.Println("Defaulting bundle path to: bundles/bundle.tar.gz")
		bundleUrl.Path = "/bundles/bundle.tar.gz"
	}
	return &HTTPBundleClient{
		BundleServerURL: bundleUrl.String(),
		HttpClient:      client,
	}, nil
}
