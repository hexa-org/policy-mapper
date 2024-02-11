package apimservice_test

import (
	"context"
	"encoding/json"

	"net/http"
	"testing"

	"github.com/hexa-org/policy-mapper/providers/azure/azarm/armclientsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azarm/azapim/apimservice"
	"github.com/hexa-org/policy-mapper/providers/azure/azurecommon"
	"github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport/apim_testsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport/armtestsupport"
	"github.com/stretchr/testify/assert"
)

func TestClient_List(t *testing.T) {
	resp := apim_testsupport.ApimServiceListResponse(armtestsupport.ApimServiceGatewayUrl)
	theBytes, _ := json.Marshal(resp)
	reqUrl := apim_testsupport.ListServiceUrl()
	httpClient := armtestsupport.FakeTokenCredentialHttpClient(armtestsupport.Issuer)
	httpClient.AddRequest("GET", reqUrl, http.StatusOK, theBytes)

	client := apimServiceClient(httpClient)
	pager := client.NewListPager(nil)
	assert.True(t, pager.More())
	assert.NotNil(t, pager)

	page, err := pager.NextPage(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, page)
	assert.False(t, pager.More())
}

func apimServiceClient(httpClient azurecommon.HTTPClient) apimservice.Client {
	tokenCredential, _ := azurecommon.ClientSecretCredentials(azuretestsupport.AzureKey(), httpClient)
	clientOptions := armclientsupport.NewArmClientOptions(httpClient)
	serviceClient := apimservice.NewClient(azuretestsupport.AzureSubscription, tokenCredential, clientOptions)
	return serviceClient
}
