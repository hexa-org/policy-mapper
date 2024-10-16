package avpProvider

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/models/formats/cedar"
	"github.com/hexa-org/policy-mapper/models/policyInfoModel"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/providers/aws/avpProvider/avpClient"
	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
)

const (
	ProviderTypeAvp string = "avp"
	ParamResource   string = "resource"
	ParamPrincipal  string = "principal"
	ParamPolicyType string = "policyType"
)

func MapAvpMeta(item types.PolicyItem) hexapolicy.MetaInfo {
	data := map[string]interface{}{}

	data[ParamPrincipal] = item.Principal
	data[ParamResource] = item.Resource
	data[ParamPolicyType] = string(types.PolicyTypeStatic)

	return hexapolicy.MetaInfo{
		Version:      hexapolicy.IdqlVersion,
		ProviderType: ProviderTypeAvp,
		Created:      item.CreatedDate,
		Modified:     item.LastUpdatedDate,
		PolicyId:     item.PolicyId,
		PapId:        item.PolicyStoreId,
		SourceData:   data,
	}
}

func MapAvpTemplate(item *verifiedpermissions.GetPolicyTemplateOutput) hexapolicy.MetaInfo {
	data := map[string]interface{}{}
	data[ParamPolicyType] = string(types.PolicyTypeTemplateLinked)
	return hexapolicy.MetaInfo{
		Version:      hexapolicy.IdqlVersion,
		ProviderType: ProviderTypeAvp,
		Created:      item.CreatedDate,
		Modified:     item.LastUpdatedDate,
		PolicyId:     item.PolicyTemplateId,
		PapId:        item.PolicyStoreId,
		SourceData:   data,
	}
}

type (
	AmazonAvpProvider struct {
		AwsClientOpts awscommon.AWSClientOptions
		CedarMapper   *cedar.CedarMapper
	}
)

func (a AmazonAvpProvider) Name() string {
	return ProviderTypeAvp
}

func (a AmazonAvpProvider) initCedarMapper() {
	if a.CedarMapper == nil {
		a.CedarMapper = cedar.NewCedarMapper(map[string]string{})
	}
}

func (a AmazonAvpProvider) getAvpClient(info policyprovider.IntegrationInfo) (avpClient.AvpClient, error) {
	var err error
	client, err := avpClient.NewAvpClient(info.Key, a.AwsClientOpts) // NewFromConfig(info.Key, a.AwsClientOpts)
	if err != nil {
		return nil, err
	}
	a.initCedarMapper()

	return client, nil
}

func (a AmazonAvpProvider) DiscoverApplications(info policyprovider.IntegrationInfo) ([]policyprovider.ApplicationInfo, error) {
	if !strings.EqualFold(info.Name, a.Name()) {
		return []policyprovider.ApplicationInfo{}, nil
	}

	client, err := a.getAvpClient(info)
	if err != nil {
		return nil, err
	}

	return client.ListStores()
}

func (a AmazonAvpProvider) mapAvpPolicyToHexa(avpPolicy types.PolicyItem, client avpClient.AvpClient, applicationInfo policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
	hexaPols := make([]hexapolicy.PolicyInfo, 0)
	policyType := avpPolicy.PolicyType

	switch policyType {
	case types.PolicyTypeStatic:
		output, err := client.GetPolicy(*avpPolicy.PolicyId, applicationInfo)
		if err != nil {
			return nil, err
		}
		policyDefinition := output.Definition
		policyStatic := policyDefinition.(*types.PolicyDefinitionDetailMemberStatic).Value
		cedarPolicy := policyStatic.Statement
		mapPols, err := a.CedarMapper.MapCedarPolicyBytes(applicationInfo.ObjectID, []byte(*cedarPolicy))
		if err != nil {
			return nil, err
		}
		hexaPolicy := mapPols.Policies[0]

		// Update IDQL Meta
		avpMeta := MapAvpMeta(avpPolicy)
		hexaPolicy.Meta = avpMeta
		hexaPolicy.Meta.Description = *policyStatic.Description
		hexaPolicy.CalculateEtag()
		hexaPols = append(hexaPols, hexaPolicy)

	case types.PolicyTypeTemplateLinked:

		policyDefinition := avpPolicy.Definition
		policyLinked := policyDefinition.(*types.PolicyDefinitionItemMemberTemplateLinked).Value

		output, err := client.GetTemplatePolicy(*policyLinked.PolicyTemplateId, applicationInfo)
		if err != nil {
			return nil, err
		}
		// permit(
		//    principal == ?principal,
		//    action in [hexa_avp::Action::"ReadAccount"],
		//    resource == ?resource
		// );
		policyString := *output.Statement
		policyString = strings.Replace(policyString, "?principal", "Template::\"principal\"", -1)
		policyString = strings.Replace(policyString, "?resource", "Template::\"resource\"", -1)

		mapPols, err := a.CedarMapper.MapCedarPolicyBytes(applicationInfo.ObjectID, []byte(policyString))
		if err != nil {
			return nil, err
		}
		hexaPolicy := mapPols.Policies[0]

		// Update the meta information
		avpMeta := MapAvpTemplate(output)
		avpMeta.SourceData[ParamResource] = avpPolicy.Resource
		avpMeta.SourceData[ParamPrincipal] = avpPolicy.Principal
		hexaPolicy.Meta = avpMeta
		if output.Description != nil {
			hexaPolicy.Meta.Description = *output.Description
		}
		hexaPolicy.CalculateEtag()
		hexaPols = append(hexaPols, hexaPolicy)

	default:
	}
	return hexaPols, nil
}

func (a AmazonAvpProvider) GetPolicyInfo(info policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
	client, err := a.getAvpClient(info)
	if err != nil {
		return nil, err
	}
	hexaPols := make([]hexapolicy.PolicyInfo, 0)

	avpPolicies, err := client.ListPolicies(applicationInfo)
	if err != nil {
		return nil, err
	}

	for _, avpPolicy := range avpPolicies {
		policies, err := a.mapAvpPolicyToHexa(avpPolicy, client, applicationInfo)
		if err != nil {
			return nil, err
		}
		hexaPols = append(hexaPols, policies...)
	}
	// Now to map the policies
	return hexaPols, nil
}

func (a AmazonAvpProvider) Reconcile(info policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo, compareHexaPolicies []hexapolicy.PolicyInfo, diffsOnly bool) ([]hexapolicy.PolicyDif, error) {

	// Get all existing policies to compare:
	avpExistingPolicies, err := a.GetPolicyInfo(info, applicationInfo)
	if err != nil {
		return []hexapolicy.PolicyDif{}, err
	}

	var res = make([]hexapolicy.PolicyDif, 0)

	var avpMap = make(map[string]hexapolicy.PolicyInfo, len(avpExistingPolicies))
	for _, policy := range avpExistingPolicies {
		policyId := *policy.Meta.PolicyId
		avpMap[policyId] = policy
	}
	for _, comparePolicy := range compareHexaPolicies {

		meta := comparePolicy.Meta
		switch meta.ProviderType {
		case ProviderTypeAvp:
			policyId := *meta.PolicyId
			sourcePolicy, exists := avpMap[policyId]
			if isTemplate(comparePolicy) {
				dif := hexapolicy.PolicyDif{
					Type:          hexapolicy.ChangeTypeIgnore,
					DifTypes:      nil,
					PolicyExist:   []hexapolicy.PolicyInfo{sourcePolicy},
					PolicyCompare: &comparePolicy,
				}
				res = append(res, dif)

				delete(avpMap, *meta.PolicyId) // Remove to indicate existing policy handled
				fmt.Printf("Ignoring AVP policyid %s. Template updates not currently supported\n",
					*meta.PolicyId)
				continue
			}

			if exists {
				differenceTypes := comparePolicy.Compare(sourcePolicy)
				if slices.Contains(differenceTypes, hexapolicy.CompareEqual) {
					if !diffsOnly {
						// policy matches
						dif := hexapolicy.PolicyDif{
							Type:          hexapolicy.ChangeTypeEqual,
							DifTypes:      nil,
							PolicyExist:   []hexapolicy.PolicyInfo{sourcePolicy},
							PolicyCompare: &comparePolicy,
						}
						res = append(res, dif)
					}
					delete(avpMap, policyId) // Remove to indicate existing policy handled
					continue                 // nothing to do
				}
				// This is a modify request
				newPolicy := comparePolicy
				dif := hexapolicy.PolicyDif{
					Type:          hexapolicy.ChangeTypeUpdate,
					DifTypes:      differenceTypes,
					PolicyExist:   []hexapolicy.PolicyInfo{sourcePolicy},
					PolicyCompare: &newPolicy,
				}
				res = append(res, dif)
				delete(avpMap, policyId) // Remove to indicate existing policy handled
				continue
			}
		default:
			// Fall through to create - likely a policy from another source
		}

		// At this point no match was found. So assume new

		if isTemplate(comparePolicy) {
			fmt.Printf("AVP template policy ignored (Etag: %s)\n", comparePolicy.CalculateEtag())
			continue
		}
		newPolicy := comparePolicy
		dif := hexapolicy.PolicyDif{
			Type:          hexapolicy.ChangeTypeNew,
			DifTypes:      nil,
			PolicyExist:   nil,
			PolicyCompare: &newPolicy,
		}
		res = append(res, dif)

	}

	// For each remaining pre-existing policy there is an implied delete
	if len(avpMap) > 0 {
		fmt.Printf("%v existing AVP policies will be removed.\n", len(avpMap))
		for _, policy := range avpMap {
			dif := hexapolicy.PolicyDif{
				Type:          hexapolicy.ChangeTypeDelete,
				DifTypes:      nil,
				PolicyExist:   []hexapolicy.PolicyInfo{policy},
				PolicyCompare: nil,
			}
			res = append(res, dif)
		}
	}
	return res, nil
}

func (a AmazonAvpProvider) SetPolicyInfo(info policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo, hexaPolicies []hexapolicy.PolicyInfo) (int, error) {
	client, err := a.getAvpClient(info)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	differences, err := a.Reconcile(info, applicationInfo, hexaPolicies, true)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	for _, dif := range differences {
		switch dif.Type {

		case hexapolicy.ChangeTypeNew:
			hexaPolicy := *dif.PolicyCompare
			if isTemplate(hexaPolicy) {
				fmt.Printf("AVP template policy creation not currently supported (Etag: %s)\n", hexaPolicy.CalculateEtag())
				continue
			}
			createInput, err := a.prepareCreatePolicy(hexaPolicy, applicationInfo)
			if err != nil {
				return http.StatusBadRequest, err
			}
			output, err := client.CreatePolicy(createInput)
			if err != nil {
				return http.StatusBadRequest, err
			}
			policyId := output.PolicyId
			fmt.Printf("AVP PolicyId %s created (hexa etag: %s)\n", *policyId, hexaPolicy.Meta.Etag)

		case hexapolicy.ChangeTypeDelete:
			for _, existPolicy := range dif.PolicyExist {
				source := existPolicy.Meta
				deleteInput := a.prepareDelete(source)
				_, err = client.DeletePolicy(deleteInput)
				if err != nil {
					return http.StatusBadRequest, err
				}
				fmt.Printf("AVP PolicyId %s deleted\n", *source.PolicyId)
			}

		case hexapolicy.ChangeTypeUpdate:
			hexaPolicy := *dif.PolicyCompare
			source := hexaPolicy.Meta
			metaType := source.ProviderType
			switch metaType {
			case ProviderTypeAvp:
				policyId := *source.PolicyId

				if slices.Contains(dif.DifTypes, hexapolicy.CompareDifSubject) || slices.Contains(dif.DifTypes, hexapolicy.CompareDifObject) {
					// will delete and replace
					deleteInput := a.prepareDelete(source)
					_, err = client.DeletePolicy(deleteInput)
					if err != nil {
						return http.StatusBadRequest, err
					}
					createInput, err := a.prepareCreatePolicy(hexaPolicy, applicationInfo)
					if err != nil {
						return http.StatusBadRequest, err
					}
					output, err := client.CreatePolicy(createInput)
					if err != nil {
						return http.StatusBadRequest, err
					}
					newPolicyId := output.PolicyId
					fmt.Printf("AVP PolicyId %s replaced as %s (hexa etag: %s)\n", policyId, *newPolicyId, hexaPolicy.Meta.Etag)

				} else if slices.Contains(dif.DifTypes, hexapolicy.CompareDifAction) || slices.Contains(dif.DifTypes, hexapolicy.CompareDifCondition) {
					// Do Update (if subject or object changed, the update would already be done)
					update, err := a.preparePolicyUpdate(hexaPolicy, source)
					if err != nil {
						return http.StatusBadRequest, err
					}
					_, err = client.UpdatePolicy(update)
					if err != nil {
						return http.StatusBadRequest, err
					}
					fmt.Printf("AVP PolicyId %s updated\n", policyId)
					continue
				}

			default:
				// Fall through to create - likely a policy from another source
			}
		case hexapolicy.ChangeTypeIgnore, hexapolicy.ChangeTypeEqual:
			// do nothing
		}
	}

	return http.StatusOK, nil
}

func (a AmazonAvpProvider) convertCedarStatement(hexaPolicy hexapolicy.PolicyInfo) (*string, error) {
	cedarPolicies, err := a.CedarMapper.MapHexaPolicies("", []hexapolicy.PolicyInfo{hexaPolicy})
	cedarPolicies = strings.Replace(cedarPolicies, "Template::\"principal\"", "?principal", -1)
	cedarPolicies = strings.Replace(cedarPolicies, "Template::\"resource\"", "?resource", -1)
	return &cedarPolicies, err
}

func (a AmazonAvpProvider) prepareCreatePolicy(hexaPolicy hexapolicy.PolicyInfo, app policyprovider.ApplicationInfo) (*verifiedpermissions.CreatePolicyInput, error) {
	cedarStatement, err := a.convertCedarStatement(hexaPolicy)
	if err != nil {
		return nil, err
	}
	description := fmt.Sprintf("Mapped from IDQL (etag: %s)", hexaPolicy.CalculateEtag())
	if hexaPolicy.Meta.Description != "" {
		description = hexaPolicy.Meta.Description
	}
	createPolicyDefinition := types.StaticPolicyDefinition{
		Statement:   cedarStatement,
		Description: &description,
	}
	createStatic := types.PolicyDefinitionMemberStatic{
		Value: createPolicyDefinition,
	}
	createPolicyInput := verifiedpermissions.CreatePolicyInput{
		Definition:    &createStatic,
		PolicyStoreId: &app.ObjectID,
	}
	return &createPolicyInput, nil
}

func (a AmazonAvpProvider) preparePolicyUpdate(hexaPolicy hexapolicy.PolicyInfo, meta hexapolicy.MetaInfo) (*verifiedpermissions.UpdatePolicyInput, error) {
	cedarStatement, err := a.convertCedarStatement(hexaPolicy)
	if err != nil {
		return nil, err
	}

	updatePolicyDefinition := types.UpdateStaticPolicyDefinition{
		Statement:   cedarStatement,
		Description: &hexaPolicy.Meta.Description,
	}

	updateMemberStatic := types.UpdatePolicyDefinitionMemberStatic{Value: updatePolicyDefinition}
	update := verifiedpermissions.UpdatePolicyInput{
		Definition:    &updateMemberStatic,
		PolicyId:      meta.PolicyId,
		PolicyStoreId: meta.PapId,
	}
	return &update, nil
}

func (a AmazonAvpProvider) prepareDelete(avpMeta hexapolicy.MetaInfo) *verifiedpermissions.DeletePolicyInput {
	policyType := avpMeta.SourceData[ParamPolicyType]
	if policyType == string(types.PolicyTypeTemplateLinked) {
		return nil // template deletions not currently supported
	}
	deletePolicyInput := verifiedpermissions.DeletePolicyInput{
		PolicyId:      avpMeta.PolicyId,
		PolicyStoreId: avpMeta.PapId,
	}
	return &deletePolicyInput
}

func isTemplate(hexaPolicy hexapolicy.PolicyInfo) bool {
	if hexaPolicy.Meta.SourceData == nil {
		// in the case where a policy is new, but contains template we need to test for ?resource and ?principle
		if slices.Contains(hexaPolicy.Subjects.String(), "?principal") {
			return true
		}
		if strings.Contains(hexaPolicy.Object.String(), "?resource") {
			return true
		}

		return false
	}
	policyType, exists := hexaPolicy.Meta.SourceData[ParamPolicyType]
	return exists && policyType == string(types.PolicyTypeTemplateLinked)
}

func (a AmazonAvpProvider) GetSchema(info policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo) (*policyInfoModel.Namespaces, error) {
	client, err := a.getAvpClient(info)
	if err != nil {
		return nil, err
	}

	schemaResponse, err := client.GetSchema(applicationInfo)
	if err != nil {
		return nil, err
	}
	namespaceNames := schemaResponse.Namespaces
	fmt.Println(fmt.Sprintf("Found namespaces: %v", namespaceNames))
	cedarSchemaString := schemaResponse.Schema

	return policyInfoModel.ParseSchemaFile([]byte(*cedarSchemaString))

}
