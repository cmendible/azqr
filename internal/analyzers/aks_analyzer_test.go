package analyzers

import (
	"context"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/Azure/go-autorest/autorest/to"
)

func newAKS(t *testing.T) *armcontainerservice.ManagedCluster {
	sku := armcontainerservice.ManagedClusterSKUNameBasic
	tier := armcontainerservice.ManagedClusterSKUTierFree
	return &armcontainerservice.ManagedCluster{
		ID:       to.StringPtr("id"),
		Name:     to.StringPtr("aks-name"),
		Location: to.StringPtr("westeurope"),
		Type:     to.StringPtr("Microsoft.ContainerService/managedClusters"),
		SKU: &armcontainerservice.ManagedClusterSKU{
			Name: &sku,
			Tier: &tier,
		},
		Properties: &armcontainerservice.ManagedClusterProperties{
			APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
				EnablePrivateCluster: to.BoolPtr(false),
			},
			AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
				{
					AvailabilityZones: []*string{},
				},
			},
		},
	}
}

func newAKSWithAvailabilityZones(t *testing.T) *armcontainerservice.ManagedCluster {
	svc := newAKS(t)
	svc.Properties.AgentPoolProfiles = []*armcontainerservice.ManagedClusterAgentPoolProfile{
		{
			AvailabilityZones: []*string{to.StringPtr("1"), to.StringPtr("2"), to.StringPtr("3")},
		},
	}
	return svc
}

func newAKSWithPrivateEndpoints(t *testing.T) *armcontainerservice.ManagedCluster {
	svc := newAKS(t)
	svc.Properties.APIServerAccessProfile.EnablePrivateCluster = to.BoolPtr(true)
	return svc
}

func newAKSResult(t *testing.T) AzureServiceResult {
	return AzureServiceResult{
		SubscriptionID:     "subscriptionId",
		ResourceGroup:      "resourceGroupName",
		ServiceName:        "aks-name",
		SKU:                "Free",
		SLA:                "None",
		Type:               "Microsoft.ContainerService/managedClusters",
		Location:           "westeurope",
		CAFNaming:          true,
		AvailabilityZones:  false,
		PrivateEndpoints:   false,
		DiagnosticSettings: true,
	}
}

func newAKSAvailabilityZonesResult(t *testing.T) AzureServiceResult {
	svc := newAKSResult(t)
	svc.AvailabilityZones = true
	return svc
}

func newAKSPrivateEndpointResult(t *testing.T) AzureServiceResult {
	svc := newAKSResult(t)
	svc.PrivateEndpoints = true
	return svc
}

func TestAKSAnalyzer_Review(t *testing.T) {
	type args struct {
		resourceGroupName string
	}
	tests := []struct {
		name    string
		a       AKSAnalyzer
		args    args
		want    []IAzureServiceResult
		wantErr bool
	}{
		{
			name: "Test Review",
			a: AKSAnalyzer{
				diagnosticsSettings: DiagnosticsSettings{
					diagnosticsSettingsClient: nil,
					ctx:                       context.TODO(),
					hasDiagnosticsFunc: func(resourceId string) (bool, error) {
						return true, nil
					},
				},
				subscriptionID: "subscriptionId",
				ctx:            context.TODO(),
				cred:           nil,
				clustersClient: nil,
				listClustersFunc: func(resourceGroupName string) ([]*armcontainerservice.ManagedCluster, error) {
					return []*armcontainerservice.ManagedCluster{
							newAKS(t),
							newAKSWithAvailabilityZones(t),
							newAKSWithPrivateEndpoints(t),
						},
						nil
				},
			},
			args: args{
				resourceGroupName: "resourceGroupName",
			},
			want: []IAzureServiceResult{
				newAKSResult(t),
				newAKSAvailabilityZonesResult(t),
				newAKSPrivateEndpointResult(t),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.Review(tt.args.resourceGroupName)
			if (err != nil) != tt.wantErr {
				t.Errorf("AKSAnalyzer.Review() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AKSAnalyzer.Review() = %v, want %v", got, tt.want)
			}
		})
	}
}
