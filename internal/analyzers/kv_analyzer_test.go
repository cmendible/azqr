package analyzers

import (
	"context"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/go-autorest/autorest/to"
)

func newKeyVault(t *testing.T) *armkeyvault.Vault {
	sku := armkeyvault.SKUNameStandard
	return &armkeyvault.Vault{
		ID:       to.StringPtr("id"),
		Name:     to.StringPtr("kv-name"),
		Location: to.StringPtr("westeurope"),
		Type:     to.StringPtr("Microsoft.KeyVault/vaults"),
		Properties: &armkeyvault.VaultProperties{
			SKU: &armkeyvault.SKU{
				Name: &sku,
			},
			PrivateEndpointConnections: []*armkeyvault.PrivateEndpointConnectionItem{},
		},
	}
}

func newKeyVaultWithPrivateEndpoints(t *testing.T) *armkeyvault.Vault {
	svc := newKeyVault(t)
	svc.Properties.PrivateEndpointConnections = []*armkeyvault.PrivateEndpointConnectionItem{
		{
			ID: to.StringPtr("id"),
		},
	}
	return svc
}

func newKeyVaultResult(t *testing.T) AzureServiceResult {
	return AzureServiceResult{
		SubscriptionID:     "subscriptionId",
		ResourceGroup:      "resourceGroupName",
		ServiceName:        "kv-name",
		SKU:                "standard",
		SLA:                "99.99%",
		Type:               "Microsoft.KeyVault/vaults",
		Location:           "westeurope",
		CAFNaming:          true,
		AvailabilityZones:  true,
		PrivateEndpoints:   false,
		DiagnosticSettings: true,
	}
}

func newKeyVaultPrivateEndpointResult(t *testing.T) AzureServiceResult {
	svc := newKeyVaultResult(t)
	svc.PrivateEndpoints = true
	return svc
}

func TestKeyVaultAnalyzer_Review(t *testing.T) {
	type args struct {
		resourceGroupName string
	}
	tests := []struct {
		name    string
		c       KeyVaultAnalyzer
		args    args
		want    []IAzureServiceResult
		wantErr bool
	}{
		{
			name: "Test Review",
			c: KeyVaultAnalyzer{
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
				vaultsClient:   nil,
				listVaultsFunc: func(resourceGroupName string) ([]*armkeyvault.Vault, error) {
					return []*armkeyvault.Vault{
							newKeyVault(t),
							newKeyVaultWithPrivateEndpoints(t),
						},
						nil
				},
			},
			args: args{
				resourceGroupName: "resourceGroupName",
			},
			want: []IAzureServiceResult{
				newKeyVaultResult(t),
				newKeyVaultPrivateEndpointResult(t),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.c.Review(tt.args.resourceGroupName)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyVaultAnalyzer.Review() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyVaultAnalyzer.Review() = %v, want %v", got, tt.want)
			}
		})
	}
}
