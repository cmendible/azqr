package analyzers

import (
	"context"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/Azure/go-autorest/autorest/to"
)

func newEventGrid(t *testing.T) *armeventgrid.Domain {
	return &armeventgrid.Domain{
		ID:       to.StringPtr("id"),
		Name:     to.StringPtr("evgd-name"),
		Location: to.StringPtr("westeurope"),
		Type:     to.StringPtr("Microsoft.EventGrid/domains"),
		Properties: &armeventgrid.DomainProperties{
			PrivateEndpointConnections: []*armeventgrid.PrivateEndpointConnection{},
		},
	}
}

func newEventGridWithPrivateEndpoints(t *testing.T) *armeventgrid.Domain {
	svc := newEventGrid(t)
	svc.Properties.PrivateEndpointConnections = []*armeventgrid.PrivateEndpointConnection{
		{
			ID: to.StringPtr("id"),
		},
	}
	return svc
}

func newEventGridResult(t *testing.T) AzureServiceResult {
	return AzureServiceResult{
		SubscriptionID:     "subscriptionId",
		ResourceGroup:      "resourceGroupName",
		ServiceName:        "evgd-name",
		SKU:                "None",
		SLA:                "99.99%",
		Type:               "Microsoft.EventGrid/domains",
		Location:           "westeurope",
		CAFNaming:          true,
		AvailabilityZones:  true,
		PrivateEndpoints:   false,
		DiagnosticSettings: true,
	}
}

func newEventGridPrivateEndpointResult(t *testing.T) AzureServiceResult {
	svc := newEventGridResult(t)
	svc.PrivateEndpoints = true
	return svc
}

func TestEventGridAnalyzer_Review(t *testing.T) {
	type args struct {
		resourceGroupName string
	}
	tests := []struct {
		name    string
		a       EventGridAnalyzer
		args    args
		want    []IAzureServiceResult
		wantErr bool
	}{
		{
			name: "Test Review",
			a: EventGridAnalyzer{
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
				domainsClient:  nil,
				listDomainFunc: func(resourceGroupName string) ([]*armeventgrid.Domain, error) {
					return []*armeventgrid.Domain{
							newEventGrid(t),
							newEventGridWithPrivateEndpoints(t),
						},
						nil
				},
			},
			args: args{
				resourceGroupName: "resourceGroupName",
			},
			want: []IAzureServiceResult{
				newEventGridResult(t),
				newEventGridPrivateEndpointResult(t),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.Review(tt.args.resourceGroupName)
			if (err != nil) != tt.wantErr {
				t.Errorf("EventGridAnalyzer.Review() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EventGridAnalyzer.Review() = %v, want %v", got, tt.want)
			}
		})
	}
}
