package analyzers

import (
	"strconv"
	"strings"
)

type (
	// IAzureServiceResult - Interface for all Azure Service Results
	IAzureServiceResult interface {
		GetResourceType() string
		GetProperties() []string
		GetDetailProperties() []string
		ToMap() map[string]string
		ToDetail() map[string]string
		Value() AzureServiceResult
	}

	// AzureServiceAnalyzer - Interface for all Azure Service Analyzers
	AzureServiceAnalyzer interface {
		Review(resourceGroupName string) ([]IAzureServiceResult, error)
	}

	// AzureServiceResult - Struct for all Azure Service Results
	AzureServiceResult struct {
		SubscriptionID     string
		ResourceGroup      string
		ServiceName        string
		SKU                string
		SLA                string
		Type               string
		Location           string
		CAFNaming          bool
		AvailabilityZones  bool
		PrivateEndpoints   bool
		DiagnosticSettings bool
	}
)

// ToMap - Returns a map representation of the Azure Service Result
func (r AzureServiceResult) ToMap() map[string]string {
	return map[string]string{
		"SubscriptionID": r.SubscriptionID,
		"ResourceGroup":  r.ResourceGroup,
		"Location":       parseLocation(r.Location),
		"Type":           r.Type,
		"Name":           r.ServiceName,
		"SKU":            r.SKU,
		"SLA":            r.SLA,
		"AZ":             strconv.FormatBool(r.AvailabilityZones),
		"PE":             strconv.FormatBool(r.PrivateEndpoints),
		"DS":             strconv.FormatBool(r.DiagnosticSettings),
		"CAF":            strconv.FormatBool(r.CAFNaming),
	}
}

// ToDetail - Returns a map representation of the Azure Service Result
func (r AzureServiceResult) ToDetail() map[string]string {
	return map[string]string{}
}

// GetResourceType - Returns the resource type of the Azure Service Result
func (r AzureServiceResult) GetResourceType() string {
	return r.Type
}

// GetProperties - Returns the headers of the Azure Service Result
func (r AzureServiceResult) GetProperties() []string {
	return []string{
		"SubscriptionID",
		"ResourceGroup",
		"Location",
		"Type",
		"Name",
		"SKU",
		"SLA",
		"AZ",
		"PE",
		"DS",
		"CAF",
	}
}

// GetDetailProperties - Returns the detail headers of the Azure Service Result
func (r AzureServiceResult) GetDetailProperties() []string {
	return []string{}
}

// Get - Returns the Azure Service Result
func (r AzureServiceResult) Value() AzureServiceResult {
	return r
}

// AzureFunctionAppResult - Struct for Azure Fucntion App Results
type AzureFunctionAppResult struct {
	AzureServiceResult
	AzureWebJobsDashboard         bool
	ScaleControllerLoggingEnabled bool // SCALE_CONTROLLER_LOGGING_ENABLED
	ContentOverVNET               bool // WEBSITE_CONTENTOVERVNET
	RunFromPackage                bool // WEBSITE_RUN_FROM_PACKAGE
	VNETRouteAll                  bool // WEBSITE_VNET_ROUTE_ALL
	AppInsightsEnabled            bool // APPINSIGHTS_INSTRUMENTATIONKEY or APPLICATIONINSIGHTS_CONNECTION_STRING
}

// ToDetail - Returns a map representation of the Azure Function App Result
func (r AzureFunctionAppResult) ToDetail() map[string]string {
	return map[string]string{
		"SubscriptionID":                r.SubscriptionID,
		"ResourceGroup":                 r.ResourceGroup,
		"Location":                      parseLocation(r.Location),
		"Type":                          r.Type,
		"Name":                          r.ServiceName,
		"RunFromPackage":                strconv.FormatBool(r.RunFromPackage),
		"ContentOverVNET":               strconv.FormatBool(r.ContentOverVNET),
		"VNETRouteAll":                  strconv.FormatBool(r.VNETRouteAll),
		"AzureWebJobsDashboard":         strconv.FormatBool(r.AzureWebJobsDashboard),
		"AppInsightsEnabled":            strconv.FormatBool(r.AppInsightsEnabled),
		"ScaleControllerLoggingEnabled": strconv.FormatBool(r.ScaleControllerLoggingEnabled),
	}
}

// GetDetailProperties - Returns the detail properties of the Azure Function App Result
func (r AzureFunctionAppResult) GetDetailProperties() []string {
	return []string{
		"SubscriptionID",
		"ResourceGroup",
		"Location",
		"Type",
		"Name",
		"RunFromPackage",
		"ContentOverVNET",
		"VNETRouteAll",
		"AzureWebJobsDashboard",
		"AppInsightsEnabled",
		"ScaleControllerLoggingEnabled",
	}
}

func parseLocation(location string) string {
	return strings.ToLower(strings.ReplaceAll(location, " ", ""))
}
