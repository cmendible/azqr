// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package afd

import (
	"strings"

	"github.com/Azure/azqr/internal/azqr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn"
)

// GetRules - Returns the rules for the FrontDoorScanner
func (a *FrontDoorScanner) GetRecommendations() map[string]azqr.AzqrRecommendation {
	return map[string]azqr.AzqrRecommendation{
		"afd-001": {
			RecommendationID: "afd-001",
			ResourceType:     "Microsoft.Cdn/profiles",
			Category:         azqr.CategoryMonitoringAndAlerting,
			Recommendation:   "Azure FrontDoor should have diagnostic settings enabled",
			Impact:           azqr.ImpactLow,
			Eval: func(target interface{}, scanContext *azqr.ScanContext) (bool, string) {
				service := target.(*armcdn.Profile)
				_, ok := scanContext.DiagnosticsSettings[strings.ToLower(*service.ID)]
				return !ok, ""
			},
			LearnMoreUrl: "https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/how-to-logs",
		},
		"afd-003": {
			RecommendationID:   "afd-003",
			ResourceType:       "Microsoft.Cdn/profiles",
			Category:           azqr.CategoryHighAvailability,
			Recommendation:     "Azure FrontDoor SLA",
			RecommendationType: azqr.TypeSLA,
			Impact:             azqr.ImpactHigh,
			Eval: func(target interface{}, scanContext *azqr.ScanContext) (bool, string) {
				return false, "99.99%"
			},
			LearnMoreUrl: "https://www.azure.cn/en-us/support/sla/cdn/",
		},
		"afd-006": {
			RecommendationID: "afd-006",
			ResourceType:     "Microsoft.Cdn/profiles",
			Category:         azqr.CategoryGovernance,
			Recommendation:   "Azure FrontDoor Name should comply with naming conventions",
			Impact:           azqr.ImpactLow,
			Eval: func(target interface{}, scanContext *azqr.ScanContext) (bool, string) {
				c := target.(*armcdn.Profile)
				caf := strings.HasPrefix(*c.Name, "afd")
				return !caf, ""
			},
			LearnMoreUrl: "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations",
		},
		"afd-007": {
			RecommendationID: "afd-007",
			ResourceType:     "Microsoft.Cdn/profiles",
			Category:         azqr.CategoryGovernance,
			Recommendation:   "Azure FrontDoor should have tags",
			Impact:           azqr.ImpactLow,
			Eval: func(target interface{}, scanContext *azqr.ScanContext) (bool, string) {
				c := target.(*armcdn.Profile)
				return len(c.Tags) == 0, ""
			},
			LearnMoreUrl: "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources?tabs=json",
		},
	}
}
