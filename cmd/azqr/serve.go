// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package azqr

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Azure/azqr/internal"
	"github.com/Azure/azqr/internal/azqr"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run Azure Quick Review as a service",
	Long:  "Run Azure Quick Review as a service",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		http.HandleFunc("/scan/", scanHandler)
		http.ListenAndServe(":8080", nil)
	},
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var params internal.ScanParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	params.Filters = azqr.LoadFilters("")

	// Validate input
	if params.SubscriptionID == "" && params.ResourceGroup != "" {
		http.Error(w, "Resource Group name can only be used with a Subscription Id", http.StatusBadRequest)
		return
	}

	if params.SubscriptionID != "" {
		params.Filters.Azqr.AddSubscription(params.SubscriptionID)
	}

	// Extract the scan type from the URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.Error(w, "Invalid route", http.StatusBadRequest)
		return
	}
	scanType := pathParts[2]

	// Fill ServiceScanners based on the scan type
	switch scanType {
	case "all":
		params.ServiceScanners = []azqr.IAzureScanner{
			// scanners.NewAKSScanner(),
			// scanners.NewVMScanner(),
			// Add other scanners as needed
		}
	case "aks":
		params.ServiceScanners = []azqr.IAzureScanner{
			// scanners.NewAKSScanner(),
		}
	// Add more cases as needed
	default:
		http.Error(w, "Unknown scan type", http.StatusNotFound)
		return
	}

	go func(params *internal.ScanParams) {
		scanner := internal.Scanner{}
		scanner.Scan(params)
	}(&params)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(params)
}
