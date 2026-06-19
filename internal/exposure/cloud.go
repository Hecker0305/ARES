package exposure

import (
	"time"

	"github.com/ares/engine/internal/secrets"
)

type CloudExposureMonitor struct {
	providers []CloudProvider
}

type CloudProvider interface {
	Name() string
	CheckExposures() ([]ExposureFinding, error)
}

type AWSMonitor struct{}

func NewAWSMonitor() *AWSMonitor {
	return &AWSMonitor{}
}

func (a *AWSMonitor) Name() string { return "aws" }

func (a *AWSMonitor) CheckExposures() ([]ExposureFinding, error) {
	var findings []ExposureFinding

	accessKey := secrets.Get("AWS_ACCESS_KEY_ID")
	secretKey := secrets.Get("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" || secretKey == "" {
		findings = append(findings, ExposureFinding{
			ID:          "aws-no-credentials",
			Type:        ExposureCloudExposure,
			Severity:    SevHigh,
			Title:       "AWS Credentials Not Configured",
			Description: "AWS cloud exposure monitoring cannot run without configured credentials",
			Source:      "AWS",
			Target:      "AWS Account",
			Discovered:  time.Now(),
			Status:      "open",
		})
	}

	return findings, nil
}

type GCPMonitor struct{}

func NewGCPMonitor() *GCPMonitor {
	return &GCPMonitor{}
}

func (g *GCPMonitor) Name() string { return "gcp" }

func (g *GCPMonitor) CheckExposures() ([]ExposureFinding, error) {
	var findings []ExposureFinding

	projectID := secrets.Get("GCP_PROJECT_ID")
	if projectID == "" {
		findings = append(findings, ExposureFinding{
			ID:          "gcp-no-project",
			Type:        ExposureCloudExposure,
			Severity:    SevHigh,
			Title:       "GCP Project Not Configured",
			Description: "GCP cloud exposure monitoring cannot run without a configured project ID",
			Source:      "GCP",
			Target:      "GCP Project",
			Discovered:  time.Now(),
			Status:      "open",
		})
	}

	return findings, nil
}

type AzureMonitor struct{}

func NewAzureMonitor() *AzureMonitor {
	return &AzureMonitor{}
}

func (a *AzureMonitor) Name() string { return "azure" }

func (a *AzureMonitor) CheckExposures() ([]ExposureFinding, error) {
	var findings []ExposureFinding

	tenantID := secrets.Get("AZURE_TENANT_ID")
	clientID := secrets.Get("AZURE_CLIENT_ID")
	if tenantID == "" || clientID == "" {
		findings = append(findings, ExposureFinding{
			ID:          "azure-no-credentials",
			Type:        ExposureCloudExposure,
			Severity:    SevHigh,
			Title:       "Azure Credentials Not Configured",
			Description: "Azure cloud exposure monitoring cannot run without configured credentials",
			Source:      "Azure",
			Target:      "Azure Subscription",
			Discovered:  time.Now(),
			Status:      "open",
		})
	}

	return findings, nil
}

func NewCloudExposureMonitor() *CloudExposureMonitor {
	return &CloudExposureMonitor{
		providers: []CloudProvider{
			NewAWSMonitor(),
			NewGCPMonitor(),
			NewAzureMonitor(),
		},
	}
}

func (c *CloudExposureMonitor) Name() string {
	return "cloud-exposure-monitor"
}

func (c *CloudExposureMonitor) Interval() time.Duration {
	return 6 * time.Hour
}

func (c *CloudExposureMonitor) Run() ([]ExposureFinding, error) {
	var allFindings []ExposureFinding
	for _, p := range c.providers {
		findings, err := p.CheckExposures()
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}
