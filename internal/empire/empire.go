package empire

import (
	"crypto/tls"
	"net/http"
)

type EmpireEngine struct {
	client  *http.Client
	baseURL string
	token   string
}

func NewEmpireEngine(baseURL string) *EmpireEngine {
	return &EmpireEngine{
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		baseURL: baseURL,
	}
}
