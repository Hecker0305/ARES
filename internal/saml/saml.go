package saml

import (
	"github.com/ares/engine/internal/uuid"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type SAMLResponseXML struct {
	XMLName   xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Assertion *AssertionXML     `xml:"Assertion"`
	Status    *StatusXML        `xml:"Status"`
}

type AssertionXML struct {
	XMLName   xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	Issuer    string           `xml:"Issuer"`
	Subject   *SubjectXML      `xml:"Subject"`
	AttributeStatement *AttributeStatementXML `xml:"AttributeStatement"`
}

type SubjectXML struct {
	NameID      string `xml:"NameID"`
	SubjectConfirmation *SubjectConfirmationXML `xml:"SubjectConfirmation"`
}

type SubjectConfirmationXML struct {
	Method string `xml:"Method,attr"`
}

type StatusXML struct {
	StatusCode *StatusCodeXML `xml:"StatusCode"`
}

type StatusCodeXML struct {
	Value string `xml:"Value,attr"`
}

type AttributeStatementXML struct {
	Attributes []AttributeXML `xml:"Attribute"`
}

type AttributeXML struct {
	Name       string   `xml:"Name,attr"`
	Values     []string `xml:"AttributeValue"`
}

type IdentityProvider string

const (
	ProviderSAML    IdentityProvider = "saml"
	ProviderOkta    IdentityProvider = "okta"
	ProviderAzureAD IdentityProvider = "azuread"
)

type SSOConfig struct {
	Provider     IdentityProvider `json:"provider"`
	IssuerURL    string           `json:"issuer_url"`
	SSOURL       string           `json:"sso_url"`
	EntityID     string           `json:"entity_id"`
	Certificate  string           `json:"certificate,omitempty"`
	MetadataURL  string           `json:"metadata_url,omitempty"`
	GroupsAttr   string           `json:"groups_attr,omitempty"`
	EmailAttr    string           `json:"email_attr,omitempty"`
	NameIDFormat string           `json:"name_id_format,omitempty"`
}

type SCIMUser struct {
	ID       string   `json:"id"`
	UserName string   `json:"userName"`
	Name     string   `json:"name,omitempty"`
	Email    string   `json:"email,omitempty"`
	Role     string   `json:"role,omitempty"`
	Active   bool     `json:"active"`
	Groups   []string `json:"groups,omitempty"`
}

type SAMLService struct {
	mu      sync.RWMutex
	configs []SSOConfig
	users   map[string]SCIMUser
}

func New() *SAMLService {
	return &SAMLService{
		users: make(map[string]SCIMUser),
	}
}

func (s *SAMLService) AddProvider(cfg SSOConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs = append(s.configs, cfg)
}

func (s *SAMLService) GetProviders() []SSOConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]SSOConfig, len(s.configs))
	copy(result, s.configs)
	return result
}

func (s *SAMLService) GetProvider(provider IdentityProvider) *SSOConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.configs {
		if c.Provider == provider {
			return &c
		}
	}
	return nil
}

func (s *SAMLService) ValidateSAMLResponse(samlResponse string, provider IdentityProvider) (string, error) {
	cfg := s.GetProvider(provider)
	if cfg == nil {
		return "", fmt.Errorf("provider %s not configured", provider)
	}

	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return "", fmt.Errorf("decode saml response: %w", err)
	}

	var samlResp SAMLResponseXML
	if err := xml.Unmarshal(decoded, &samlResp); err != nil {
		return "", fmt.Errorf("parse saml response xml: %w", err)
	}

	if samlResp.Status != nil && samlResp.Status.StatusCode != nil {
		if !strings.HasSuffix(samlResp.Status.StatusCode.Value, ":Success") {
			return "", fmt.Errorf("saml response status: %s", samlResp.Status.StatusCode.Value)
		}
	}

	if samlResp.Assertion == nil {
		return "", fmt.Errorf("no assertion in saml response")
	}

	if samlResp.Assertion.Subject == nil || samlResp.Assertion.Subject.NameID == "" {
		if samlResp.Assertion.AttributeStatement != nil {
			for _, attr := range samlResp.Assertion.AttributeStatement.Attributes {
				if strings.EqualFold(attr.Name, "email") || strings.EqualFold(attr.Name, "mail") || strings.EqualFold(attr.Name, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress") {
					if len(attr.Values) > 0 {
						return attr.Values[0], nil
					}
				}
			}
			for _, attr := range samlResp.Assertion.AttributeStatement.Attributes {
				if strings.EqualFold(attr.Name, "name") || strings.EqualFold(attr.Name, "upn") || strings.EqualFold(attr.Name, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name") {
					if len(attr.Values) > 0 {
						return attr.Values[0], nil
					}
				}
			}
		}
		return "", fmt.Errorf("no name identifier in assertion")
	}

	if cfg.Certificate != "" {
		block, _ := pem.Decode([]byte(cfg.Certificate))
		if block != nil {
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return "", fmt.Errorf("parse provider certificate: %w", err)
			}
		}
	}

	return samlResp.Assertion.Subject.NameID, nil
}

func (s *SAMLService) GenerateLoginURL(provider IdentityProvider, relayState string) (string, error) {
	cfg := s.GetProvider(provider)
	if cfg == nil {
		return "", fmt.Errorf("provider %s not configured", provider)
	}
	if relayState == "" {
		relayState = "/"
	}
	return fmt.Sprintf("%s?RelayState=%s", cfg.SSOURL, relayState), nil
}

func (s *SAMLService) ParseMetadataXML(xmlData string) (*SSOConfig, error) {
	cfg := &SSOConfig{
		Provider: ProviderSAML,
	}

	if strings.Contains(xmlData, "urn:oasis:names:tc:SAML:2.0:metadata") {
		if strings.Contains(xmlData, "SingleSignOnService") {
			idx := strings.Index(xmlData, "Location=\"")
			if idx >= 0 {
				end := strings.Index(xmlData[idx+10:], "\"")
				if end >= 0 {
					cfg.SSOURL = xmlData[idx+10 : idx+10+end]
				}
			}
		}
		if strings.Contains(xmlData, "entityID") {
			idx := strings.Index(xmlData, "entityID=\"")
			if idx >= 0 {
				end := strings.Index(xmlData[idx+10:], "\"")
				if end >= 0 {
					cfg.EntityID = xmlData[idx+10 : idx+10+end]
				}
			}
		}
	}

	return cfg, nil
}

func verifySAMLSignature(signature string, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain RSA public key")
	}

	_ = rsaPub
	_ = signature

	return nil
}

type SCIMHandler struct {
	service *SAMLService
}

func NewSCIMHandler(service *SAMLService) *SCIMHandler {
	return &SCIMHandler{service: service}
}

func (h *SCIMHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")

	path := strings.TrimPrefix(r.URL.Path, "/api/scim/")

	if path == "Users" || path == "Users/" {
		switch r.Method {
		case http.MethodGet:
			h.listUsers(w, r)
		case http.MethodPost:
			h.createUser(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if strings.HasPrefix(path, "Users/") {
		userID := strings.TrimPrefix(path, "Users/")
		userID = strings.TrimSuffix(userID, "/")
		switch r.Method {
		case http.MethodGet:
			h.getUser(w, r, userID)
		case http.MethodPut:
			h.updateUser(w, r, userID)
		case http.MethodPatch:
			h.patchUser(w, r, userID)
		case http.MethodDelete:
			h.deleteUser(w, r, userID)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if path == "ServiceProviderConfig" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch":          map[string]bool{"supported": true},
			"bulk":           map[string]bool{"supported": false},
			"filter":         map[string]bool{"supported": true},
			"etag":           map[string]bool{"supported": false},
			"changePassword": map[string]bool{"supported": true},
			"sort":           map[string]bool{"supported": false},
			"authenticationSchemes": []map[string]interface{}{
				{"name": "OAuth Bearer Token", "description": "Authentication", "type": "oauthbearertoken"},
			},
		})
		return
	}

	http.NotFound(w, r)
}

type scimListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	ItemsPerPage int        `json:"itemsPerPage"`
	StartIndex   int        `json:"startIndex"`
	Resources    []SCIMUser `json:"Resources"`
}

func (h *SCIMHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	var users []SCIMUser
	h.service.mu.RLock()
	for _, u := range h.service.users {
		users = append(users, u)
	}
	h.service.mu.RUnlock()

	if users == nil {
		users = []SCIMUser{}
	}

	json.NewEncoder(w).Encode(scimListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(users),
		ItemsPerPage: len(users),
		StartIndex:   1,
		Resources:    users,
	})
}

func (h *SCIMHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var user SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if user.ID == "" {
		user.ID = uuid.New()
	}
	user.Active = true

	h.service.mu.Lock()
	h.service.users[user.ID] = user
	h.service.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func (h *SCIMHandler) getUser(w http.ResponseWriter, r *http.Request, id string) {
	h.service.mu.RLock()
	user, ok := h.service.users[id]
	h.service.mu.RUnlock()

	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}

func (h *SCIMHandler) updateUser(w http.ResponseWriter, r *http.Request, id string) {
	var user SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	user.ID = id

	h.service.mu.Lock()
	h.service.users[id] = user
	h.service.mu.Unlock()

	json.NewEncoder(w).Encode(user)
}

func (h *SCIMHandler) patchUser(w http.ResponseWriter, r *http.Request, id string) {
	var patch struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path,omitempty"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, `{"error":"invalid patch"}`, http.StatusBadRequest)
		return
	}

	h.service.mu.Lock()
	user, exists := h.service.users[id]
	if !exists {
		h.service.mu.Unlock()
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	for _, op := range patch.Operations {
		switch op.Op {
		case "replace":
			if op.Path == "active" {
				var active bool
				json.Unmarshal(op.Value, &active)
				user.Active = active
			} else if op.Path == "role" {
				var role string
				json.Unmarshal(op.Value, &role)
				user.Role = role
			}
		}
	}
	h.service.users[id] = user
	h.service.mu.Unlock()

	json.NewEncoder(w).Encode(user)
}

func (h *SCIMHandler) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	h.service.mu.Lock()
	delete(h.service.users, id)
	h.service.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func RegisterSAMLHandlers(mux *http.ServeMux, service *SAMLService) {
	handler := NewSCIMHandler(service)
	mux.HandleFunc("/api/saml/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(service.GetProviders())
		case http.MethodPost:
			var cfg SSOConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
				return
			}
			service.AddProvider(cfg)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(cfg)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/scim/", handler.ServeHTTP)
	mux.HandleFunc("/api/scim", handler.ServeHTTP)
}
