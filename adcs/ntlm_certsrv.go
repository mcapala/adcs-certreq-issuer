package adcs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/Azure/go-ntlmssp"
)

type NtlmCertsrv struct {
	url      string
	username string
	password string
	//ca         string
	httpClient *http.Client
}

type ProxyResponse struct {
    Status           string `json:"status"`
    Certificate      string `json:"certificate"`
    StatusDescription string `json:"status_description"`
    RequestID        string `json:"request_id"`
    Error            string `json:"error"`
}

const (
	certnew_cer = "certnew.cer"
	certnew_p7b = "certnew.p7b"
	certcarc    = "certcarc.asp"
	certfnsh    = "certfnsh.asp"

	getCertificateEndpoint = "getCertificate"
	requestCertificateEndpoint = "requestCertificate"
	getCAEndpoint = "getCA"

	ct_pkix   = "application/pkix-cert"
	ct_pkcs7  = "application/x-pkcs7-certificates"
	ct_html   = "text/html"
	ct_urlenc = "application/x-www-form-urlencoded"
)

func NewNtlmCertsrv(url string, username string, password string, caCertPool *x509.CertPool, verify bool) (AdcsCertsrv, error) {
	log := log.Log.WithName("newNtlm")
	var client *http.Client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			RootCAs:            caCertPool,
		},
	}
	if os.Getenv("ENABLE_DEBUG") == "true" {
		log.Info("NTLM verification start", "username", username, "password", password, "url", url)
	}
	if username != "" && password != "" {
		// Set up NTLM authentication
		client = &http.Client{
			Transport: ntlmssp.Negotiator{
				RoundTripper: transport,
			},
		}
		if os.Getenv("ENABLE_DEBUG") == "true" {
			log.Info("NTLM verification Using NTLM")
		}
	} else {
		// Plain client with no NTLM
		client = &http.Client{
			Transport: transport,
		}
		if os.Getenv("ENABLE_DEBUG") == "true" {
			log.Info("NTLM verification not using NTLM")
		}
		log.V(5).Info("NTLM verification not using NTL")
	}

	c := &NtlmCertsrv{
		url:        url,
		username:   username,
		password:   password,
		httpClient: client,
	}
	if verify {
		success, err := c.verifyNtlm()
		if !success {
			return nil, err
		}
	}
	if os.Getenv("ENABLE_DEBUG") == "true" {
		log.Info("NTLM verification stop", "username", username, "password", password, "url", url)
	}
	return c, nil
}

// Check if NTLM authentication is working for current credentials and URL
func (s *NtlmCertsrv) verifyNtlm() (bool, error) {
	log := log.Log.WithName("verifyNtlm")
	if os.Getenv("ENABLE_DEBUG") == "true" {
		log.Info("NTLM verification", "username", s.username, "url", s.url)
	}
	log.V(5).Info("NTLM verification", "username", s.username, "url", s.url)

	req, _ := http.NewRequest("GET", s.url, nil)
	req.SetBasicAuth(s.username, s.password)
	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Error(err, "ADCS server error")
		return false, err
	}
	if os.Getenv("ENABLE_DEBUG") == "true" {
		log.Info("NTLM verification successful", "status", res.Status)
	}
	log.V(5).Info("NTLM verification successful", "status", res.Status)
	return true, nil
}

/*
 * Returns:
 * - Certificate response status
 * - Certificate (if status is Ready) or status description (if status is not Ready)
 * - ADCS Request ID
 * - Error
 */
func (s *NtlmCertsrv) GetExistingCertificate(id string) (AdcsResponseStatus, string, string, error) {
	log := log.Log.WithName("GetExistingCertificate")
	var certStatus AdcsResponseStatus = Unknown

	url := fmt.Sprintf("%s/%s", s.url, getCertificateEndpoint)
    payload := map[string]string{
        "request_id": id,
    }
    payloadBytes, err := json.Marshal(payload)
	if err != nil {
        log.Error(err, "Failed to marshal JSON payload")
        return certStatus, "", id, err
    }
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))

    if err != nil {
        log.Error(err, "Failed to create HTTP request")
        return certStatus, "", id, err
    }

    req.SetBasicAuth(s.username, s.password)
    req.Header.Set("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
        log.Error(err, "Failed to send HTTP request")
        return certStatus, "", id, err
    }
	defer res.Body.Close()

    body, err := io.ReadAll(res.Body)
    if err != nil {
        log.Error(err, "Failed to read response body")
        return certStatus, "", id, err
    }

    if res.StatusCode != http.StatusOK {
        errMsg := fmt.Sprintf("Proxy server returned status %d: %s", res.StatusCode, string(body))
        log.Error(fmt.Errorf(errMsg), "non-OK HTTP status")
        return certStatus, "", id, fmt.Errorf(errMsg)
    }

    var proxyResp ProxyResponse
    err = json.Unmarshal(body, &proxyResp)
    if err != nil {
        log.Error(err, "Failed to unmarshal JSON response")
        return certStatus, "", id, err
    }

	// Encode status as an integer

	if proxyResp.Status == "Ready" {
		certStatus = Ready
	} else if proxyResp.Status == "Pending" {
		certStatus = Pending
	} else if proxyResp.Status == "Errored" {
		certStatus = Errored
	} else {
		certStatus = Unknown
	}

    if certStatus == Ready {
        // Decode the base64-encoded certificate
        decodedCert, err := base64.StdEncoding.DecodeString(proxyResp.Certificate)
        if err != nil {
            log.Error(err, "Failed to decode certificate")
            return certStatus, "", id, err
        }
        return certStatus, string(decodedCert), id, nil
    }

    // Return status description if not Ready
    return certStatus, proxyResp.StatusDescription, id, nil
}

/*
 * Returns:
 * - Certificate response status
 * - Certificate (if status is Ready) or status description (if status is not Ready)
 * - ADCS Request ID (if known)
 * - Error
 */
func (s *NtlmCertsrv) RequestCertificate(csr string, template string) (AdcsResponseStatus, string, string, error) {
    log := log.Log.WithName("RequestCertificate").WithValues("template", template)
    var certStatus AdcsResponseStatus = Unknown

    log.Info("Starting certificate request")

    url := fmt.Sprintf("%s/requestCertificate", s.url)
    log.Info("Sending request to proxy server", "url", url)

    // Encode the CSR in base64
    csrB64 := base64.StdEncoding.EncodeToString([]byte(csr))

    // Prepare request payload
    payload := map[string]string{
        "csr":          csrB64,
        "template_name": template,
    }
    payloadBytes, err := json.Marshal(payload)
    if err != nil {
        log.Error(err, "Failed to marshal JSON payload")
        return certStatus, "", "", err
    }

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
    if err != nil {
        log.Error(err, "Failed to create HTTP request")
        return certStatus, "", "", err
    }

    req.SetBasicAuth(s.username, s.password)
    req.Header.Set("Content-Type", "application/json")

    res, err := s.httpClient.Do(req)
    if err != nil {
        log.Error(err, "Failed to send HTTP request")
        return certStatus, "", "", err
    }
    defer res.Body.Close()

    body, err := io.ReadAll(res.Body)
    if err != nil {
        log.Error(err, "Failed to read response body")
        return certStatus, "", "", err
    }

    if res.StatusCode != http.StatusOK {
        errMsg := fmt.Sprintf("Proxy server returned status %d: %s", res.StatusCode, string(body))
        log.Error(fmt.Errorf(errMsg), "Non-OK HTTP status")
        return certStatus, "", "", fmt.Errorf(errMsg)
    }

    var proxyResp ProxyResponse
    err = json.Unmarshal(body, &proxyResp)
    if err != nil {
        log.Error(err, "Failed to unmarshal JSON response")
        return certStatus, "", "", err
    }

	if proxyResp.Status == "Ready" {
		certStatus = Ready
	} else if proxyResp.Status == "Pending" {
		certStatus = Pending
	} else if proxyResp.Status == "Errored" {
		certStatus = Errored
	} else {
		certStatus = Unknown
	}

    requestID := proxyResp.RequestID

    if certStatus == Ready {
        // Decode the base64-encoded certificate
        decodedCert, err := base64.StdEncoding.DecodeString(proxyResp.Certificate)
        if err != nil {
            log.Error(err, "Failed to decode certificate")
            return certStatus, "", requestID, err
        }
        return certStatus, string(decodedCert), requestID, nil
    }

    // Return status description if not Ready
    return certStatus, proxyResp.StatusDescription, requestID, nil
}

func (s *NtlmCertsrv) obtainCaCertificate(certPage string, expectedContentType string) (string, error) {
	log := log.Log.WithName("obtainCaCertificate")

	url := fmt.Sprintf("%s/%s", s.url, getCAEndpoint)
	// klog.V(4).Infof("inside obtainCaCertificate: going to url: %v ", url)
	req, _ := http.NewRequest("GET", url, nil)

    req.SetBasicAuth(s.username, s.password)
    req.Header.Set("Content-Type", "application/json")

    res, err := s.httpClient.Do(req)
    if err != nil {
        log.Error(err, "Failed to send HTTP request")
        return "", err
    }
    defer res.Body.Close()

    body, err := io.ReadAll(res.Body)
    if err != nil {
        log.Error(err, "Failed to read response body")
        return "", err
    }

    if res.StatusCode != http.StatusOK {
        errMsg := fmt.Sprintf("Proxy server returned status %d: %s", res.StatusCode, string(body))
        log.Error(fmt.Errorf(errMsg), "Non-OK HTTP status")
        return "", fmt.Errorf(errMsg)
    }

    var proxyResp ProxyResponse
    err = json.Unmarshal(body, &proxyResp)
	if err != nil {
        log.Error(err, "Failed to unmarshal JSON response")
        return "", err
    }

	if proxyResp.Status != "Ready" {
		return "", fmt.Errorf("CA certificate not ready")
	}

	// Decode the base64-encoded certificate
	decodedCert, err := base64.StdEncoding.DecodeString(proxyResp.Certificate)
	if err != nil {
		log.Error(err, "Failed to decode certificate")
		return "", err
	}
	return string(decodedCert), nil
}
func (s *NtlmCertsrv) GetCaCertificate() (string, error) {
	log.Log.WithName("GetCaCertificate").Info("Getting CA from ADCS Certsrv", "url", s.url)
	return s.obtainCaCertificate(certnew_cer, ct_pkix)
}
func (s *NtlmCertsrv) GetCaCertificateChain() (string, error) {
	log.Log.WithName("GetCaCertificateChain").Info("Getting CA Chain from ADCS Certsrv", "url", s.url)
	return s.obtainCaCertificate(certnew_p7b, ct_pkcs7)
}
