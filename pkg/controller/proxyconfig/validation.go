package proxyconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/openshift/cluster-network-operator/pkg/names"

	configv1 "github.com/openshift/api/config/v1"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// The number of times the controller will attempt to issue an http GET
	// to the endpoint specified in readinessEndpoints.
	proxyProbeMaxRetries = 3
	// clusterConfigMapKey is the name of the data key containing the PEM encoded
	// CA certificate trust bundle in clusterConfigMapName.
	clusterConfigMapKey  = "ca-bundle.crt"
	proxyHTTPScheme      = "http"
	proxyHTTPSScheme     = "https"
)

// ValidateProxyConfig ensures the proxy config is valid.
func (r *ReconcileProxyConfig) ValidateProxyConfig(proxyConfig *configv1.ProxySpec) error {
	/*if isSpecHTTPProxySet(proxyConfig) {
		scheme, err := validateURI(proxyConfig.HTTPProxy)
		if err != nil {
			return fmt.Errorf("invalid httpProxy URI: %v", err)
		}
		if scheme != proxyHTTPScheme {
			return fmt.Errorf("httpProxy requires a %q URI scheme", proxyHTTPScheme)
		}
	}
	if isSpecHTTPSProxySet(proxyConfig) {
		if isSpecTrustedCASet(proxyConfig) {
			return errors.New("trustedCA is required when using httpsProxy")
		}
		scheme, err := validateURI(proxyConfig.HTTPSProxy)
		if err != nil {
			return fmt.Errorf("invalid httpsProxy URI: %v", err)
		}
		if scheme != proxyHTTPSScheme {
			return fmt.Errorf("httpsProxy requires a %q URI scheme", proxyHTTPSScheme)
		}
	}
	if isSpecNoProxySet(proxyConfig) {
		for _, v := range strings.Split(proxyConfig.NoProxy, ",") {
			v = strings.TrimSpace(v)
			errDomain := validateDomainName(v, false)
			_, _, errCIDR := net.ParseCIDR(v)
			if errDomain != nil && errCIDR != nil {
				return fmt.Errorf("invalid noProxy: %v", v)
			}
		}
	}
	var readinessCerts []*x509.Certificate
	if isSpecTrustedCASet(proxyConfig) {
		certBundle, err := r.validateTrustedCA(proxyConfig)
		if err != nil {
			return fmt.Errorf("failed validating TrustedCA %q: %v", proxyConfig.TrustedCA.Name, err)
		}
		copy(certBundle, readinessCerts[0:])
	}
	if isSpecReadinessEndpoints(proxyConfig) {
		for _, endpoint := range proxyConfig.ReadinessEndpoints {
			scheme, err := validateURI(endpoint)
			if err != nil {
				return fmt.Errorf("invalid URI for endpoint %s: %v", endpoint, err)
			}
			switch {
			case scheme == proxyHTTPScheme:
				if err := validateHTTPReadinessEndpoint(endpoint); err != nil {
					return fmt.Errorf("readinessEndpoint probe failed for endpoint %s", endpoint)
				}
			case scheme == proxyHTTPSScheme:
				if !isSpecTrustedCASet(proxyConfig) {
					return fmt.Errorf("readinessEndpoint with an %q scheme requires trustedCA to be set", proxyHTTPSScheme)
				}
				if err := validateHTTPSReadinessEndpoint(readinessCerts, endpoint); err != nil {
					return fmt.Errorf("readinessEndpoint probe failed for endpoint %s", endpoint)
				}
			default:
				return fmt.Errorf("readiness endpoints requires a %q or %q URI sheme", proxyHTTPScheme, proxyHTTPSScheme)
			}
		}
	}*/

	return nil
}

// validateURI validates if url is a valid absolute URI and returns
// the url scheme.
func validateURI(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	if !parsed.IsAbs() {
		return "", fmt.Errorf("failed validating URI, no scheme for URI %q", uri)
	}
	host := parsed.Hostname()
	if err := validateHost(host); err != nil {
		return "", fmt.Errorf("failed validating URI %q: %v", uri, err)
	}
	if port := parsed.Port(); len(port) != 0 {
		intPort, err := strconv.Atoi(port)
		if err != nil {
			return "", fmt.Errorf("failed converting port to integer for URI %q: %v", uri, err)
		}
		if err := validatePort(intPort); err != nil {
			return "", fmt.Errorf("failed to validate port for URL %q: %v", uri, err)
		}
	}

	return parsed.Scheme, nil
}

// validateHost validates if host is a valid IP address or subdomain in DNS (RFC 1123).
func validateHost(host string) error {
	errDomain := validateDomainName(host, false)
	errIP := validation.IsValidIP(host)
	if errDomain != nil && errIP != nil {
		return fmt.Errorf("invalid host: %s", host)
	}

	return nil
}

// validatePort validates if port is a valid port number between 1-65535.
func validatePort(port int) error {
	invalidPorts := validation.IsValidPortNum(port)
	if invalidPorts != nil {
		return fmt.Errorf("invalid port number: %d", port)
	}

	return nil
}

// validateHTTPReadinessEndpoint validates an http readinessEndpoint endpoint.
func validateHTTPReadinessEndpoint(endpoint string) error {
	if err := validateHTTPReadinessEndpointWithRetries(endpoint, proxyProbeMaxRetries); err != nil {
		return err
	}

	return nil
}

// validateHTTPReadinessEndpointWithRetries tries to validate an http
// endpoint in a finite loop based on the scheme type, it returns the
// last result if it never succeeds.
func validateHTTPReadinessEndpointWithRetries(endpoint string, retries int) error {
	for i := 0; i < retries; i++ {
		if err := runHTTPReadinessProbe(endpoint); err != nil {
			return err
		}
	}

	return nil
}

// runHTTPReadinessProbe issues an http GET request to an http endpoint
// and returns an error if a 2XX or 3XX http status code is not returned.
func runHTTPReadinessProbe(endpoint string) error {
	resp, err := http.Get(endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
		return nil
	}

	return fmt.Errorf("HTTP probe failed with statuscode: %d", resp.StatusCode)
}

// validateHTTPSReadinessEndpoint validates an https readinessEndpoint endpoint.
func validateHTTPSReadinessEndpoint(certBundle []*x509.Certificate, endpoint string) error {
	if err := validateHTTPSReadinessEndpointWithRetries(certBundle, endpoint, proxyProbeMaxRetries); err != nil {
		return err
	}

	return nil
}

// validateHTTPSReadinessEndpointWithRetries tries to validate an endpoint
// by using certBundle to attempt a TLS handshake in a finite loop returning
// the last result if it never succeeds.
func validateHTTPSReadinessEndpointWithRetries(certBundle []*x509.Certificate, endpoint string, retries int) error {
	for i := 0; i < retries; i++ {
		if err := runHTTPSReadinessProbe(certBundle, endpoint); err != nil {
			return err
		}
	}

	return nil
}

// runHTTPSReadinessProbe tries connecting to endpoint by using certBundle
// to attempt a TLS handshake.
func runHTTPSReadinessProbe(certBundle []*x509.Certificate, endpoint string) error {
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("failed parsing URL for endpoint: %s", endpoint)
	}
	certPool := x509.NewCertPool()
	for _, cert := range certBundle {
		certPool.AddCert(cert)
	}
	port := parsedURL.Port()
	if len(port) == 0 {
		parsedURL.Host += ":" + port
	}
	conn, err := tls.Dial("tcp", parsedURL.String(), &tls.Config{
		RootCAs:    certPool,
		ServerName: endpoint,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to endpoint %q: %v", endpoint, err)
	}

	return conn.Close()
}

// validateDomainName checks if the given string is a valid domain name and returns an error if not.
func validateDomainName(v string, acceptTrailingDot bool) error {
	if acceptTrailingDot {
		v = strings.TrimSuffix(v, ".")
	}
	return validateSubdomain(v)
}

// validateSubdomain checks if the given string is a valid subdomain name and returns an error if not.
func validateSubdomain(v string) error {
	validationMessages := validation.IsDNS1123Subdomain(v)
	if len(validationMessages) == 0 {
		return nil
	}

	errs := make([]error, len(validationMessages))
	for i, m := range validationMessages {
		errs[i] = errors.New(m)
	}
	return k8serrors.NewAggregate(errs)
}

// validateTrustedCA validates that spec.TrustedCA...
func (r *ReconcileProxyConfig) validateTrustedCA(proxyConfig *configv1.ProxySpec) ([]*x509.Certificate, error) {
	cfgMap, err := r.validateTrustedCAConfigMap(proxyConfig)
	if err != nil {
		return nil, err
	}

	caBundle, err := validateTrustedCABundle(cfgMap)
	if err != nil {
		return nil, err
	}

	return caBundle, nil
}

// validateTrustedCAConfigMap validates that configMap...
func (r *ReconcileProxyConfig) validateTrustedCAConfigMap(proxyConfig *configv1.ProxySpec) (*corev1.ConfigMap, error) {
	if isExpectedProxyConfigMap(proxyConfig) {
		return nil, fmt.Errorf("invalid ConfigMap reference for TrustedCA: %s", proxyConfig.TrustedCA.Name)
	}
	cfgMap := &corev1.ConfigMap{}
	if err := r.client.Get(context.TODO(), names.ProxyTrustedCAConfigMap(), cfgMap); err != nil {
		return nil, err
	}

	return cfgMap, nil
}

// TODO: Have validateTrustedCABundle return certBundle []byte containing the validated ca bundle.
// validateTrustedCABundle validates that configMap contains a
// CA certificate bundle named clusterConfigMapKey and that
// clusterConfigMapKey contains a valid x.509 certificate.
func validateTrustedCABundle(configMap *corev1.ConfigMap) ([]*x509.Certificate, error) {
	if _, ok := configMap.Data[clusterConfigMapKey]; !ok {
		return nil, fmt.Errorf("ConfigMap %q is missing %q", names.PROXY_TRUSTED_CA_CONFIGMAP, clusterConfigMapKey)
	}
	certData := []byte(configMap.Data[clusterConfigMapKey])
	if len(certData) == 0 {
		return nil, fmt.Errorf("data key %q is empty from ConfigMap %q", clusterConfigMapKey, names.PROXY_TRUSTED_CA_CONFIGMAP)
	}
	certBundle, err := x509.ParseCertificates(certData)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate data from ConfigMap %q: %v",configMap.Name, err)
	}

	return certBundle, nil
}
