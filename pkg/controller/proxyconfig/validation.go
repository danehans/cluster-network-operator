package proxyconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	certutil "github.com/openshift/cluster-network-operator/pkg/util/certificate"
	"github.com/openshift/cluster-network-operator/pkg/util/validation"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	proxyHTTPScheme  = "http"
	proxyHTTPSScheme = "https"
	// noProxyWildcard is the string used to as a wildcard attached to a
	// domain suffix in proxy.spec.noProxy to bypass proxying.
	noProxyWildcard = "*"
	// proxyProbeMaxRetries is the number of times to attempt an http GET
	// to a readinessEndpoints endpoint.
	proxyProbeMaxRetries = 3
	// proxyProbeWaitTime is the time to wait before retrying a failed proxy probe.
	proxyProbeWaitTime = 1 * time.Second
)

// ValidateProxyConfig ensures that httpProxy, httpsProxy and
// noProxy fields of proxyConfig are valid.
func (r *ReconcileProxyConfig) ValidateProxyConfig(proxyConfig *configv1.Proxy) error {
	if isSpecHTTPProxySet(proxyConfig) {
		scheme, err := validation.URI(proxyConfig.Spec.HTTPProxy)
		if err != nil {
			return fmt.Errorf("invalid httpProxy URI: %v", err)
		}
		if scheme != proxyHTTPScheme {
			return fmt.Errorf("httpProxy requires a '%s' URI scheme", proxyHTTPScheme)
		}
	}

	if isSpecHTTPSProxySet(proxyConfig) {
		scheme, err := validation.URI(proxyConfig.Spec.HTTPSProxy)
		if err != nil {
			return fmt.Errorf("invalid httpsProxy URI: %v", err)
		}
		if scheme != proxyHTTPScheme && scheme != proxyHTTPSScheme {
			return fmt.Errorf("httpsProxy requires a '%s' or '%s' URI scheme", proxyHTTPScheme, proxyHTTPSScheme)
		}
	}

	if isSpecNoProxySet(proxyConfig) {
		if proxyConfig.Spec.NoProxy != noProxyWildcard {
			for _, v := range strings.Split(proxyConfig.Spec.NoProxy, ",") {
				v = strings.TrimSpace(v)
				errDomain := validation.DomainName(v, false)
				_, _, errCIDR := net.ParseCIDR(v)
				if errDomain != nil && errCIDR != nil {
					return fmt.Errorf("invalid noProxy: %v", v)
				}
			}
		}
	}

	return nil
}

// validateTrustedCAConfigMap validates that name is a valid ConfigMap
// reference and that the ConfigMap contains a valid trust bundle, returning
// a byte slice of the certificate data from the ConfigMap.
func (r *ReconcileProxyConfig) validateTrustedCAConfigMap(name types.NamespacedName) ([]byte, error) {
	cfgMap, err := r.getConfigMap(name)
	if err != nil {
		return nil, fmt.Errorf("failed to validate configmap reference for proxy '%s': %v", err)
	}

	certData, err := certutil.GenerateCertificateDataFromConfigMap(cfgMap)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate data from configmap '%s/%s': %v",
			cfgMap.Namespace, cfgMap.Name, err)
	}

	return certData, nil
}

// getConfigMap returns a Configmap named name.
func (r *ReconcileProxyConfig) getConfigMap(name types.NamespacedName) (*corev1.ConfigMap, error) {
	cfgMap := &corev1.ConfigMap{}
	if err := r.client.Get(context.TODO(), name, cfgMap); err != nil {
		return nil, fmt.Errorf("failed to get configmap '%s/%s': %v", name.Name, name.Namespace, err)
	}

	return cfgMap, nil
}

// validateReadinessEndpoints...
func (r *ReconcileProxyConfig) validateReadinessEndpoints(proxyConfig *configv1.Proxy, certData []byte) error {
	readinessCerts, err := certutil.GenerateCertsFromData(certData)
	if err != nil {
		return fmt.Errorf("failed to generate certificates from data: %v", err)
	}
	for _, endpoint := range proxyConfig.Spec.ReadinessEndpoints {
		scheme, err := validation.URI(endpoint)
		if err != nil {
			return fmt.Errorf("invalid URI for readinessEndpoint '%s': %v", endpoint, err)
		}
		switch {
		case scheme == proxyHTTPScheme:
			if !isSpecHTTPProxySet(proxyConfig) {
				return fmt.Errorf("httpProxy must be set when using a http proxy readinessEndpoint")
			}
			proxyURL, err := url.Parse(proxyConfig.Spec.HTTPProxy)
			if err != nil {
				return fmt.Errorf("failed to parse proxy url '%s': %v", proxyConfig.Spec.HTTPProxy, err)
			}

			endpointURL, err := url.Parse(endpoint)
			if err != nil {
				return fmt.Errorf("failed to parse endpoint url '%s': %v", endpoint, err)
			}
			if err := validateReadinessEndpointWithRetries(readinessCerts, proxyURL, endpointURL, proxyProbeMaxRetries); err != nil {
				return err
			}
		case scheme == proxyHTTPSScheme:
			if !isSpecHTTPSProxySet(proxyConfig) {
				return fmt.Errorf("httpsProxy must be set when using a https proxy readinessEndpoint")
			}
			proxyURL, err := url.Parse(proxyConfig.Spec.HTTPSProxy)
			if err != nil {
				return fmt.Errorf("failed to parse proxy url '%s': %v", proxyConfig.Spec.HTTPSProxy, err)
			}

			endpointURL, err := url.Parse(endpoint)
			if err != nil {
				return fmt.Errorf("failed to parse endpoint url '%s': %v", endpoint, err)
			}
			if len(readinessCerts) == 0 {
				return fmt.Errorf("https proxy probe requires at least one CA certificate")
			}
			if err := validateReadinessEndpointWithRetries(readinessCerts, proxyURL, endpointURL, proxyProbeMaxRetries); err != nil {
				return err
			}
		default:
			return fmt.Errorf("a proxy readiness endpoint requires a '%s' or '%s' URI sheme",
				proxyHTTPScheme, proxyHTTPSScheme)
		}
	}

	return nil
}

// validateReadinessEndpointWithRetries tries to validate endpoint in a
// finite loop using proxy and returns the last result if it never succeeds.
func validateReadinessEndpointWithRetries(caBundle []*x509.Certificate, proxy, endpoint *url.URL, retries int) error {
	var err error
	for i := 0; i < retries; i++ {
		err = runReadinessProbe(caBundle, proxy, endpoint)
		if err == nil {
			return nil
		}
		time.Sleep(proxyProbeWaitTime)
	}

	return err
}

// runReadinessProbe issues an GET request to endpoint using proxy and
// returns an error if a 2XX or 3XX http status code is not returned.
// If proxy has a https scheme and caBundle contains at least one
// valid CA certificate, TLS transport will be used by the client.
func runReadinessProbe(caBundle []*x509.Certificate, proxy, endpoint *url.URL) error {
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxy),
	}

	if proxy.Scheme == proxyHTTPSScheme {
		caPool := x509.NewCertPool()
		for _, cert := range caBundle {
			caPool.AddCert(cert)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: caPool}
	}

	client := &http.Client{
		Transport: transport,
	}

	request, err := http.NewRequest("GET", endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s' using proxy '%s': %v", endpoint.String(),
			proxy.String(), err)
	}

	resp, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("endpoint probe failed for endpoint '%s' using proxy '%s': %v",
			endpoint.String(), proxy.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
		return nil
	}

	return fmt.Errorf("endpoint probe failed with statuscode '%d' for endpoint '%s' using proxy '%s' ",
		resp.StatusCode, endpoint.String(), proxy.String())
}
