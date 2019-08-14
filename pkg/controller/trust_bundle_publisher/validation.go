package trustbundlepublisher

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openshift/cluster-network-operator/pkg/names"
	"github.com/openshift/cluster-network-operator/pkg/util/validation"

	corev1 "k8s.io/api/core/v1"
)

// ensureTrustBundle ensures that trustedCA is a valid ConfigMap
// reference and that the ConfigMap contains a valid trust bundle,
// returning the byte slices of the certificate data from the
// validated trustedCA and system trust bundles.
func (r *PublisherConfig) ensureTrustBundle(trustedCA string) ([]byte, []byte, error) {
	cfgMap, err := r.getConfigMap(trustedCA)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate configmap reference for proxy trustedCA '%s': %v",
			trustedCA, err)
	}

	// TODO: Update return values to include []*x509.Certificates for https readinessEndpoint support.
	_, bundleData, err := r.getTrustBundle(cfgMap)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate trust bundle for proxy trustedCA '%s': %v",
			trustedCA, err)
	}

	systemData, err := r.getSystemTrustBundle(names.SYSTEM_TRUST_BUNDLE)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate system trust bundle '%s': %v", names.SYSTEM_TRUST_BUNDLE, err)
	}

	return bundleData, systemData, nil
}

// getConfigMap returns the ConfigMap referenced by trustedCA.
func (r *PublisherConfig) getConfigMap(trustedCA string) (*corev1.ConfigMap, error) {
	cfgMap := &corev1.ConfigMap{}
	ns := names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS
	if trustedCA == names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME {
		ns = names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS
	}
	if err := r.client.Get(context.TODO(), types.NamespacedName{Namespace: ns, Name: trustedCA}, cfgMap); err != nil {
		return nil, fmt.Errorf("failed to get trustedCA configmap for proxy %s: %v", names.PROXY_CONFIG, err)
	}

	return cfgMap, nil
}

// getTrustBundle is a wrapper for validation.TrustBundleConfigMap(), which
// validates that cfgMap contains a data key named "ca-bundle.crt" and the value
// of the key is one or more valid PEM encoded certificates, returning slices of
// the validated certificates and certificate data.
func (r *PublisherConfig) getTrustBundle(cfgMap *corev1.ConfigMap) ([]*x509.Certificate, []byte, error) {
	certBundle, bundleData, err := validation.TrustBundle(cfgMap)
	if err != nil {
		return nil, nil, err
	}

	return certBundle, bundleData, nil
}

// getSystemTrustBundle reads the trustBundle file, ensuring each
// PEM block is type "CERTIFICATE" and the block can be parsed as an
// x509 CA certificate, returning the parsed certificates as a []byte.
func (r *PublisherConfig) getSystemTrustBundle(trustBundle string) ([]byte, error) {
	bundleData, err := ioutil.ReadFile(trustBundle)
	if err != nil {
		return nil, err
	}
	if _, _, err := validation.CertificateData(bundleData); err != nil {
		return nil, err
	}

	return bundleData, nil
}
