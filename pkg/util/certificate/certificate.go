package validation

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/openshift/cluster-network-operator/pkg/names"

	corev1 "k8s.io/api/core/v1"
)

const (
	// certPEMBlock is the type taken from the preamble of a PEM-encoded structure.
	certPEMBlock = "CERTIFICATE"
)

// GenerateCertificateDataFromConfigMap validates that cfgMap contains a key named
// "ca-bundle.crt" and the key's value is one or more valid PEM encoded certificates,
// returning a byte slice of the certificate data upon success.
func GenerateCertificateDataFromConfigMap(cfgMap *corev1.ConfigMap) ([]byte, error) {
	if _, ok := cfgMap.Data[names.TRUSTED_CA_BUNDLE_CONFIGMAP_KEY]; !ok {
		return nil, fmt.Errorf("ConfigMap %q is missing %q", cfgMap.Name, names.TRUSTED_CA_BUNDLE_CONFIGMAP_KEY)
	}
	trustBundleData := []byte(cfgMap.Data[names.TRUSTED_CA_BUNDLE_CONFIGMAP_KEY])
	if len(trustBundleData) == 0 {
		return nil, fmt.Errorf("data key %q is empty from ConfigMap %q", names.TRUSTED_CA_BUNDLE_CONFIGMAP_KEY, cfgMap.Name)
	}

	return trustBundleData, nil
}

// GenerateCertificatesFromConfigMap validates that cfgMap contains a key named
// "ca-bundle.crt" and the key's value is one or more valid PEM encoded certificates,
// returning a byte slice of x509.Certificate pointers upon success.
func GenerateCertificatesFromConfigMap(cfgMap *corev1.ConfigMap) ([]*x509.Certificate, error) {
	trustBundleData, err := GenerateCertificateDataFromConfigMap(cfgMap)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate data from ConfigMap '%s/%s': %v", cfgMap.Name,
			cfgMap.Namespace, err)
	}
	certBundle, err := GenerateCertsFromData(trustBundleData)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate data from ConfigMap %q: %v", cfgMap.Name, err)
	}

	return certBundle, nil
}

// GenerateCertsFromData decodes certData, ensuring each PEM block is type
// "CERTIFICATE" and the block can be parsed as an x509 certificate,
// returning a slice of x509.Certificate pointers.
func GenerateCertsFromData(certData []byte) ([]*x509.Certificate, error) {
	var block *pem.Block
	certBundle := []*x509.Certificate{}
	for len(certData) > 0 {
		block, certData = pem.Decode(certData)
		if block == nil {
			return nil, fmt.Errorf("failed to parse certificate PEM")
		}
		if block.Type != certPEMBlock {
			return nil, fmt.Errorf("invalid certificate PEM, must be of type %q", certPEMBlock)

		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		certBundle = append(certBundle, cert)
	}

	return certBundle, nil
}

// EnsureCertData ensures certData contains valid PEM encoded blocks
// containing a "CERTIFICATE" preamble type for each block.
func EnsureCertData(certData []byte) error {
	var block *pem.Block
	for len(certData) > 0 {
		block, certData = pem.Decode(certData)
		if block == nil {
			return fmt.Errorf("failed to parse certificate PEM")
		}
		if block.Type != certPEMBlock {
			return fmt.Errorf("invalid certificate PEM, must be of type %q", certPEMBlock)

		}
	}

	return nil
}

// MergeDataToCertificates merges addlData and systemData into a slice of *x509.Certificate.
func MergeDataToCertificates(addlData, systemData []byte) ([]*x509.Certificate, error) {
	var mergedCerts []*x509.Certificate
	if len(addlData) > 0 {
		addlCerts, err := GenerateCertsFromData(addlData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate data: %v", err)
		}
		for _, cert := range addlCerts {
			mergedCerts = append(mergedCerts, cert)
		}
	}
	if len(systemData) > 0 {
		systemCerts, err := GenerateCertsFromData(systemData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate data: %v", err)
		}
		for _, cert := range systemCerts {
			mergedCerts = append(mergedCerts, cert)
		}
	}

	return mergedCerts, nil
}

// MergeCertificateData merges addlData and systemData into a single byte slice
// of certificate data.
func MergeCertificateData(addlData, systemData []byte) ([]byte, error) {
	var combinedData []byte
	if len(addlData) > 0 {
		for _, d := range addlData {
			combinedData = append(combinedData, d)
		}
	}
	if len(systemData) == 0 {
		for _, d := range systemData {
			combinedData = append(combinedData, d)
		}
	}

	return combinedData, nil
}

// MergeCertificates merges certsA and certsA into a single slice of x509.Certificate pointers.
func MergeCertificates(certsA, certsB []*x509.Certificate) ([]*x509.Certificate, error) {
	var mergedCerts []*x509.Certificate
	if len(certsA) > 0 {
		for _, cert := range certsA {
			mergedCerts = append(mergedCerts, cert)
		}
	}
	if len(certsB) > 0 {
		for _, cert := range certsB {
			mergedCerts = append(mergedCerts, cert)
		}
	}

	return mergedCerts, nil
}

// GenerateCertificateDataFromFile...
func GenerateCertificateDataFromFile(file string) ([]byte, error) {
	bundleData, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	if _, err := GenerateCertsFromData(bundleData); err != nil {
		return nil, err
	}

	return bundleData, nil
}

// GenerateCertificatesFromFile...
func GenerateCertificatesFromFile(file string) ([]*x509.Certificate, error) {
	var certBundle []*x509.Certificate
	data, err := GenerateCertificateDataFromFile(file)
	if err != nil {
		return nil, err
	}

	if certBundle, err = GenerateCertsFromData(data); err != nil {
		return nil, err
	}

	return certBundle, nil
}
