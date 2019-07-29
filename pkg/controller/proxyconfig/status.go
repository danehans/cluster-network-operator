package proxyconfig

import (
	"context"
	"reflect"

	"github.com/openshift/cluster-network-operator/pkg/names"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uns "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sutil "github.com/openshift/cluster-network-operator/pkg/util/k8s"
)

// ClusterProxyStatus...
func (r *ReconcileProxyConfig) clusterProxyStatus(ctx context.Context, proxy *configv1.Proxy, infra *configv1.Infrastructure, network *configv1.Network, cluster *corev1.ConfigMap) (*uns.Unstructured, error) {
	// retrieve the existing proxy config object
	proxyConfig := &configv1.Proxy{
		TypeMeta:   metav1.TypeMeta{APIVersion: configv1.GroupVersion.String(), Kind: "Proxy"},
		ObjectMeta: metav1.ObjectMeta{Name: names.PROXY_CONFIG},
	}

	err := r.client.Get(ctx, types.NamespacedName{
		Name: names.PROXY_CONFIG,
	}, proxyConfig)
	if err != nil && apierrors.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// Update the proxy config status
	status := statusFromProxyConfig(&proxyConfig.Spec)
	if reflect.DeepEqual(*status, proxyConfig.Status) {
		return nil, nil
	}
	proxyConfig.Status = *status
	proxyConfig.TypeMeta = metav1.TypeMeta{APIVersion: configv1.GroupVersion.String(), Kind: "Proxy"}

	return k8sutil.ToUnstructured(proxyConfig)
}

// statusFromProxyConfig...
func statusFromProxyConfig(proxyConf *configv1.ProxySpec) *configv1.ProxyStatus {
	status := configv1.ProxyStatus{
		HTTPProxy: proxyConf.HTTPProxy,
	}

	return &status
}
