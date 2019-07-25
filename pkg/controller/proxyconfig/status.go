package proxyconfig

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"

	//"github.com/openshift/cluster-network-operator/pkg/names"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/util/sets"
	//"k8s.io/apimachinery/pkg/types"
	//apierrors "k8s.io/apimachinery/pkg/api/errors"
	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//uns "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	//k8sutil "github.com/openshift/cluster-network-operator/pkg/util/k8s"
)

// ClusterProxyStatus...
/*func (r *ReconcileProxyConfig) clusterProxyStatus(ctx context.Context, proxy *configv1.Proxy, infra *configv1.Infrastructure, network *configv1.Network, cluster *corev1.ConfigMap) (*uns.Unstructured, error) {
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
}*/

// syncProxyStatus...
func (r *ReconcileProxyConfig) syncProxyStatus(proxy *configv1.Proxy, infra *configv1.Infrastructure, network *configv1.Network, cluster *corev1.ConfigMap) error {
	updated := proxy.DeepCopy()
	noProxy, err := mergeUserSystemNoProxy(proxy, infra, network, cluster)
	if err != nil {
		return fmt.Errorf("failed to merge user/system noProxy settings: %v", err)
	}

	updated.Status.NoProxy = noProxy
	updated.Status.HTTPProxy = proxy.Spec.HTTPProxy
	updated.Status.HTTPSProxy = proxy.Spec.HTTPSProxy

	if !proxyStatusesEqual(proxy.Status, updated.Status) {
		if err := r.client.Status().Update(context.TODO(), updated); err != nil {
			return fmt.Errorf("failed to update proxy status: %v", err)
		}
	}

	return nil
}

// mergeUserSystemNoProxy...
func mergeUserSystemNoProxy(proxy *configv1.Proxy, infra *configv1.Infrastructure, network *configv1.Network, cluster *corev1.ConfigMap) (string, error) {
	apiServerURL, err := url.Parse(infra.Status.APIServerURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse API server URL")
	}

	internalAPIServer, err := url.Parse(infra.Status.APIServerInternalURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse API server internal URL")
	}

	set := sets.NewString(
		"127.0.0.1",
		"localhost",
		network.Status.ServiceNetwork[0],
		apiServerURL.Hostname(),
		internalAPIServer.Hostname(),
	)
	platform := infra.Status.PlatformStatus.Type

	// TODO: Does a better way exist to get machineCIDR and controlplane replicas?
	type installConfig struct {
		ControlPlane struct {
			Replicas string `json:"replicas"`
		} `json:"controlPlane"`
		Networking struct {
			MachineCIDR string `json:"machineCIDR"`
		} `json:"networking"`
	}
	var ic installConfig
	data, ok := cluster.Data["install-config"]
	if !ok {
		return "", fmt.Errorf("missing install-config in configmap")
	}
	if err := yaml.Unmarshal([]byte(data), &ic); err != nil {
		return "", fmt.Errorf("invalid install-config: %v\njson:\n%s", err, data)
	}

	if platform != configv1.VSpherePlatformType && platform != configv1.NonePlatformType {
		set.Insert("169.254.169.254", ic.Networking.MachineCIDR)
	}

	replicas, err := strconv.Atoi(ic.ControlPlane.Replicas)
	if err != nil {
		return "", fmt.Errorf("failed to parse install config replicas: %v", err)
	}

	for i := int64(0); i < int64(replicas); i++ {
		etcdHost := fmt.Sprintf("etcd-%d.%s", i, infra.Status.EtcdDiscoveryDomain)
		set.Insert(etcdHost)
	}

	for _, clusterNetwork := range network.Status.ClusterNetwork {
		set.Insert(clusterNetwork.CIDR)
	}

	for _, userValue := range strings.Split(proxy.Spec.NoProxy, ",") {
		set.Insert(userValue)
	}

	return strings.Join(set.List(), ","), nil
}

// proxyStatusesEqual compares two ProxyStatus values. Returns true if the
// provided values should be considered equal for the purpose of determining
// whether an update is necessary, false otherwise.
func proxyStatusesEqual(a, b configv1.ProxyStatus) bool {
	if a.HTTPProxy != b.HTTPProxy || a.HTTPSProxy != b.HTTPSProxy || a.NoProxy != b.NoProxy {
		return false
	}

	return true
}
