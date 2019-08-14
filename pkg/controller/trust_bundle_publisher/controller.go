package trustbundlepublisher

import (
	"context"
	"fmt"
	"log"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-network-operator/pkg/controller/statusmanager"
	"github.com/openshift/cluster-network-operator/pkg/names"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// and Start it when the Manager is Started.
func Add(mgr manager.Manager, status *statusmanager.StatusManager) error {
	reconciler := newReconciler(mgr, status)
	if reconciler == nil {
		return fmt.Errorf("failed to create reconciler")
	}

	return add(mgr, reconciler)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, status *statusmanager.StatusManager) reconcile.Reconciler {
	if err := configv1.Install(mgr.GetScheme()); err != nil {
		return &PublisherConfig{}
	}

	return &PublisherConfig{client: mgr.GetClient(), scheme: mgr.GetScheme(), status: status}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("trust-bundle-publisher-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// We only care about a configmap source with a specific name/namespace,
	// so filter events before they are provided to the controller event handlers.
	pred := predicate.Funcs{
		UpdateFunc:  func(e event.UpdateEvent) bool { return handleConfigMap(e.MetaNew) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return handleConfigMap(e.Meta) },
		CreateFunc:  func(e event.CreateEvent) bool { return handleConfigMap(e.Meta) },
		GenericFunc: func(e event.GenericEvent) bool { return handleConfigMap(e.Meta) },
	}

	// Watch for changes to the additional trust bundle configmap.
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForObject{}, pred)
	if err != nil {
		return err
	}

	// Watch for changes to the proxy resource.
	err = c.Watch(&source.Kind{Type: &configv1.Proxy{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

// handleConfigMap returns true if meta namespace is "openshift-config".
func handleConfigMap(meta metav1.Object) bool {
	return meta.GetNamespace() == names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS
}

// PublisherConfig reconciles a Proxy object
type PublisherConfig struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client client.Client
	scheme *runtime.Scheme
	status *statusmanager.StatusManager
}

// Reconcile expects request to refer to a cluster-scoped proxy object
// named "cluster" or a configmap object in namespace "openshift-config"
// and will ensure either object is in the desired state.
func (r *PublisherConfig) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	trustBundle := &corev1.ConfigMap{}
	proxyConfig := &configv1.Proxy{}
	log.Printf("Reconciling request '%s'", request)

	switch {
	case request.NamespacedName == names.Proxy():
		if err := r.client.Get(context.TODO(), request.NamespacedName, proxyConfig); err != nil {
			if apierrors.IsNotFound(err) {
				// Request object not found, could have been deleted after reconcile request.
				// Return and don't requeue
				log.Println("proxy not found; reconciliation will be skipped", "request", request)
				return reconcile.Result{}, nil
			}
			// Error reading the object - requeue the request.
			return reconcile.Result{}, fmt.Errorf("failed to get proxy '%s': %v", request.Name, err)
		}

		if isSpecTrustedCASet(&proxyConfig.Spec) {
			proxyData, systemData, err := r.ensureTrustBundle(proxyConfig.Spec.TrustedCA.Name)
			if err != nil {
				log.Printf("Failed to ensure trustedCA bundle for proxy '%s': %v", proxyConfig.Name, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyConfig",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, nil
			}
			// Create a configmap containing the merged proxy.trustedCA/system bundles.
			trustBundle, err = r.mergeTrustBundles(proxyData, systemData)
			if err != nil {
				log.Printf("Failed to merge trustedCA and system bundles for proxy '%s': %v", proxyConfig.Name, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "ProxyCAMergeFailure",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, nil
			}
		} else {
			var err error
			// No proxy trustedCA so create a configmap containing the system trust bundle.
			if trustBundle, err = r.generateSystemTrustBundle(); err != nil {
				log.Printf("failed to generate system trust bundle configmap '%s/%s': %v",
					names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS, names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "GenerateConfigMapFailure",
					fmt.Sprintf("failed to generate system trust bundle configmap '%s/%s (%v).",
						names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS, names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME, err))
				return reconcile.Result{}, nil
			}
		}

		// Make sure the trust bundle configmap is in sync with the api server.
		if err := r.syncTrustedCABundle(trustBundle); err != nil {
			log.Printf("Failed to sync trust bundle configmap %s/%s: %v", trustBundle.Namespace,
				trustBundle.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "TrustBundleSyncFailure",
				fmt.Sprintf("Trust bundle configmap '%s/%s' not synced (%v)", trustBundle.Namespace,
					trustBundle.Name, err))
			return reconcile.Result{}, nil
		}

	case request.Namespace == names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS:
		if err := r.client.Get(context.TODO(), request.NamespacedName, trustBundle); err != nil {
			if apierrors.IsNotFound(err) {
				// Request object not found, could have been deleted after reconcile request.
				// Return and don't requeue.
				log.Println("configmap not found; reconciliation will be skipped", "request", request)
				return reconcile.Result{}, nil
			}
			// Error reading the object - requeue the request.
			return reconcile.Result{}, fmt.Errorf("failed to get configmap '%s': %v", request, err)
		}

		// Only proceed if request matches the configmap referenced by proxy trustedCA.
		if err := r.configMapIsProxyTrustedCA(trustBundle.Name); err != nil {
			log.Printf("configmap '%s/%s' name differs from trustedCA of proxy '%s' or trustedCA not set; "+
				"reconciliation will be skipped", trustBundle.Namespace, trustBundle.Name, names.PROXY_CONFIG)
			return reconcile.Result{}, nil
		}
	default:
		// unknown object
		log.Println("Ignoring unknown object, reconciliation will be skipped", "request", request)
		return reconcile.Result{}, nil
	}

	// Make sure the trust bundle configmap is in sync with the api server.
	if err := r.syncTrustedCABundle(trustBundle); err != nil {
		log.Printf("Failed to sync trust bundle configmap %s/%s: %v", trustBundle.Namespace,
			trustBundle.Name, err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "TrustBundleSyncFailure",
			fmt.Sprintf("Trust bundle configmap '%s/%s' not synced (%v)", trustBundle.Namespace,
				trustBundle.Name, err))
		return reconcile.Result{}, nil
	}

	log.Printf("Reconciling request '%s' complete", request)
	// Reconciliation completed, so set status manager accordingly.
	r.status.SetNotDegraded(statusmanager.ProxyConfig)

	return reconcile.Result{}, nil
}

// isSpecHTTPProxySet returns true if spec.httpProxy of
// proxyConfig is set.
func isSpecHTTPProxySet(proxyConfig *configv1.ProxySpec) bool {
	return len(proxyConfig.HTTPProxy) > 0
}

// isSpecHTTPSProxySet returns true if spec.httpsProxy of
// proxyConfig is set.
func isSpecHTTPSProxySet(proxyConfig *configv1.ProxySpec) bool {
	return len(proxyConfig.HTTPSProxy) > 0
}

// isSpecNoProxySet returns true if spec.NoProxy of proxyConfig is set.
func isSpecNoProxySet(proxyConfig *configv1.ProxySpec) bool {
	return len(proxyConfig.NoProxy) > 0
}

// isSpecTrustedCASet returns true if spec.trustedCA of proxyConfig is set.
func isSpecTrustedCASet(proxyConfig *configv1.ProxySpec) bool {
	return len(proxyConfig.TrustedCA.Name) > 0
}

// mergeTrustBundles merges the additionalData with systemData
// into a single byte slice, ensures the merged byte slice contains valid
// PEM encoded certificates, embeds the merged byte slice into a ConfigMap
// named "trusted-ca-bundle" in namespace "openshift-config-managed" and
// returns the ConfigMap. It's the caller's responsibility to create the
// ConfigMap in the api server.
func (r *PublisherConfig) mergeTrustBundles(additionalData, systemData []byte) (*corev1.ConfigMap, error) {
	if len(additionalData) == 0 {
		return nil, fmt.Errorf("failed to merge ca bundles, additional trust bundle is empty")
	}
	if len(systemData) == 0 {
		return nil, fmt.Errorf("failed to merge ca bundles, system trust bundle is empty")
	}

	combinedTrustData := []byte{}
	for _, d := range additionalData {
		combinedTrustData = append(combinedTrustData, d)
	}
	for _, d := range systemData {
		combinedTrustData = append(combinedTrustData, d)
	}

	mergedCfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME,
			Namespace: names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS,
		},
		Data: map[string]string{
			names.TRUST_BUNDLE_CONFIGMAP_KEY: string(combinedTrustData),
		},
	}
	if _, _, err := r.getTrustBundle(mergedCfgMap); err != nil {
		return nil, fmt.Errorf("failed to validate merged configmap '%s/%s': %v", mergedCfgMap.Namespace,
			mergedCfgMap.Name, err)
	}

	return mergedCfgMap, nil
}

// syncTrustedCABundle checks if ConfigMap named "trusted-ca-bundle"
// in namespace "openshift-config-managed" exists, creating trustedCABundle
// if it doesn't exist or comparing the configmap data values and updating
// trustedCABundle if the values differ.
func (r *PublisherConfig) syncTrustedCABundle(trustedCABundle *corev1.ConfigMap) error {
	currentCfgMap := &corev1.ConfigMap{}
	if err := r.client.Get(context.TODO(), names.TrustedCABundleConfigMap(), currentCfgMap); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get trusted CA bundle configmap '%s/%s': %v",
				trustedCABundle.Namespace, trustedCABundle.Name, err)
		}
		if err := r.client.Create(context.TODO(), trustedCABundle); err != nil {
			return fmt.Errorf("failed to create trusted CA bundle configmap '%s/%s': %v",
				trustedCABundle.Namespace, trustedCABundle.Name, err)
		}
	}

	if !configMapsEqual(names.TRUST_BUNDLE_CONFIGMAP_KEY, currentCfgMap, trustedCABundle) {
		if err := r.client.Update(context.TODO(), trustedCABundle); err != nil {
			return fmt.Errorf("failed to update trusted CA bundle configmap '%s/%s': %v",
				trustedCABundle.Namespace, trustedCABundle.Name, err)
		}
	}

	return nil
}

// configMapsEqual compares the data key values between
// a and b ConfigMaps, returning true if they are equal.
func configMapsEqual(key string, a, b *corev1.ConfigMap) bool {
	return a.Data[key] == b.Data[key]
}

// generateSystemTrustBundle creates a ConfigMap object named
// "trusted-ca-bundle" in namespace "openshift-config-managed". The ConfigMap
// consists of a data key named "ca-bundle.crt" that contains a validated
// system trust bundle. It's the caller's responsibility to create the
// ConfigMap in the api server.
func (r *PublisherConfig) generateSystemTrustBundle() (*corev1.ConfigMap, error) {
	bundleData, err := r.getSystemTrustBundle(names.SYSTEM_TRUST_BUNDLE)
	if err != nil {
		return nil, fmt.Errorf("failed to validate trust bundle %s: %v", names.SYSTEM_TRUST_BUNDLE, err)
	}

	cfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME,
			Namespace: names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS,
		},
		Data: map[string]string{
			names.TRUST_BUNDLE_CONFIGMAP_KEY: string(bundleData),
		},
	}

	return cfgMap, nil
}

// configMapIsProxyTrustedCA returns an error if cfgMapName does not match the
// ConfigMap name referenced by proxy "cluster" trustedCA.
func (r *PublisherConfig) configMapIsProxyTrustedCA(cfgMapName string) error {
	proxyConfig := &configv1.Proxy{}
	err := r.client.Get(context.TODO(), names.Proxy(), proxyConfig)
	if err != nil {
		return fmt.Errorf("failed to get proxy '%s': %v", names.PROXY_CONFIG, err)
	}

	if proxyConfig.Spec.TrustedCA.Name != cfgMapName {
		return fmt.Errorf("configmap name '%s' does not match proxy trustedCA name '%s'", cfgMapName,
			proxyConfig.Spec.TrustedCA.Name)
	}

	return nil
}
