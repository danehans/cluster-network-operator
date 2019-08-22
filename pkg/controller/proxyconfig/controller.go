package proxyconfig

import (
	"context"
	"fmt"
	"log"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-network-operator/pkg/controller/statusmanager"
	"github.com/openshift/cluster-network-operator/pkg/names"
	certutil "github.com/openshift/cluster-network-operator/pkg/util/certificate"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
		return &ReconcileProxyConfig{}
	}

	return &ReconcileProxyConfig{client: mgr.GetClient(), scheme: mgr.GetScheme(), status: status}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("proxyconfig-controller", mgr, controller.Options{Reconciler: r})
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

// ReconcileProxyConfig reconciles a Proxy object
type ReconcileProxyConfig struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client client.Client
	scheme *runtime.Scheme
	status *statusmanager.StatusManager
}

// Reconcile expects request to refer to a cluster-scoped proxy object
// named "cluster" or a configmap object in namespace "openshift-config"
// and will ensure either object is in the desired state.
func (r *ReconcileProxyConfig) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	var err error
	var systemData []byte
	var trustedCAData []byte
	var mergedData []byte
	proxyConfig := &configv1.Proxy{}
	trustedCACfgMap := &corev1.ConfigMap{}
	validate := true

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

	// Get the system trust bundle.
	if systemData, err = certutil.GenerateCertificateDataFromFile(names.SYSTEM_TRUST_BUNDLE); err != nil {
		log.Printf("Failed to generate certificates from system trust bundle '%s': %v", names.SYSTEM_TRUST_BUNDLE, err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "ValidateSystemBundle",
			fmt.Sprintf("failed to generate certificates from system trust bundle '%s' (%v).",
				names.SYSTEM_TRUST_BUNDLE, err))
		return reconcile.Result{}, fmt.Errorf("failed to generate certificates from system trust bundle '%s': %v",
			names.SYSTEM_TRUST_BUNDLE, err)
	}

	switch {
	case request.NamespacedName == names.Proxy():
		infraConfig := &configv1.Infrastructure{}
		netConfig := &configv1.Network{}
		clusterConfig := &corev1.ConfigMap{}

		log.Printf("Reconciling proxy '%s'", request.Name)
		// A nil proxy is generated by upgrades and installs not requiring a proxy.
		if !isSpecHTTPProxySet(proxyConfig) && !isSpecHTTPSProxySet(proxyConfig) &&	!isSpecNoProxySet(proxyConfig) {
			log.Printf("httpProxy, httpsProxy and noProxy not defined for proxy '%s'; validation will be skipped",
				request.Name)
			validate = false
		}

		if validate {
			if err := r.ValidateProxyConfig(proxyConfig); err != nil {
				log.Printf("Failed to validate proxy '%s': %v", proxyConfig.Name, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyConfig",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, fmt.Errorf("failed to validate proxy '%s': %v", proxyConfig.Name, err)
			}
		}

		if isSpecTrustedCASet(proxyConfig) {
			cfgMapName := names.TrustedCAConfigMapRef(proxyConfig.Spec.TrustedCA.Name)
			trustedCAData, err := r.validateTrustedCAConfigMap(cfgMapName)
			if err != nil {
				log.Printf("Failed to validate trustedCA for proxy '%s': %v", proxyConfig.Name, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyConfig",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, fmt.Errorf("failed to validate trustedCA for proxy '%s': %v",
					proxyConfig.Name, err)
			}
			mergedData, err = certutil.MergeCertificateData(systemData, trustedCAData)
			if err != nil {
				log.Printf("Failed to.... '%s' for proxy '%s': %v", proxyConfig.Spec.TrustedCA.Name, names.PROXY_CONFIG, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyTrustedCA",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, fmt.Errorf("failed to... '%s' for proxy '%s': %v", proxyConfig.Spec.TrustedCA.Name, names.PROXY_CONFIG, err)
			}
		}

		if isSpecReadinessEndpointsSet(proxyConfig) {
			if err := r.validateReadinessEndpoints(proxyConfig, mergedData); err != nil {
				log.Printf("Failed to validate readinessEndpoints for proxy '%s': %v", names.PROXY_CONFIG, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyReadinessEndpoints",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, fmt.Errorf("failed to validate readinessEndpoints for proxy '%s': %v",
					names.PROXY_CONFIG, err)
			}
		}

		trustedCACfgMap, err = generateTrustBundleConfigMap(mergedData)
		if err != nil {
			log.Printf("Failed to... '%s': %v", names.PROXY_CONFIG, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "EnsureProxyConfigFailure",
				fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
					"Use 'oc edit proxy.config.openshift.io %s' to fix.", names.PROXY_CONFIG, err, names.PROXY_CONFIG))
			return reconcile.Result{}, fmt.Errorf("failed to... '%s': %v", names.PROXY_CONFIG, err)
		}
		// Make sure the trust bundle configmap is in sync with the api server.
		if err := r.syncTrustedCABundle(trustedCACfgMap); err != nil {
			log.Printf("Failed to sync additional trust bundle configmap %s/%s: %v", trustedCACfgMap.Namespace,
				trustedCACfgMap.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "TrustBundleSyncFailure",
				fmt.Sprintf("Additional trust bundle configmap '%s/%s' not synced (%v)", trustedCACfgMap.Namespace,
					trustedCACfgMap.Name, err))
			return reconcile.Result{}, fmt.Errorf("failed to sync additional trust bundle configmap %s/%s: %v",
				trustedCACfgMap.Namespace, trustedCACfgMap.Name, err)
		}

		// Only proceed if the required config objects can be collected.
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: names.CLUSTER_CONFIG}, infraConfig); err != nil {
			log.Printf("Failed to get infrastructure config '%s': %v", names.CLUSTER_CONFIG, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "InfraConfigError",
				fmt.Sprintf("Error getting infrastructure config %s: %v", names.CLUSTER_CONFIG, err))
			return reconcile.Result{}, fmt.Errorf("failed to get infrastructure config '%s': %v", names.CLUSTER_CONFIG, err)
		}
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: names.CLUSTER_CONFIG}, netConfig); err != nil {
			log.Printf("Failed to get network config '%s': %v", names.CLUSTER_CONFIG, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "NetworkConfigError",
				fmt.Sprintf("Error getting network config '%s': %v.", names.CLUSTER_CONFIG, err))
			return reconcile.Result{}, fmt.Errorf("failed to get network config '%s': %v", names.CLUSTER_CONFIG, err)
		}
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: "cluster-config-v1", Namespace: "kube-system"},
			clusterConfig); err != nil {
			log.Printf("Failed to get configmap '%s/%s': %v", clusterConfig.Namespace, clusterConfig.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "ClusterConfigError",
				fmt.Sprintf("Error getting cluster config configmap '%s/%s': %v.", clusterConfig.Namespace,
					clusterConfig.Name, err))
			return reconcile.Result{}, fmt.Errorf("failed to get configmap '%s/%s': %v", clusterConfig.Namespace, clusterConfig.Name, err)
		}
		// Update proxy status.
		if err := r.syncProxyStatus(proxyConfig, infraConfig, netConfig, clusterConfig); err != nil {
			log.Printf("Could not sync proxy '%s' status: %v", proxyConfig.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "StatusError",
				fmt.Sprintf("Could not update proxy '%s' status: %v", proxyConfig.Name, err))
			return reconcile.Result{}, fmt.Errorf("failed to sync proxy '%s': %v", names.PROXY_CONFIG, err)
		}
		log.Printf("Reconciling proxy '%s' complete", request.Name)
	case request.Namespace == names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS:
		var addlBundle *corev1.ConfigMap
		log.Printf("Reconciling additional trust bundle configmap '%s/%s'", request.Namespace, request.Name)
		if err := r.client.Get(context.TODO(), request.NamespacedName, addlBundle); err != nil {
			if apierrors.IsNotFound(err) {
				// Request object not found, could have been deleted after reconcile request.
				// Return and don't requeue
				log.Println("configmap not found; reconciliation will be skipped", "request", request)
				return reconcile.Result{}, nil
			}
			// Error reading the object - requeue the request.
			return reconcile.Result{}, fmt.Errorf("failed to get configmap '%s': %v", request, err)
		}
		// Only proceed if request matches the configmap referenced by proxy trustedCA.
		if err := r.configMapIsProxyTrustedCA(addlBundle.Name); err != nil {
			log.Printf("configmap '%s/%s' name differs from trustedCA of proxy '%s' or trustedCA not set; "+
				"reconciliation will be skipped", addlBundle.Namespace, addlBundle.Name, names.PROXY_CONFIG)
			return reconcile.Result{}, nil
		}
		// Validate the trust bundle configmap.
		trustedCAData, err = certutil.GenerateCertificateDataFromConfigMap(addlBundle)
		if err != nil {
			log.Printf("Failed to generate certificate data from configmap '%s/%s': %v", addlBundle.Namespace,
				addlBundle.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "CertDataGenerationFailure",
				fmt.Sprintf("Failed to generate certificate data from configmap '%s/%s' (%v)",
					addlBundle.Namespace, addlBundle.Name, err))
			return reconcile.Result{}, fmt.Errorf("failed to generate certificate data from configmap '%s/%s': %v",
				addlBundle.Namespace, addlBundle.Name, err)
		}
		mergedData, err = certutil.MergeCertificateData(systemData, trustedCAData)
		if err != nil {
			log.Printf("Failed to.... '%s' for proxy '%s': %v", proxyConfig.Spec.TrustedCA.Name,
				names.PROXY_CONFIG, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyTrustedCA",
				fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
					"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
			return reconcile.Result{}, fmt.Errorf("failed to... '%s' for proxy '%s': %v",
				proxyConfig.Spec.TrustedCA.Name, names.PROXY_CONFIG, err)
		}
		if isSpecReadinessEndpointsSet(proxyConfig) {
			if err := r.validateReadinessEndpoints(proxyConfig, mergedData); err != nil {
				log.Printf("Failed to validate readinessEndpoints for proxy '%s': %v", names.PROXY_CONFIG, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyReadinessEndpoints",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, fmt.Errorf("failed to validate readinessEndpoints for proxy '%s': %v",
					names.PROXY_CONFIG, err)
			}
		}
		trustedCACfgMap, err = generateTrustBundleConfigMap(mergedData)
		if err != nil {
			log.Printf("Failed to... '%s': %v", names.PROXY_CONFIG, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "EnsureProxyConfigFailure",
				fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
					"Use 'oc edit proxy.config.openshift.io %s' to fix.", names.PROXY_CONFIG, err, names.PROXY_CONFIG))
			return reconcile.Result{}, fmt.Errorf("failed to... '%s': %v", names.PROXY_CONFIG, err)
		}
		// Make sure the trust bundle configmap is in sync with the api server.
		if err := r.syncTrustedCABundle(trustedCACfgMap); err != nil {
			log.Printf("Failed to sync additional trust bundle configmap %s/%s: %v", trustedCACfgMap.Namespace,
				trustedCACfgMap.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "TrustBundleSyncFailure",
				fmt.Sprintf("Additional trust bundle configmap '%s/%s' not synced (%v)", trustedCACfgMap.Namespace,
					trustedCACfgMap.Name, err))
			return reconcile.Result{}, fmt.Errorf("failed to sync additional trust bundle configmap %s/%s: %v",
				trustedCACfgMap.Namespace, trustedCACfgMap.Name, err)
		}
		log.Printf("Reconciling additional trust bundle configmap '%s/%s' complete",
			request.Namespace, request.Name)
	default:
		// unknown object
		log.Println("Ignoring unknown object, reconciliation will be skipped", "request", request)
		return reconcile.Result{}, nil
	}

	// Reconciliation completed, so set status manager accordingly.
	r.status.SetNotDegraded(statusmanager.ProxyConfig)

	return reconcile.Result{}, nil
}

// isSpecHTTPProxySet returns true if spec.httpProxy of
// proxyConfig is set.
func isSpecHTTPProxySet(proxyConfig *configv1.Proxy) bool {
	return len(proxyConfig.Spec.HTTPProxy) > 0
}

// isSpecHTTPSProxySet returns true if spec.httpsProxy of
// proxyConfig is set.
func isSpecHTTPSProxySet(proxyConfig *configv1.Proxy) bool {
	return len(proxyConfig.Spec.HTTPSProxy) > 0
}

// isSpecNoProxySet returns true if spec.NoProxy of proxyConfig is set.
func isSpecNoProxySet(proxyConfig *configv1.Proxy) bool {
	return len(proxyConfig.Spec.NoProxy) > 0
}

// isSpecReadinessEndpointsSet returns true if spec.readinessEndpoints of
// proxyConfig is set.
func isSpecReadinessEndpointsSet(proxyConfig *configv1.Proxy) bool {
	return len(proxyConfig.Spec.ReadinessEndpoints) > 0
}

// isSpecTrustedCASet returns true if spec.trustedCA of proxyConfig is set.
func isSpecTrustedCASet(proxyConfig *configv1.Proxy) bool {
	return len(proxyConfig.Spec.TrustedCA.Name) > 0
}

// generateTrustBundleConfigMap generates a ConfigMap object with name
// "trusted-ca-bundle", namespace "openshift-config-managed" and data
// key "ca-bundle.crt" containing bundleData. It's the caller's
// responsibility to create the ConfigMap in the api server.
func generateTrustBundleConfigMap(bundleData []byte) (*corev1.ConfigMap, error) {
	cfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.TRUSTED_CA_BUNDLE_CONFIGMAP,
			Namespace: names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS,
		},
		Data: map[string]string{
			names.TRUSTED_CA_BUNDLE_CONFIGMAP_KEY: string(bundleData),
		},
	}

	return cfgMap, nil
}

// syncTrustedCABundle checks if ConfigMap named "trusted-ca-bundle"
// in namespace "openshift-config-managed" exists, creating trustedCABundle
// if it doesn't exist or comparing the configmap data values and updating
// trustedCABundle if the values differ.
func (r *ReconcileProxyConfig) syncTrustedCABundle(trustBundleCfgMap *corev1.ConfigMap) error {
	currentCfgMap := &corev1.ConfigMap{}
	if err := r.client.Get(context.TODO(), names.TrustedCABundleConfigMap(), currentCfgMap); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get trusted CA bundle configmap '%s/%s': %v",
				trustBundleCfgMap.Namespace, trustBundleCfgMap.Name, err)
		}
		if err := r.client.Create(context.TODO(), trustBundleCfgMap); err != nil {
			return fmt.Errorf("failed to create trusted CA bundle configmap '%s/%s': %v",
				trustBundleCfgMap.Namespace, trustBundleCfgMap.Name, err)
		}
	}

	if !configMapsEqual(names.TRUSTED_CA_BUNDLE_CONFIGMAP_KEY, currentCfgMap, trustBundleCfgMap) {
		if err := r.client.Update(context.TODO(), trustBundleCfgMap); err != nil {
			return fmt.Errorf("failed to update trusted CA bundle configmap '%s/%s': %v",
				trustBundleCfgMap.Namespace, trustBundleCfgMap.Name, err)
		}
	}

	return nil
}

// configMapsEqual compares the data key values between
// a and b ConfigMaps, returning true if they are equal.
func configMapsEqual(key string, a, b *corev1.ConfigMap) bool {
	return a.Data[key] == b.Data[key]
}

// configMapIsProxyTrustedCA returns an error if cfgMapName does not match the
// ConfigMap name referenced by proxy "cluster" trustedCA.
func (r *ReconcileProxyConfig) configMapIsProxyTrustedCA(cfgMapName string) error {
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
