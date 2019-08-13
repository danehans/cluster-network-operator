package proxyconfig

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

	// Watch for changes to the trust bundle configmap.
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

// handleConfigMap returns true if meta namespace is "openshift-config"
// or if meta name is "trusted-ca-bundle" in namespace
// "openshift-config-managed".
func handleConfigMap(meta metav1.Object) bool {
	return meta.GetNamespace() == names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS
}

/*func handleConfigMap(meta metav1.Object) bool {
	return meta.GetNamespace() == names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS ||
		(meta.GetNamespace() == names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS &&
			meta.GetName() == names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME)
}*/

// ReconcileProxyConfig reconciles a Proxy object
type ReconcileProxyConfig struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client client.Client
	scheme *runtime.Scheme
	status *statusmanager.StatusManager
}

// Reconcile expects request to refer to a proxy object named "cluster"
// in the default namespace or a configmap object named "user-ca-bundle"
// in namespace "openshift-config-managed", and will ensure either
// object is in the desired state.
func (r *ReconcileProxyConfig) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	validate := true
	trustBundle := &corev1.ConfigMap{}
	switch {
	case request.NamespacedName == names.Proxy():
		// Collect required config objects for proxy reconciliation.
		proxyConfig := &configv1.Proxy{}
		infraConfig := &configv1.Infrastructure{}
		netConfig := &configv1.Network{}
		clusterCfgMap := &corev1.ConfigMap{}
		log.Printf("Reconciling proxy '%s'", request.Name)
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

		// A nil proxy is generated by upgrades and installs not requiring a proxy.
		if !isSpecHTTPProxySet(&proxyConfig.Spec) &&
			!isSpecHTTPSProxySet(&proxyConfig.Spec) &&
			!isSpecNoProxySet(&proxyConfig.Spec) {
			log.Printf("httpProxy, httpsProxy and noProxy not defined for proxy '%s'; validation will be skipped",
				request.Name)
			validate = false
		}

		if validate {
			if err := r.ValidateProxyConfig(&proxyConfig.Spec); err != nil {
				log.Printf("Failed to validate proxy '%s': %v", proxyConfig.Name, err)
				r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyConfig",
					fmt.Sprintf("The configuration is invalid for proxy '%s' (%v). "+
						"Use 'oc edit proxy.config.openshift.io %s' to fix.", proxyConfig.Name, err, proxyConfig.Name))
				return reconcile.Result{}, nil
			}
		}

		// Only proceed if the required config objects can be collected.
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: names.PROXY_CONFIG}, infraConfig); err != nil {
			log.Printf("failed to get infrastructure config '%s': %v", names.PROXY_CONFIG, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "InfraConfigError",
				fmt.Sprintf("Error getting infrastructure config %s: %v.", names.PROXY_CONFIG, err))
			return reconcile.Result{}, nil
		}
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: names.CLUSTER_CONFIG}, netConfig); err != nil {
			log.Printf("failed to get network config '%s': %v", names.CLUSTER_CONFIG, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "NetworkConfigError",
				fmt.Sprintf("Error getting network config '%s': %v.", names.CLUSTER_CONFIG, err))
			return reconcile.Result{}, nil
		}
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: "cluster-config-v1", Namespace: "kube-system"},
			clusterCfgMap); err != nil {
			log.Printf("failed to get configmap '%s/%s': %v", clusterCfgMap.Namespace, clusterCfgMap.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "ClusterConfigError",
				fmt.Sprintf("Error getting cluster config configmap '%s/%s': %v.", clusterCfgMap.Namespace,
					clusterCfgMap.Name, err))
			return reconcile.Result{}, nil
		}
		// Update proxy status.
		if err := r.syncProxyStatus(proxyConfig, infraConfig, netConfig, clusterCfgMap); err != nil {
			log.Printf("Could not sync proxy '%s' status: %v", proxyConfig.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "StatusError",
				fmt.Sprintf("Could not update proxy '%s' status: %v", proxyConfig.Name, err))
			return reconcile.Result{}, err
		}
		log.Printf("Reconciling proxy '%s' complete", request.Name)
	case request.Namespace == names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS:
		log.Printf("Reconciling configmap '%s/%s'", request.Namespace, request.Name)

		if err := r.client.Get(context.TODO(), request.NamespacedName, trustBundle); err != nil {
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
		if err := r.configMapIsProxyTrustedCA(trustBundle.Name); err != nil {
			log.Printf("configmap '%s/%s' name differs from trustedCA of proxy '%s' or trustedCA not set; "+
				"reconciliation will be skipped", trustBundle.Namespace, trustBundle.Name, names.PROXY_CONFIG)
			return reconcile.Result{}, nil
		}

		if _, _, err := r.validateTrustBundle(trustBundle); err != nil {
			log.Printf("Failed to validate trust bundle for configmap '%s/%s': %v", trustBundle.Namespace,
				trustBundle.Name, err)
			r.status.SetDegraded(statusmanager.ProxyConfig, "TrustedCAConfigMapFailure",
				fmt.Sprintf("Failed to validate trust bundle configmap '%s/%s' (%v)", trustBundle.Namespace,
					trustBundle.Name, err))
			return reconcile.Result{}, err
		}

		log.Printf("Reconciling configmap '%s/%s' complete", request.Namespace, request.Name)
	/*case request.Namespace == names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS:
	log.Printf("Reconciling configmap '%s/%s'", request.Namespace, request.Name)

	if err := r.client.Get(context.TODO(), request.NamespacedName, trustBundle); err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			log.Println("configmap not found; reconciliation will be skipped", "request", request)
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, fmt.Errorf("failed to get configmap '%s': %v", request, err)
	}

	if _, _, err := r.validateTrustBundle(trustBundle); err != nil {
		log.Printf("Failed to validate trust bundle for configmap '%s/%s': %v", trustBundle.Namespace,
			trustBundle.Name, err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "TrustedCAConfigMapFailure",
			fmt.Sprintf("Failed to validate trust bundle configmap '%s/%s' (%v)", trustBundle.Namespace,
				trustBundle.Name, err))
		return reconcile.Result{}, err
	}

	log.Printf("Reconciling configmap '%s/%s' complete", request.Namespace, request.Name)*/
	default:
		// unknown object
		log.Println("Ignoring unknown object, reconciliation will be skipped", "request", request)
		return reconcile.Result{}, nil
	}

	trustBundleCfgMap, err := r.ensureTrustedCABundleConfigMap()
	if err != nil {
		log.Printf("Failed to ensure trusted ca bundle configmap '%s/%s': %v",
			trustBundleCfgMap.Namespace, trustBundleCfgMap.Name, err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "EnsureTrustedCAConfigMapFailure",
			fmt.Sprintf("Failed to ensure trusted ca bundle configmap '%s/%s' (%v). "+
				"Use 'oc edit proxy.config.openshift.io cluster' to fix.", trustBundleCfgMap.Namespace, trustBundleCfgMap.Name, err))
		return reconcile.Result{}, nil
	}

	if err := r.syncTrustedCABundleConfigMap(trustBundleCfgMap); err != nil {
		log.Printf("Failed to sync trusted ca bundle configmap '%s/%s': %v",
			trustBundleCfgMap.Namespace, trustBundleCfgMap.Name, err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "TrustedCAConfigMapSyncFailure",
			fmt.Sprintf("Failed to sync trusted ca bundle configmap '%s/%s' (%v). "+
				"Use 'oc edit proxy.config.openshift.io cluster' to fix.", trustBundleCfgMap.Namespace, trustBundleCfgMap.Name, err))
		return reconcile.Result{}, nil
	}

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

// syncTrustedCABundleConfigMap checks if trustedCABundle exists. It creates
// trustedCABundle if it doesn't exist or comparing the configmap data values
// and updates trustedCABundle if the values differ.
func (r *ReconcileProxyConfig) syncTrustedCABundleConfigMap(trustedCABundle *corev1.ConfigMap) error {
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

	if !configMapsEqual(currentCfgMap, trustedCABundle) {
		if err := r.client.Update(context.TODO(), trustedCABundle); err != nil {
			return fmt.Errorf("failed to update trusted CA bundle configmap '%s/%s': %v",
				trustedCABundle.Namespace, trustedCABundle.Name, err)
		}
	}

	return nil
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

// ensureTrustedCABundleConfigMap merges the system trust bundle with the
// proxyConfig trustedCA trust bundle (if specified), returning the configmap.
func (r *ReconcileProxyConfig) ensureTrustedCABundleConfigMap() (*corev1.ConfigMap, error) {
	/*systemData, err := r.validateSystemTrustBundle(names.SYSTEM_TRUST_BUNDLE)
	if err != nil {
		return nil, fmt.Errorf("failed to validate system trust bundle %s: %v", names.SYSTEM_TRUST_BUNDLE, err)
	}*/

	proxyConfig := &configv1.Proxy{}
	if err := r.client.Get(context.TODO(), names.Proxy(), proxyConfig); err != nil {
		return nil, fmt.Errorf("failed to get proxy '%s': %v", names.PROXY_CONFIG, err)
	}

	combinedTrustData := []byte{}
	if len(proxyConfig.Spec.TrustedCA.Name) > 0 {
		addlCfgMap := &corev1.ConfigMap{}
		if err := r.client.Get(context.TODO(), types.NamespacedName{Namespace: names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS, Name: proxyConfig.Spec.TrustedCA.Name}, addlCfgMap); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("failed to get additional trust bundle configmap '%s/%s': %v", addlCfgMap.Namespace, addlCfgMap.Name, err)
			}
			certString, ok := addlCfgMap.Data[names.TRUST_BUNDLE_CONFIGMAP_KEY]
			if !ok {
				return nil, fmt.Errorf("trust bundle configmap '%s/%s' missing data key '%s'", names.TRUST_BUNDLE_CONFIGMAP_KEY)
			}
			if len(certString) == 0 {
				return nil, fmt.Errorf("trust bundle configmap '%s/%s' key '%s' is empty", names.TRUST_BUNDLE_CONFIGMAP_KEY)
			}
			addlTrustData := []byte(certString)
			for _, d := range addlTrustData {
				combinedTrustData = append(combinedTrustData, d)
			}
		}
	}
	/*if len(systemData) > 0 {
		for _, d := range systemData {
			combinedTrustData = append(combinedTrustData, d)
		}
	}*/

	trustedCACfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME,
			Namespace: names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS,
		},
		Data: map[string]string{names.TRUST_BUNDLE_CONFIGMAP_KEY: string(combinedTrustData)},
	}

	/*if _, _, err := r.validateTrustBundle(trustedCACfgMap); err != nil {
		return nil, fmt.Errorf("failed to validate configmap '%s/%s': %v", trustedCACfgMap.Namespace,
			trustedCACfgMap.Name, err)
	}*/

	return trustedCACfgMap, nil
}

// ensureTrustedCABundleConfigMap merges the additionalData with systemData
// into a single byte slice, ensures the merged byte slice contains valid
// PEM encoded certificates, embeds the merged byte slice into a ConfigMap
// named "trusted-ca-bundle" in namespace "openshift-config-managed" and
// returns the configmap.
/*func (r *ReconcileProxyConfig) ensureTrustedCABundleConfigMap() (*corev1.ConfigMap, error) {
	systemData, err := r.validateSystemTrustBundle(names.SYSTEM_TRUST_BUNDLE)
	if err != nil {
		return nil, fmt.Errorf("failed to validate system trust bundle %s: %v", names.SYSTEM_TRUST_BUNDLE, err)
	}

	proxyConfig := &configv1.Proxy{}
	if err := r.client.Get(context.TODO(), names.Proxy(), proxyConfig); err != nil {
		return nil, fmt.Errorf("failed to get proxy '%s': %v", names.PROXY_CONFIG, err)
	}

	combinedTrustData := []byte{}
	if len(proxyConfig.Spec.TrustedCA.Name) > 0 {
		addlCfgMap := &corev1.ConfigMap{}
		if err := r.client.Get(context.TODO(), types.NamespacedName{Namespace: names.ADDL_TRUST_BUNDLE_CONFIGMAP_NS, Name: proxyConfig.Spec.TrustedCA.Name}, addlCfgMap); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("failed to get additional trust bundle configmap '%s/%s': %v", addlCfgMap.Namespace, addlCfgMap.Name, err)
			}
			if certString, ok := addlCfgMap.Data[names.TRUST_BUNDLE_CONFIGMAP_KEY]; ok {
				if len(certString) > 0 {
					addlTrustData := []byte(certString)
					for _, d := range addlTrustData {
						combinedTrustData = append(combinedTrustData, d)
						}
				}
			}
		}
	}

	if len(systemData) > 0 {
		for _, d := range systemData {
			combinedTrustData = append(combinedTrustData, d)
		}
	}

	trustBundleCfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.TRUSTED_CA_BUNDLE_CONFIGMAP_NAME,
			Namespace: names.TRUSTED_CA_BUNDLE_CONFIGMAP_NS,
		},
		Data: map[string]string{names.TRUST_BUNDLE_CONFIGMAP_KEY: string(combinedTrustData)},
	}
	if _, _, err := r.validateTrustBundle(trustBundleCfgMap); err != nil {
		return nil, fmt.Errorf("failed to validate merged configmap '%s/%s': %v", trustBundleCfgMap.Namespace,
			trustBundleCfgMap.Name, err)
	}

	return trustBundleCfgMap, nil
}*/

// configMapsEqual compares the values of data key "ca-bundle.crt"
// between a and b, returning true if they are equal.
func configMapsEqual(a, b *corev1.ConfigMap) bool {
	return a.Data[names.TRUST_BUNDLE_CONFIGMAP_KEY] == b.Data[names.TRUST_BUNDLE_CONFIGMAP_KEY]
}
