package proxyconfig

import (
	"context"
	"fmt"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-network-operator/pkg/controller/statusmanager"
	"github.com/openshift/cluster-network-operator/pkg/names"
	"log"

	corev1 "k8s.io/api/core/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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
	if err:= configv1.Install(mgr.GetScheme()); err != nil {
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

	// Watch for changes to primary resource config.openshift.io/v1/Proxy
	err = c.Watch(&source.Kind{Type: &configv1.Proxy{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileProxyConfig{}

// ReconcileProxyConfig reconciles a Proxy object
type ReconcileProxyConfig struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client client.Client
	scheme *runtime.Scheme
	status *statusmanager.StatusManager
}

// Reconcile expects request to refer to a proxy object named "cluster" in the
// default namespace, and will ensure proxy is in the desired state.
func (r *ReconcileProxyConfig) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	log.Printf("Reconciling Proxy.config.openshift.io %s\n", request.Name)

	// Only reconcile the "cluster" proxy.
	if request.Name != names.PROXY_CONFIG {
		log.Printf("Ignoring Proxy without default name " + names.PROXY_CONFIG)
		return reconcile.Result{}, nil
	}

	// Fetch the proxy config
	proxyConfig := &configv1.Proxy{}
	err := r.client.Get(context.TODO(), request.NamespacedName, proxyConfig)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			log.Println("proxy not found; reconciliation will be skipped", "request", request)
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, fmt.Errorf("failed to get proxy %q: %v", request, err)
	}

	// A nil proxy is generated by upgrades and installs not requiring a proxy.
	if isSpecHTTPAndHTTPSProxySet(&proxyConfig.Spec) {
		log.Println("httpProxy or httpsProxy not defined; reconciliation will be skipped", "request", request)
		return reconcile.Result{}, nil
	}

	// Only proceed if the required config objects can be collected.
	infraConfig := &configv1.Infrastructure{}
	if err := r.client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, infraConfig); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get infrastructure config 'cluster': %v", err)
	}
	netConfig := &configv1.Network{}
	if err := r.client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, netConfig); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get network config 'cluster': %v", err)
	}
	clusterConfig := &corev1.ConfigMap{}
	if err := r.client.Get(context.TODO(), types.NamespacedName{Name: "cluster-config-v1"}, clusterConfig); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get network config 'cluster': %v", err)
	}

	if err := r.ValidateProxyConfig(&proxyConfig.Spec); err != nil {
		log.Printf("Failed to validate Proxy.Spec: %v", err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "InvalidProxyConfig",
			fmt.Sprintf("The proxy configuration is invalid (%v). Use 'oc edit proxy.config.openshift.io cluster' to fix.", err))
		return reconcile.Result{}, err
	}

	/*if err := r.syncProxyStatus(proxyConfig, infraConfig, netConfig, clusterConfig); err != nil {
		log.Printf("Failed to enforce NoProxy default values: %v", err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "DefaultNoProxyFailedEnforcement",
			fmt.Sprintf("Failed to enforce system default NoProxy values: %v", err))
		return reconcile.Result{}, err
	}*/

	r.status.SetNotDegraded(statusmanager.ProxyConfig)
	return reconcile.Result{}, nil
}

// isSpecHTTPAndHTTPSProxySet checks whether spec.httpProxy and spec.httpsProxy
// of proxy is set.
func isSpecHTTPAndHTTPSProxySet(proxyConfig *configv1.ProxySpec) bool {
	return !isSpecHTTPProxySet(proxyConfig) && !isSpecHTTPSProxySet(proxyConfig)
}

// isSpecHTTPProxySet checks whether spec.httpProxy of proxy is set.
func isSpecHTTPProxySet(proxyConfig *configv1.ProxySpec) bool {
	if len(proxyConfig.HTTPProxy) == 0 {
		return false
	}

	return true
}

// isSpecHTTPSProxySet checks whether spec.httpsProxy of proxy is set.
func isSpecHTTPSProxySet(proxyConfig *configv1.ProxySpec) bool {
	if len(proxyConfig.HTTPSProxy) == 0 {
		return false
	}

	return true
}

// isSpecNoProxySet checks whether spec.NoProxy of proxy is set.
func isSpecNoProxySet(proxyConfig *configv1.ProxySpec) bool {
	if len(proxyConfig.NoProxy) == 0 {
		return false
	}

	return true
}

// isSpecTrustedCASet checks whether spec.trustedCA of proxy is set.
func isSpecTrustedCASet(proxyConfig *configv1.ProxySpec) bool {
	if len(proxyConfig.TrustedCA.Name) == 0 {
		return false
	}

	return true
}

// isExpectedProxyConfigMap checks whether the ConfigMap name in
// spec.trustedCA is "proxy-ca-bundle".
func isExpectedProxyConfigMap(proxyConfig *configv1.ProxySpec) bool {
	if proxyConfig.TrustedCA.Name != names.PROXY_TRUSTED_CA_CONFIGMAP {
		return false
	}

	return true
}

// isSpecReadinessEndpoints checks whether spec.readinessEndpoints of
// proxy is set.
func isSpecReadinessEndpoints(proxyConfig *configv1.ProxySpec) bool {
	if len(proxyConfig.ReadinessEndpoints) == 0 {
		return false
	}

	return true
}