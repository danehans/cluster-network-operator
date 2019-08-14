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

	// Watch for changes to the proxy resource.
	err = c.Watch(&source.Kind{Type: &configv1.Proxy{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
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
// named "cluster" and will ensure either object is in the desired state.
func (r *ReconcileProxyConfig) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	validate := true
	proxyConfig := &configv1.Proxy{}
	infraConfig := &configv1.Infrastructure{}
	netConfig := &configv1.Network{}
	clusterConfig := &corev1.ConfigMap{}

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

	if isSpecTrustedCASet(&proxyConfig.Spec) {
		// Validate trustedCA of proxy spec.
		if err := r.validateTrustedCA(proxyConfig.Spec.TrustedCA.Name); err != nil {
			log.Printf("Failed to validate trustedCA for proxy '%s': %v", proxyConfig.Name, err)
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
		clusterConfig); err != nil {
		log.Printf("failed to get configmap '%s/%s': %v", clusterConfig.Namespace, clusterConfig.Name, err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "ClusterConfigError",
			fmt.Sprintf("Error getting cluster config configmap '%s/%s': %v.", clusterConfig.Namespace,
				clusterConfig.Name, err))
		return reconcile.Result{}, nil
	}
	// Update proxy status.
	if err := r.syncProxyStatus(proxyConfig, infraConfig, netConfig, clusterConfig); err != nil {
		log.Printf("Could not sync proxy '%s' status: %v", proxyConfig.Name, err)
		r.status.SetDegraded(statusmanager.ProxyConfig, "StatusError",
			fmt.Sprintf("Could not update proxy '%s' status: %v", proxyConfig.Name, err))
		return reconcile.Result{}, nil
	}
	log.Printf("Reconciling proxy '%s' complete", request.Name)

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
