package proxyconfig

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/openshift/cluster-ingress-operator/pkg/manifests"

	configv1 "github.com/openshift/api/config/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilclock "k8s.io/apimachinery/pkg/util/clock"
)

const (
	defaultProxyName    = "cluster"
	testAPIServerURL    = "https://api-int.test.example.com:6443"
	testAPIServerIntURL = "https://api.test.example.com:6443"
)

func proxy(http, https, no string) *configv1.Proxy {
	return &configv1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultProxyName,
		},
		Spec: configv1.ProxySpec{
			HTTPProxy: http,
			HTTPSProxy: https,
			NoProxy: no,
		},
	}
}

func proxyStatus(http, https, no string) *configv1.ProxyStatus {
	return &configv1.ProxyStatus{
		HTTPProxy: http,
		HTTPSProxy: https,
		NoProxy: no,
	}
}

func cluster() *corev1.ConfigMap {
	clusterData := map[string]string{"install-config": "controlPlane:\n  replicas: 3\nnetworking:\n  machineCIDR: 10.0.0.0/16\n"}

	return &corev1.ConfigMap {
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-config-v1",
			Namespace: "kube-system",
		},
		Data: clusterData,
	}
}

func infraStatus() *configv1.InfrastructureStatus {
	return &configv1.InfrastructureStatus{
		InfrastructureName: "aws",
		PlatformStatus: &configv1.PlatformStatus{
			Type: configv1.AWSPlatformType,
		},
		APIServerInternalURL: testAPIServerIntURL,
		APIServerURL: testAPIServerURL,
	}
}

func network() *configv1.Network {
	return &configv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.NetworkStatus{
			ClusterNetwork: []configv1.ClusterNetworkEntry{{CIDR: "172.30.0.0/16", HostPrefix: uint32(23)}},
			ServiceNetwork: []string{"172.30.0.0/16"},
		},
	}
}

func TestMergeUserSystemNoProxy(t *testing.T) {
	tests := []struct {
		name   string
		proxy  *configv1.Proxy
		expect *configv1.ProxyStatus
	}{
		{
			name:  "empty proxy",
			proxy: proxy("","",""),
			expect: proxyStatus("","",""),
		},
	}

	for _, test := range tests {
		t.Logf("evaluating test %s", test.name)

		r := &ReconcileProxyConfig{client: mgr.GetClient(), scheme: mgr.GetScheme(), status: status}

		actual := computeLoadBalancerStatus(test.controller, test.service, test.events)

		conditionsCmpOpts := []cmp.Option{
			cmpopts.IgnoreFields(operatorv1.OperatorCondition{}, "LastTransitionTime", "Message"),
			cmpopts.EquateEmpty(),
			cmpopts.SortSlices(func(a, b operatorv1.OperatorCondition) bool { return a.Type < b.Type }),
		}
		if !cmp.Equal(actual, test.expect, conditionsCmpOpts...) {
			t.Fatalf("expected:\n%#v\ngot:\n%#v", test.expect, actual)
		}
	}
}

func TestIngressStatusesEqual(t *testing.T) {
	testCases := []struct {
		description string
		expected    bool
		a, b        operatorv1.IngressControllerStatus
	}{
		{
			description: "nil and non-nil slices are equal",
			expected:    true,
			a: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{},
			},
		},
		{
			description: "empty slices should be equal",
			expected:    true,
			a: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{},
			},
			b: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{},
			},
		},
		{
			description: "condition LastTransitionTime should not be ignored",
			expected:    false,
			a: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:               operatorv1.IngressControllerAvailableConditionType,
						Status:             operatorv1.ConditionTrue,
						LastTransitionTime: metav1.Unix(0, 0),
					},
				},
			},
			b: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:               operatorv1.IngressControllerAvailableConditionType,
						Status:             operatorv1.ConditionTrue,
						LastTransitionTime: metav1.Unix(1, 0),
					},
				},
			},
		},
		{
			description: "check condition reason differs",
			expected:    false,
			a: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:   operatorv1.IngressControllerAvailableConditionType,
						Status: operatorv1.ConditionFalse,
						Reason: "foo",
					},
				},
			},
			b: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:   operatorv1.IngressControllerAvailableConditionType,
						Status: operatorv1.ConditionFalse,
						Reason: "bar",
					},
				},
			},
		},
		{
			description: "condition status differs",
			expected:    false,
			a: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:   operatorv1.IngressControllerAvailableConditionType,
						Status: operatorv1.ConditionTrue,
					},
				},
			},
			b: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:   operatorv1.IngressControllerAvailableConditionType,
						Status: operatorv1.ConditionFalse,
					},
				},
			},
		},
		{
			description: "check duplicate with single condition",
			expected:    false,
			a: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:    operatorv1.IngressControllerAvailableConditionType,
						Message: "foo",
					},
				},
			},
			b: operatorv1.IngressControllerStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:    operatorv1.IngressControllerAvailableConditionType,
						Message: "foo",
					},
					{
						Type:    operatorv1.IngressControllerAvailableConditionType,
						Message: "foo",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		if actual := ingressStatusesEqual(tc.a, tc.b); actual != tc.expected {
			t.Fatalf("%q: expected %v, got %v", tc.description, tc.expected, actual)
		}
	}
}

func TestMergeConditions(t *testing.T) {
	// Inject a fake clock and don't forget to reset it
	fakeClock := utilclock.NewFakeClock(time.Time{})
	clock = fakeClock
	defer func() {
		clock = utilclock.RealClock{}
	}()

	start := fakeClock.Now()
	middle := start.Add(1 * time.Minute)
	later := start.Add(2 * time.Minute)

	tests := map[string]struct {
		conditions []operatorv1.OperatorCondition
		updates    []operatorv1.OperatorCondition
		expected   []operatorv1.OperatorCondition
	}{
		"updates": {
			conditions: []operatorv1.OperatorCondition{
				cond("A", "False", "Reason", start),
				cond("B", "True", "Reason", start),
				cond("Ignored", "True", "Reason", start),
			},
			updates: []operatorv1.OperatorCondition{
				cond("A", "True", "Reason", middle),
				cond("B", "True", "Reason", middle),
				cond("C", "False", "Reason", middle),
			},
			expected: []operatorv1.OperatorCondition{
				cond("A", "True", "Reason", later),
				cond("B", "True", "Reason", start),
				cond("C", "False", "Reason", later),
				cond("Ignored", "True", "Reason", start),
			},
		},
	}

	// Simulate the passage of time between original condition creation
	// and update processing
	fakeClock.SetTime(later)

	for name, test := range tests {
		t.Logf("test: %s", name)
		actual := mergeConditions(test.conditions, test.updates...)
		if !conditionsEqual(test.expected, actual) {
			t.Errorf("expected:\n%v\nactual:\n%v", toYaml(test.expected), toYaml(actual))
		}
	}
}
