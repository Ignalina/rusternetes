// pbgen: write Kubernetes protobuf request bodies (what client-go sends with
// ContentType application/vnd.kubernetes.protobuf) and the JSON of the same
// objects, as fixtures for the Rusternetes protobuf decoder (R3).
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
)

func ptr[T any](v T) *T { return &v }

func main() {
	out := os.Args[1]
	t := metav1.NewTime(time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC))
	mt := metav1.NewMicroTime(time.Date(2026, 11, 4, 10, 0, 1, 123456000, time.UTC))
	meta := func(name, ns string) metav1.ObjectMeta {
		return metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID("8a1b2c3d-0000-4000-8000-000000000001"),
			ResourceVersion: "42", Generation: 3, CreationTimestamp: t,
			Labels:      map[string]string{"kubernetes.io/hostname": name, "k8s.ovn.org/zone-name": name},
			Annotations: map[string]string{"k8s.ovn.org/node-subnets": `{"default":["10.244.1.0/24"]}`, "k8s.ovn.org/node-chassis-id": "3f1a"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: "cp", UID: "u-1", Controller: ptr(true)}},
			Finalizers:      []string{"k8s.ovn.org/f"},
		}
	}
	node := &corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
		ObjectMeta: meta("worker", ""),
		Spec: corev1.NodeSpec{
			PodCIDR: "10.244.1.0/24", PodCIDRs: []string{"10.244.1.0/24", "fd00:10:244:1::/64"},
			ProviderID: "tunnr://worker", Unschedulable: true,
			Taints: []corev1.Taint{{Key: "k8s.ovn.org/network-unavailable", Value: "x", Effect: corev1.TaintEffectNoSchedule, TimeAdded: &t}},
		},
		Status: corev1.NodeStatus{
			Capacity:    corev1.ResourceList{"cpu": resource.MustParse("4"), "memory": resource.MustParse("3Gi"), "pods": resource.MustParse("110")},
			Allocatable: corev1.ResourceList{"cpu": resource.MustParse("3800m"), "memory": resource.MustParse("2900Mi")},
			Phase:       corev1.NodeRunning,
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastHeartbeatTime: t, LastTransitionTime: t, Reason: "KubeletReady", Message: "kubelet is posting ready status"},
				{Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionFalse, LastHeartbeatTime: t, LastTransitionTime: t, Reason: "RouteCreated", Message: "ovn"},
			},
			Addresses:       []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.2.15"}, {Type: corev1.NodeHostName, Address: "worker"}},
			DaemonEndpoints: corev1.NodeDaemonEndpoints{KubeletEndpoint: corev1.DaemonEndpoint{Port: 10250}},
			NodeInfo: corev1.NodeSystemInfo{MachineID: "m", SystemUUID: "s", BootID: "b", KernelVersion: "6.12", OSImage: "tunnr", ContainerRuntimeVersion: "youki://0.7.0",
				KubeletVersion: "v1.35.0", KubeProxyVersion: "", OperatingSystem: "linux", Architecture: "amd64", Swap: &corev1.NodeSwapStatus{Capacity: ptr(int64(0))}},
			Images:          []corev1.ContainerImage{{Names: []string{"ghcr.io/ovn-kubernetes/ovn-kubernetes/ovn-kube-ubuntu:release-1.4"}, SizeBytes: 982000000}},
			VolumesInUse:    []corev1.UniqueVolumeName{"kubernetes.io/csi/x"},
			VolumesAttached: []corev1.AttachedVolume{{Name: "kubernetes.io/csi/x", DevicePath: "/dev/vdb"}},
			RuntimeHandlers: []corev1.NodeRuntimeHandler{{Name: "heimdall", Features: &corev1.NodeRuntimeHandlerFeatures{RecursiveReadOnlyMounts: ptr(true), UserNamespaces: ptr(false)}}},
			Features:        &corev1.NodeFeatures{SupplementalGroupsPolicy: ptr(true)},
		},
	}
	ev := &corev1.Event{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Event"},
		ObjectMeta: metav1.ObjectMeta{Name: "worker.18a2b", Namespace: "default"},
		InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: "worker", UID: "u-2", APIVersion: "v1", ResourceVersion: "41", FieldPath: "spec"},
		Reason: "ErrorReconcilingNode", Message: "error creating gateway", Source: corev1.EventSource{Component: "ovnkube-controller", Host: "worker"},
		FirstTimestamp: t, LastTimestamp: t, Count: 2, Type: "Warning", EventTime: mt,
		Series: &corev1.EventSeries{Count: 2, LastObservedTime: mt}, Action: "Reconcile",
		Related: &corev1.ObjectReference{Kind: "Pod", Namespace: "ovn-kubernetes", Name: "ovnkube-node-x"},
		ReportingController: "ovnkube", ReportingInstance: "worker",
	}
	ev2 := &eventsv1.Event{
		TypeMeta:   metav1.TypeMeta{APIVersion: "events.k8s.io/v1", Kind: "Event"},
		ObjectMeta: metav1.ObjectMeta{Name: "worker.18a2c", Namespace: "default"},
		EventTime:  mt, Series: &eventsv1.EventSeries{Count: 3, LastObservedTime: mt},
		ReportingController: "ovnkube", ReportingInstance: "worker", Action: "Reconcile", Reason: "Started",
		Regarding: corev1.ObjectReference{Kind: "Node", Name: "worker"}, Related: &corev1.ObjectReference{Kind: "Pod", Name: "p"},
		Note: "started", Type: "Normal", DeprecatedSource: corev1.EventSource{Component: "c", Host: "h"},
		DeprecatedFirstTimestamp: t, DeprecatedLastTimestamp: t, DeprecatedCount: 1,
	}
	lease := &coordv1.Lease{
		TypeMeta:   metav1.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"},
		ObjectMeta: metav1.ObjectMeta{Name: "ovn-kubernetes-master", Namespace: "ovn-kubernetes"},
		Spec: coordv1.LeaseSpec{HolderIdentity: ptr("cp"), LeaseDurationSeconds: ptr(int32(137)), AcquireTime: &mt, RenewTime: &mt, LeaseTransitions: ptr(int32(1))},
	}
	pb := protobuf.NewSerializer(scheme.Scheme, scheme.Scheme)
	for name, obj := range map[string]runtime.Object{"node": node, "event-core": ev, "event-events": ev2, "lease": lease} {
		var b bytes.Buffer
		if err := pb.Encode(obj, &b); err != nil {
			panic(err)
		}
		j, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			panic(err)
		}
		_ = os.WriteFile(filepath.Join(out, name+".pb"), b.Bytes(), 0o644)
		_ = os.WriteFile(filepath.Join(out, name+".json"), append(j, '\n'), 0o644)
	}
}
