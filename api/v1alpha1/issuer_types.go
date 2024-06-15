/*
Copyright 2023 will@byted.sh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="NotBefore",type="date",JSONPath=".status.notBefore"
// +kubebuilder:printcolumn:name="NotAfter",type="date",JSONPath=".status.notAfter"
//+kubebuilder:printcolumn:name="SecretName",type="string",JSONPath=".status.secretName"
//+kubebuilder:printcolumn:name="SecretNamespace",type="string",JSONPath=".status.secretNamespace"

// SpireIssuer is the Schema for the issuers API
type SpireIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SpireIssuerSpec   `json:"spec,omitempty"`
	Status SpireIssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SpireIssuerList contains a list of SpireIssuer
type SpireIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SpireIssuer `json:"items"`
}

// SpireIssuerSpec defines the desired state of SpireIssuer
type SpireIssuerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	TrustDomain   string `json:"trustDomain"`  // trustdomain of the issuer,should be same with spire agent and spire server configuration
	AgentSocket   string `json:"agentSocket"`  // spire agent's unix domain socket path
	ServerAddress string `json:"spireAddress"` // spire server listen address, looks like: “address:port”
	Config        Config `json:"config"`
}

type Config struct {
	TTL int64  `json:"ttl"` // hours
	C   string `json:"c,omitempty"`
	L   string `json:"l,omitempty"`
	ST  string `json:"st,omitempty"`
	O   string `json:"o,omitempty"`
	OU  string `json:"ou,omitempty"`
	CN  string `json:"cn,omitempty"`

	Hosts []string `json:"hosts,omitempty"` // URI, DNS, IPs

	Ratio string `json:"ratio,omitempty"` // TODO
}

type WorkMode string

const (
	Downstream WorkMode = "downstream" // spire server downstream ca
	Mint       WorkMode = "mint"       // connect back to spire server to mint svid, not supported now
)

// SpireIssuerStatus defines the observed state of SpireIssuer
type SpireIssuerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Phase           Phase              `json:"phase,omitempty"`
	NotBefore       metav1.Time        `json:"notBefore,omitempty"`
	NotAfter        metav1.Time        `json:"notAfter,omitempty"`
	SecretName      string             `json:"secretName,omitempty"`
	SecretNamespace string             `json:"secretNamespace,omitempty"`
	Conditions      []metav1.Condition `json:"conditions,omitempty"`
}

type Phase string

const (
	Processing  Phase = "Processing"
	Ready       Phase = "Ready"
	Terminating Phase = "Terminating"
)

func init() {
	SchemeBuilder.Register(&SpireIssuer{}, &SpireIssuerList{})
}
