/*


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
	"github.com/containers/common/pkg/seccomp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SeccompProfileSpec defines the desired state of SeccompProfile
type SeccompProfileSpec struct {
	seccomp.Seccomp
	// TODO: seccomp.Seccomp doesn't support flags from runtime spec
	// TODO: seccomp.Seccomp.Syscalls doesn't support errnoRet from runtime spec
}

// SeccompProfileStatus defines the observed state of SeccompProfile
type SeccompProfileStatus struct {
	// TODO: record some state?
}

// SeccompProfile is the Schema for the seccompprofiles API
type SeccompProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SeccompProfileSpec   `json:"spec,omitempty"`
	Status SeccompProfileStatus `json:"status,omitempty"`
}

// SeccompProfileList contains a list of SeccompProfile
type SeccompProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SeccompProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SeccompProfile{}, &SeccompProfileList{})
}
