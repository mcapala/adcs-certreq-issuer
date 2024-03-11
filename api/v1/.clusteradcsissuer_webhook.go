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

package v1

import (
	"regexp"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	//validationutils "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type Warnings []string

// log is for logging in this package.
var clusteradcsissuerlog = logf.Log.WithName("clusteradcsissuer-resource")

func (r *ClusterAdcsIssuer) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-batch-certmanager-csf-nokia-com-v1-clusteradcsissuer,mutating=true,failurePolicy=fail,groups=batch.certmanager.csf.nokia.com,resources=clusteradcsissuers,verbs=create;update,versions=v1,name=mclusteradcsissuer.kb.io,sideEffects=None,admissionReviewVersions=v1

var _ webhook.Defaulter = &ClusterAdcsIssuer{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) Default() {
	clusteradcsissuerlog.Info("default", "name", r.Name)

	if r.Spec.StatusCheckInterval == "" {
		r.Spec.StatusCheckInterval = "6h"
	}
	if r.Spec.RetryInterval == "" {
		r.Spec.RetryInterval = "1h"
	}
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// +kubebuilder:webhook:verbs=create;update,path=/validate-batch-certmanager-csf-nokia-com-v1-clusteradcsissuer,mutating=false,failurePolicy=fail,groups=batch.certmanager.csf.nokia.com,resources=clusteradcsissuers,versions=v1,name=vclusteradcsissuer.kb.io,sideEffects=None,admissionReviewVersions=v1

var _ webhook.Validator = &ClusterAdcsIssuer{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) ValidateCreate() (warnings admission.Warnings, err error) {
	clusteradcsissuerlog.Info("validate create", "name", r.Name)

	return r.validateClusterAdcsIssuer()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) ValidateUpdate(old runtime.Object) (warnings admission.Warnings, err error) {
	clusteradcsissuerlog.Info("validate update", "name", r.Name)

	return r.validateClusterAdcsIssuer()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) ValidateDelete() (warnings admission.Warnings, err error) {
	clusteradcsissuerlog.Info("validate delete", "name", r.Name)

	return r.validateClusterAdcsIssuer()
}

func (r *ClusterAdcsIssuer) validateClusterAdcsIssuer() (warnings admission.Warnings, err error) {
	var allErrs field.ErrorList

	// Validate RetryInterval
	_, err_val := time.ParseDuration(r.Spec.RetryInterval)
	if err_val != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("retryInterval"), r.Spec.RetryInterval, err_val.Error()))
	}

	// Validate Status Check Interval
	_, err_val = time.ParseDuration(r.Spec.StatusCheckInterval)
	if err_val != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("statusCheckInterval"), r.Spec.StatusCheckInterval, err_val.Error()))
	}

	// Validate URL. Must be valide http or https URL
	re := regexp.MustCompile(`(http|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?`)
	if !re.MatchString(r.Spec.URL) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("url"), r.Spec.URL, "Invalid URL format. Must be valid 'http://' or 'https://' URL."))
	}

	// Validate CA Bundle. Must be a valid certificate PEM.
	_, err_val = pki.DecodeX509CertificateBytes(r.Spec.CABundle)
	if err_val != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("caBundle"), r.Spec.CABundle, err_val.Error()))
	}

	// TODO: Validate credentials secret name?

	if len(allErrs) == 0 {
		return nil, nil
	}
	return apierrors.NewInvalid(
		schema.GroupKind{Group: "adcs.certmanager.csf.nokia.com", Kind: "AdcsIssuer"},
		r.Name, allErrs), nil

}
