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
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var log = logf.Log.WithName("adcsissuer-resource")

func (r *AdcsIssuer) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-adcs-certmanager-csf-nokia-com-v1-adcsissuer,mutating=true,failurePolicy=fail,groups=adcs.certmanager.csf.nokia.com,resources=adcsissuer,verbs=create;update,versions=v1,name=adcsissuer-mutation.adcs.certmanager.csf.nokia.com,sideEffects=None,admissionReviewVersions=v1

var _ webhook.Defaulter = &AdcsIssuer{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *AdcsIssuer) Default() {
	log.Info("default", "name", r.Name)

	if r.Spec.StatusCheckInterval == "" {
		r.Spec.StatusCheckInterval = "6h"
	}
	if r.Spec.RetryInterval == "" {
		r.Spec.RetryInterval = "1h"
	}
}

// +kubebuilder:webhook:verbs=create;update,path=/validate-adcs-certmanager-csf-nokia-com-v1-adcsissuer,mutating=false,failurePolicy=fail,groups=adcs.certmanager.csf.nokia.com,resources=adcsissuer,versions=v1,name=adcsissuer-validation.adcs.certmanager.csf.nokia.com,sideEffects=None,admissionReviewVersions=v1

var _ webhook.Validator = &AdcsIssuer{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *AdcsIssuer) ValidateCreate() (warnings admission.Warnings, err error) {
	log.Info("validate create", "name", r.Name)

	return r.validateAdcsIssuer()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *AdcsIssuer) ValidateUpdate(old runtime.Object) (warnings admission.Warnings, err error) {
	log.Info("validate update", "name", r.Name)

	return r.validateAdcsIssuer()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *AdcsIssuer) ValidateDelete() (warnings admission.Warnings, err error) {
	log.Info("validate delete", "name", r.Name)

	return nil, nil
}

func (r *AdcsIssuer) validateAdcsIssuer() (warnings admission.Warnings, err error) {
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
