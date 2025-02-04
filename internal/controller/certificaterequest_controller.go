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

package controller

import (
	"context"
	"errors"
	"fmt"
	"github.com/kongweiguo/spire-issuer/internal/spire"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kongweiguo/spire-issuer/api/v1alpha1"
	"github.com/kongweiguo/spire-issuer/internal/utils"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
	errSpireAuthority = errors.New("failed to get the spire signer")
	errSignerSign     = errors.New("failed to sign")
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string

	Clock                  clock.Clock
	CheckApprovedCondition bool
	recorder               record.EventRecorder
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(v1alpha1.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	// Get the CertificateRequest
	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if issuerRef doesn't match our group
	if certificateRequest.Spec.IssuerRef.Group != v1alpha1.GroupVersion.Group {
		log.Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.Info("CertificateRequest is Failed. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it already has a Denied Ready Reason
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		log.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return ctrl.Result{}, nil
	}

	if r.CheckApprovedCondition {
		// If CertificateRequest has not been approved, exit early.
		if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
			log.Info("CertificateRequest has not been approved yet. Ignoring.")
			return ctrl.Result{}, nil
		}
	}

	// report gives feedback by updating the Ready Condition of the Cert Request.
	// For added visibility we also log a message and create a Kubernetes Event.
	report := func(reason, message string, err error) {
		status := cmmeta.ConditionFalse
		if reason == cmapi.CertificateRequestReasonIssued {
			status = cmmeta.ConditionTrue
		}
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Info(message)
		}
		r.recorder.Event(
			&certificateRequest,
			eventType,
			v1alpha1.EventReasonCertificateRequestReconciler,
			message,
		)
		cmutil.SetCertificateRequestCondition(
			&certificateRequest,
			cmapi.CertificateRequestConditionReady,
			status,
			reason,
			message,
		)
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			report(cmapi.CertificateRequestReasonPending, "Temporary error. Retrying", err)
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// If CertificateRequest has been denied, mark the CertificateRequest as
	// Ready=Denied and set FailureTime if not already.
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		log.Info("CertificateRequest has been denied yet. Marking as failed.")

		if certificateRequest.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			certificateRequest.Status.FailureTime = &nowTime
		}

		message := "The CertificateRequest was denied by an approval controller"
		report(cmapi.CertificateRequestReasonDenied, message, nil)
		return ctrl.Result{}, nil
	}

	// Add a Ready condition if one does not already exist
	if ready := cmutil.GetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		report(cmapi.CertificateRequestReasonPending, "Initialising Ready condition", nil)
		return ctrl.Result{}, nil
	}

	// Ignore but log an error if the issuerRef.Kind is unrecognised
	issuerGVK := v1alpha1.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		report(cmapi.CertificateRequestReasonFailed, "Unrecognised kind. Ignoring", fmt.Errorf("%w: %v", errIssuerRef, err))
		return ctrl.Result{}, nil
	}
	issuer := issuerRO.(client.Object)
	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}

	switch t := issuer.(type) {
	case *v1alpha1.SpireIssuer:
		issuerName.Namespace = certificateRequest.Namespace
		log = log.WithValues("issuer", issuerName)
	case *v1alpha1.ClusterSpireIssuer:
		log = log.WithValues("clusterissuer", issuerName)
	default:
		report(cmapi.CertificateRequestReasonFailed, "The issuerRef referred to a registered Kind which is not yet handled. Ignoring", fmt.Errorf("unexpected issuer type: %v", t))
		return ctrl.Result{}, nil
	}

	// Get the Issuer or ClusterIssuer
	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	_, issuerStatus, err := utils.GetSpecAndStatus(issuer)
	if err != nil {
		report(cmapi.CertificateRequestReasonFailed, "Unable to get the IssuerStatus. Ignoring", err)
		return ctrl.Result{}, nil
	}

	if issuerStatus.Phase != v1alpha1.Ready {
		return ctrl.Result{}, errIssuerNotReady
	}

	signer, err := r.GetAuthority(ctx, issuerStatus.SecretName, issuerStatus.SecretNamespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSpireAuthority, err)
	}

	chain, err := signer.Sign(&certificateRequest.Spec)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerSign, err)
	}
	certificateRequest.Status.Certificate = chain
	certificateRequest.Status.CA = signer.X509AuthoritiesPem

	report(cmapi.CertificateRequestReasonIssued, "Signed", nil)
	return ctrl.Result{}, nil
}

func (r *CertificateRequestReconciler) GetAuthority(ctx context.Context, name string, namespace string) (authority *spire.Authority, err error) {
	var ca *spire.Authority
	var secret = new(corev1.Secret)

	log := ctrl.LoggerFrom(ctx)

	secretName := types.NamespacedName{Namespace: namespace, Name: name}
	if len(secretName.Namespace) == 0 {
		secretName.Namespace = r.ClusterResourceNamespace
	}

	err = r.Client.Get(ctx, secretName, secret)
	if err != nil {
		log.Info("failed to get authority secret", "error", err)
		return nil, err
	}

	ca, err = spire.SecretToAuthority(secret)
	if err != nil {
		log.Error(err, "secret to spire failed")
		return nil, err
	}

	return ca, nil
}
