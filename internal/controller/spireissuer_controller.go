/*
Copyright 2020 The cert-manager Authors

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
	"fmt"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/go-logr/logr"
	"github.com/kongweiguo/spire-issuer/api/v1alpha1"
	"github.com/kongweiguo/spire-issuer/internal/authority"
	"github.com/kongweiguo/spire-issuer/internal/utils"
)

const (
	defaultHealthCheckInterval = time.Minute
)

type Reconciler func(ictx *issuerContext) (ctrl.Result, error)

// IssuerReconciler reconciles a SpireIssuer object
type IssuerReconciler struct {
	Logger logr.Logger

	Client                   client.Client
	Kind                     string
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	recorder                 record.EventRecorder

	handlers map[v1alpha1.Phase][]Reconciler
}

type issuerContext struct {
	Logger logr.Logger

	ctx context.Context
	req ctrl.Request

	issuer client.Object
	spec   *v1alpha1.SpireIssuerSpec
	status *v1alpha1.SpireIssuerStatus
}

func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newSpireIssuerObject()
	if err != nil {
		return err
	}

	r.handlers = make(map[v1alpha1.Phase][]Reconciler)

	r.handlers[v1alpha1.Processing] = []Reconciler{
		r.ReconcileAuthority,
	}

	r.handlers[v1alpha1.Ready] = []Reconciler{
		r.ReconcileAuthority,
	}

	r.recorder = mgr.GetEventRecorderFor(v1alpha1.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Watches(&corev1.Secret{}, &handler.EnqueueRequestForObject{}). // 监视 Secrets
		Complete(r)
}

// +kubebuilder:rbac:groups=spire.byted.sh,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=spire.byted.sh,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)
	r.Logger = log

	issuer, err := r.newSpireIssuerObject()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Client.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := utils.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	iCtx := &issuerContext{
		Logger: log,
		ctx:    ctx,
		req:    req,

		issuer: issuer,
		spec:   issuerSpec,
		status: issuerStatus,
	}

	result, err = r.reconcile(iCtx)
	if err != nil {
		log.Error(err, "reconcile fail. won't retrying.")
		return ctrl.Result{}, nil
	}

	return result, nil
}

func (r *IssuerReconciler) newSpireIssuerObject() (client.Object, error) {
	issuerGVK := v1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

func (r *IssuerReconciler) reconcile(iCtx *issuerContext) (ctrl.Result, error) {
	// Flow:
	// 1. 判断当前Phase下所有Procedure的Condition
	// 2. 判定是否跃迁到下一个阶段

	if iCtx.status.Phase == "" {
		iCtx.status.Phase = v1alpha1.Processing
	}

	CurrentHandlers, ok := r.handlers[iCtx.status.Phase]
	if !ok {
		err := fmt.Errorf("not found phase(%s) procedures", iCtx.status.Phase)
		r.Logger.Error(err, "fail to retrieve handlers")
		return ctrl.Result{}, err
	}

	var result ctrl.Result
	var errorList []error

	for _, h := range CurrentHandlers {
		procedureName := utils.GetFuncName(h)
		currentResult, err := h(iCtx)
		if err != nil {
			r.Logger.Error(err, fmt.Sprintf("%s failed", procedureName))
			errorList = append(errorList, err)
		}
		result = utils.LowestNonZeroResult(result, currentResult)
	}

	for _, nc := range iCtx.status.Conditions {
		found := false

		for _, h := range CurrentHandlers {
			typ := utils.GetFuncName(h)
			if nc.Type == typ {
				found = true
				break
			}
		}

		if found {
			continue
		} else {
			utils.DeleteCondition(iCtx.status, nc.Type)
		}
	}

	var ready = true
	for _, h := range CurrentHandlers {
		typ := utils.GetFuncName(h)
		c, ok := utils.GetCondition(iCtx.status, typ)
		if !ok || c.Status != metav1.ConditionTrue {
			ready = false
		}
	}

	switch iCtx.status.Phase {
	case v1alpha1.Ready, v1alpha1.Processing:
		if ready {
			iCtx.status.Phase = v1alpha1.Ready
		} else {
			iCtx.status.Phase = v1alpha1.Processing
		}
	}

	r.applyStatus(iCtx)
	return result, utilerrors.NewAggregate(errorList)
}

func (r *IssuerReconciler) ReconcileAuthority(ictx *issuerContext) (ctrl.Result, error) {
	var err error
	var ca *authority.Authority
	var secret = new(corev1.Secret)

	conditionType := utils.GetFuncName(r.ReconcileAuthority)

	defer func() {
		if err != nil {
			utils.SetConditionError(ictx.status, conditionType, err.Error())

		} else {
			ictx.status.NotAfter = metav1.NewTime(ca.Cert.NotAfter)
			ictx.status.NotBefore = metav1.NewTime(ca.Cert.NotBefore)
			ictx.status.SecretName = secret.Name
			ictx.status.SecretNamespace = secret.Namespace

			utils.SetConditionSuccess(ictx.status, conditionType)
		}
	}()

	secretName := types.NamespacedName{Namespace: ictx.req.Namespace, Name: ictx.req.Name}
	if len(secretName.Namespace) == 0 {
		secretName.Namespace = r.ClusterResourceNamespace
	}

	err = r.Client.Get(ictx.ctx, secretName, secret)
	if err == nil {
		r.Logger.Info("found secret, trying to check TTL")

		ca, err = authority.SecretToAuthority(secret)
		if err != nil {
			r.Logger.Error(err, "secret to authority failed")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}

		if !ca.NeedRotation(&ictx.spec.Config) {
			return ctrl.Result{}, nil
		}

		ca, err = r.buildAuthority(ictx)
		if err != nil {
			r.Logger.Error(err, "build authority failed")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}

		newSecret := authority.AuthorityToSecret(&secretName, ca)
		secret.Data = newSecret.Data

		err = ctrl.SetControllerReference(ictx.issuer, secret, r.Scheme)
		if err != nil {
			r.Logger.Error(err, "couldn't set controller reference for secret")
			return ctrl.Result{}, err
		}

		err = controllerutil.SetOwnerReference(ictx.issuer, secret, r.Scheme)
		if err != nil {
			r.Logger.Error(err, "couldn't set owner reference for secret")
			return ctrl.Result{}, err
		}

		err = r.Client.Update(ictx.ctx, secret)
		if err != nil {
			r.Logger.Error(err, "build authority failed")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}

		return ctrl.Result{}, nil
	} else if apierrors.IsNotFound(err) {
		// not found
		r.Logger.Info("not found secret")

		ca, err = r.buildAuthority(ictx)
		if err != nil {
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}

		secret = authority.AuthorityToSecret(&secretName, ca)

		err = ctrl.SetControllerReference(ictx.issuer, secret, r.Scheme)
		if err != nil {
			r.Logger.Error(err, "couldn't set controller reference for secret")
			return ctrl.Result{}, err
		}

		err = controllerutil.SetOwnerReference(ictx.issuer, secret, r.Scheme)
		if err != nil {
			r.Logger.Error(err, "couldn't set controller reference for secret")
			return ctrl.Result{}, err
		}

		err = r.Client.Create(ictx.ctx, secret)
		if err != nil {
			r.Logger.Error(err, "create secret failed")
			return ctrl.Result{}, fmt.Errorf("create secret failed. not retrying... error: %v", err)
		}

		r.Logger.Info("Create Secret Success")
		return ctrl.Result{}, nil
	} else {
		r.Logger.Error(err, "unexpected Get Secret. not retrying...")
		return ctrl.Result{}, fmt.Errorf("unexpected Get Secret. not retrying... error: %v", err)
	}
}

func (r *IssuerReconciler) buildAuthority(iCtx *issuerContext) (*authority.Authority, error) {
	spireConfig := &authority.SpireConfig{
		TrustDomain:   iCtx.spec.TrustDomain,
		AgentSocket:   iCtx.spec.AgentSocket,
		ServerAddress: iCtx.spec.ServerAddress,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ca, err := authority.GetDownstreamAuthority(ctx, spireConfig, &iCtx.spec.Config)
	if err != nil {
		r.Logger.Error(err, "GetDownstreamAuthority fail")
		return nil, err
	}

	return ca, nil
}

func (r *IssuerReconciler) applyStatus(ictx *issuerContext) {
	issuerInSystem, err := r.newSpireIssuerObject()
	if err != nil {
		r.Logger.Error(err, "Unrecognised issuer type")
		return
	}

	if err := r.Client.Get(ictx.ctx, ictx.req.NamespacedName, issuerInSystem); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			r.Logger.Error(err, "unexpected get error")
			return
		}
		r.Logger.Info("Not found. Ignoring.")
		return
	}

	_, issuerStatusInSystem, err := utils.GetSpecAndStatus(issuerInSystem)
	if err != nil {
		r.Logger.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return
	}

	if !utils.DeepEqual(ictx.status, issuerStatusInSystem, true) {
		metaAccessor := meta.NewAccessor()
		currentResourceVersion, err := metaAccessor.ResourceVersion(issuerInSystem)
		if err != nil {
			r.Logger.Error(err, "failed to metaAccessor")
			return
		}

		_ = metaAccessor.SetResourceVersion(ictx.issuer, currentResourceVersion)
		err = r.Client.Status().Update(ictx.ctx, ictx.issuer)
		if err != nil {
			r.Logger.Error(err, "failed to update status")
			return
		}

		r.Logger.Info("Update CisCluster status successfully")
	}
}
