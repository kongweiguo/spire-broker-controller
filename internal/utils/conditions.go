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

package utils

import (
	"github.com/kongweiguo/spire-issuer/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ReasonFailedProcess     = "FailedProcess"
	ReasonWaitingProcess    = "WaitingProcess"
	ReasonSuccessfulProcess = "SuccessfulProcess"
	ReasonSkipProcess       = "SkipProcess"
)

func SetConditionError(status *v1alpha1.SpireIssuerStatus, conditionType string, message string) {
	nc := metav1.Condition{
		Type:    conditionType,
		Status:  metav1.ConditionFalse,
		Reason:  ReasonFailedProcess,
		Message: message,
	}

	SetCondition(status, nc)
}

func SetConditionWaiting(status *v1alpha1.SpireIssuerStatus, conditionType string, message string) {
	nc := metav1.Condition{
		Type:    conditionType,
		Status:  metav1.ConditionFalse,
		Reason:  ReasonWaitingProcess,
		Message: message,
	}

	SetCondition(status, nc)
}

func SetConditionSuccess(status *v1alpha1.SpireIssuerStatus, conditionType string) {
	nc := metav1.Condition{
		Type:    conditionType,
		Status:  metav1.ConditionTrue,
		Reason:  ReasonSuccessfulProcess,
		Message: "Success",
	}

	SetCondition(status, nc)
}

// SetCondition ...
func SetCondition(status *v1alpha1.SpireIssuerStatus, nc metav1.Condition) {
	var conditions []metav1.Condition
	exist := false

	if nc.LastTransitionTime.IsZero() {
		nc.LastTransitionTime = metav1.Now()
	}
	for _, c := range status.Conditions {
		if c.Type == nc.Type {
			exist = true

			// 只有当"状态"、"信息"、"原因"变更时才需要赋值，更新LastTransitionTime
			if c.Status != nc.Status ||
				c.Message != nc.Message ||
				c.Reason != nc.Reason {
				c = nc
			}
		}
		conditions = append(conditions, c)
	}

	if !exist {
		conditions = append(conditions, nc)
	}

	status.Conditions = conditions
}

func GetCondition(status *v1alpha1.SpireIssuerStatus, conditionType string) (metav1.Condition, bool) {
	for _, v := range status.Conditions {
		if v.Type == conditionType {
			return v, true
		}
	}

	return metav1.Condition{}, false
}

func DeleteCondition(status *v1alpha1.SpireIssuerStatus, conditionType string) {
	olds := status.Conditions

	for idx := 0; idx < len(olds); idx++ {
		if olds[idx].Type == conditionType {
			olds = append(olds[:idx], olds[idx+1:]...)
			idx--
		}
	}

	status.Conditions = olds
}
