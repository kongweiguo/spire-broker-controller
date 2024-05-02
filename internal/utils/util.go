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
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kongweiguo/spire-issuer/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSpecAndStatus(issuer client.Object) (*v1alpha1.SpireIssuerSpec, *v1alpha1.SpireIssuerStatus, error) {
	switch t := issuer.(type) {
	case *v1alpha1.SpireIssuer:
		return &t.Spec, &t.Status, nil
	case *v1alpha1.ClusterSpireIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

// DeepEqual ...
func DeepEqual(x, y interface{}, isEquateEmpty bool) bool {
	if isEquateEmpty {
		opts := []cmp.Option{cmpopts.EquateEmpty(), cmpopts.IgnoreUnexported()}
		return cmp.Equal(x, y, opts...)
	}

	return reflect.DeepEqual(x, y)
}

func NormalizeUnixSocket(socket string) (string, error) {
	var (
		socketPath string
		filePath   string
	)
	if strings.HasPrefix(socket, "unix://") {
		socketPath = socket
		filePath = strings.TrimPrefix(socket, "unix://")
	} else {
		filePath = socket
		socketPath = "unix://" + socket
	}

	_, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}

	return socketPath, nil
}

// GenRandRequeueAfter ...
func GenRandRequeueAfter(lowBase, topLimit int64) ctrl.Result {
	return ctrl.Result{
		RequeueAfter: time.Duration(rand.Int63()%topLimit+lowBase) * time.Second,
	}
}

// GenRandRequeueAfter3_8Seconds ...
func GenRandRequeueAfter3_8Seconds() ctrl.Result {
	return GenRandRequeueAfter(3, 8)
}

// LowestNonZeroResult compares two reconciliation results
// and returns the one with lowest requeue time.
func LowestNonZeroResult(i, j ctrl.Result) ctrl.Result {
	switch {
	case i.IsZero():
		return j
	case j.IsZero():
		return i
	case i.Requeue:
		return i
	case j.Requeue:
		return j
	case i.RequeueAfter < j.RequeueAfter:
		return i
	default:
		return j
	}
}

func GetCurrentTime() string {
	return time.Now().Format(time.RFC3339)
}

// GetFuncName ...return the function pointer ClusterName
func GetFuncName(f interface{}) string {
	name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	list := strings.Split(name, ".")
	return strings.TrimSuffix(list[len(list)-1], "-fm")
}
