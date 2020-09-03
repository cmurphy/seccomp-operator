/*
Copyright 2020 The Kubernetes Authors.

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

package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/containers/common/pkg/seccomp"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	//"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	//"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompoperatorv1alpha1 "sigs.k8s.io/seccomp-operator/api/v1alpha1"
	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	wait = 30 * time.Second

	errGetProfile          = "cannot get profile"
	errConfigMapNil        = "config map cannot be nil"
	errSavingProfile       = "cannot save profile"
	errCreatingOperatorDir = "cannot create operator directory"

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	// seccompProfileAnnotation is the annotation on a ConfigMap that specifies
	// its intention to be treated as a seccomp profile.
	seccompProfileAnnotation = "seccomp.security.kubernetes.io/profile"

	reasonSeccompNotSupported   event.Reason = "SeccompNotSupportedOnNode"
	reasonInvalidSeccompProfile event.Reason = "InvalidSeccompProfile"
	reasonCannotGetProfilePath  event.Reason = "CannotGetSeccompProfilePath"
	reasonCannotSaveProfile     event.Reason = "CannotSaveSeccompProfile"

	reasonSavedProfile event.Reason = "SavedSeccompProfile"
)

// isProfile checks if a ConfigMap has been designated as a seccomp profile.
func isProfile(obj runtime.Object) bool {
	r, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return false
	}

	return r.Annotations[seccompProfileAnnotation] == "true"
}

// Setup adds a controller that reconciles seccomp profiles.
func Setup(mgr ctrl.Manager, l logr.Logger) error {
	const name = "profile"

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&seccompoperatorv1alpha1.SeccompProfile{}).
		//WithEventFilter(resource.NewPredicates(isProfile)).
		Complete(&Reconciler{
			client: mgr.GetClient(),
			log:    l,
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor("profile")),
		})
}

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	client client.Client
	log    logr.Logger
	record event.Recorder
}

// Reconcile reconciles a SeccompProfile or a ConfigMap representing a seccomp profile.
// TODO: add back ConfigMap reconciliation
func (r *Reconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	seccompProfile := &seccompoperatorv1alpha1.SeccompProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, seccompProfile); err != nil {
		logger.Error(err, "unable to fetch SeccompProfile")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Pre-check if the node supports seccomp
	if !seccomp.IsSupported() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support seccomp", os.Getenv(config.NodeNameEnvKey)))
		r.record.Event(seccompProfile,
			event.Warning(reasonSeccompNotSupported, err, os.Getenv(config.NodeNameEnvKey),
				"node does not support seccomp"))

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	profileName := seccompProfile.Name
	if !strings.HasSuffix(profileName, ".json") {
		profileName += ".json"
	}

	profileContent, err := json.Marshal(seccompProfile.Spec)
	if err != nil {
		logger.Error(err, "cannot validate profile "+profileName)
		r.record.Event(seccompProfile, event.Warning(reasonInvalidSeccompProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	profilePath, err := GetProfilePath(profileName, seccompProfile)
	if err != nil {
		logger.Error(err, "cannot get profile path")
		r.record.Event(seccompProfile, event.Warning(reasonCannotGetProfilePath, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	if err = saveProfileOnDisk(profilePath, profileContent); err != nil {
		logger.Error(err, "cannot save profile into disk")
		r.record.Event(seccompProfile, event.Warning(reasonCannotSaveProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	logger.Info(
		"Reconciled profile",
		"resource version", seccompProfile.GetResourceVersion(),
		"name", seccompProfile.GetName(),
	)
	r.record.Event(seccompProfile, event.Normal(reasonSavedProfile, "Successfully saved profile (test)"))
	return reconcile.Result{}, nil
}

func saveProfileOnDisk(fileName string, contents []byte) error {
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		return errors.Wrap(err, errCreatingOperatorDir)
	}

	if err := ioutil.WriteFile(fileName, contents, filePermissionMode); err != nil {
		return errors.Wrap(err, errSavingProfile)
	}
	return nil
}

// GetProfilePath returns the full path for the provided profile name and config.
func GetProfilePath(profileName string, profile *seccompoperatorv1alpha1.SeccompProfile) (string, error) {
	if profile == nil {
		return "", errors.New(errConfigMapNil)
	}

	return path.Join(
		config.ProfilesRootPath,
		filepath.Base(profile.ObjectMeta.Namespace),
		filepath.Base(profile.ObjectMeta.Name),
		filepath.Base(profileName),
	), nil
}

func ignoreNotFound(err error) error {
	if kerrors.IsNotFound(err) {
		return nil
	}
	return err
}

// validateProfile does a basic validation for the provided seccomp profile
// string.
func validateProfile(content string) error {
	profile := &seccomp.Seccomp{}
	if err := json.Unmarshal([]byte(content), &profile); err != nil {
		return errors.Wrap(err, "decoding seccomp profile")
	}

	// TODO: consider further validation steps
	return nil
}
