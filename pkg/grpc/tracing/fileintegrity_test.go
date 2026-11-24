// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/fileintegrity"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/watcher"
)

func TestMain(m *testing.M) {
	if err := process.InitCache(context.Background(), watcher.NewFakeK8sWatcher(nil), 10, defaults.DefaultProcessCacheGCInterval); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func fileIntegrityEvent(
	policy string,
	id int,
	op v1alpha1.FileIntegrityOperation,
	args ...tracingapi.MsgGenericKprobeArg,
) *MsgGenericKprobeUnix {
	return &MsgGenericKprobeUnix{
		Msg: &tracingapi.MsgGenericKprobe{
			Common: processapi.MsgCommon{Ktime: 1},
			ProcessKey: processapi.MsgExecveKey{
				Pid:   1234,
				Ktime: 1,
			},
		},
		FuncName:   "security_file_permission",
		PolicyName: policy,
		Message:    "file modified",
		Tags: []string{
			"user-tag",
			fileintegrity.OperationTag(op),
			fileintegrity.IDTag(id),
		},
		FileIntegrity: &FileIntegrityInfo{Operation: op},
		Args:          args,
	}
}

func registerFileIntegrityPolicy(t *testing.T, policyName string, id int, spec v1alpha1.FileIntegritySpec) {
	t.Helper()
	policy, err := fileintegrity.NewPolicy(spec)
	require.NoError(t, err)
	key := fileintegrity.RegistryKey(policyName, id)
	fileintegrity.Register(key, policy)
	t.Cleanup(func() { fileintegrity.Unregister(key) })
}

func TestProcessFileIntegrityTamperScenarios(t *testing.T) {
	const policyName = "fim-test"
	dir := t.TempDir()
	protected := filepath.Join(dir, "protected.conf")
	require.NoError(t, os.WriteFile(protected, []byte("trusted\n"), 0600))
	registerFileIntegrityPolicy(t, policyName, 0, v1alpha1.FileIntegritySpec{
		Paths: []string{protected},
	})

	t.Run("write", func(t *testing.T) {
		event := fileIntegrityEvent(policyName, 0, v1alpha1.FileIntegrityOperationWrite,
			tracingapi.MsgGenericKprobeArgFile{Index: 0, Value: protected})
		ret := GetProcessFileIntegrity(event)
		require.NotNil(t, ret)
		require.Equal(t, protected, ret.Path)
		require.Equal(t, "write", ret.Operation)
		require.True(t, strings.HasPrefix(ret.Digest, "sha256:"))
		require.Equal(t, []string{"user-tag"}, ret.Tags)
	})

	t.Run("truncate", func(t *testing.T) {
		event := fileIntegrityEvent(policyName, 0, v1alpha1.FileIntegrityOperationTruncate,
			tracingapi.MsgGenericKprobeArgPath{Index: 0, Value: protected})
		ret := GetProcessFileIntegrity(event)
		require.NotNil(t, ret)
		require.Equal(t, protected, ret.Path)
		require.Equal(t, "truncate", ret.Operation)
	})

	t.Run("rename", func(t *testing.T) {
		renamed := filepath.Join(dir, "renamed.conf")
		require.NoError(t, os.Rename(protected, renamed))
		event := fileIntegrityEvent(policyName, 0, v1alpha1.FileIntegrityOperationRename,
			tracingapi.MsgGenericKprobeArgPath{Index: 1, Value: protected, Label: "old_path"},
			tracingapi.MsgGenericKprobeArgPath{Index: 3, Value: renamed, Label: "new_path"})
		ret := GetProcessFileIntegrity(event)
		require.NotNil(t, ret)
		require.Equal(t, renamed, ret.Path)
		require.Equal(t, protected, ret.OldPath)
		require.Equal(t, "rename", ret.Operation)
		require.True(t, strings.HasPrefix(ret.Digest, "sha256:"))
	})
}

func TestProcessFileIntegrityNormalWriteIgnored(t *testing.T) {
	const policyName = "fim-benign"
	dir := t.TempDir()
	protected := filepath.Join(dir, "protected.conf")
	benign := filepath.Join(dir, "application.log")
	require.NoError(t, os.WriteFile(protected, []byte("trusted\n"), 0600))
	require.NoError(t, os.WriteFile(benign, []byte("normal\n"), 0600))
	registerFileIntegrityPolicy(t, policyName, 0, v1alpha1.FileIntegritySpec{
		Paths: []string{protected},
	})

	event := fileIntegrityEvent(policyName, 0, v1alpha1.FileIntegrityOperationWrite,
		tracingapi.MsgGenericKprobeArgFile{Index: 0, Value: benign})
	require.Nil(t, GetProcessFileIntegrity(event))
}

func TestProcessFileIntegrityExcludedPathIgnored(t *testing.T) {
	const policyName = "fim-exclude"
	dir := t.TempDir()
	excluded := filepath.Join(dir, "cache", "entry")
	require.NoError(t, os.MkdirAll(filepath.Dir(excluded), 0755))
	require.NoError(t, os.WriteFile(excluded, []byte("cache\n"), 0600))
	registerFileIntegrityPolicy(t, policyName, 0, v1alpha1.FileIntegritySpec{
		Paths:        []string{dir + "/"},
		ExcludePaths: []string{filepath.Join(dir, "cache") + "/"},
	})

	event := fileIntegrityEvent(policyName, 0, v1alpha1.FileIntegrityOperationWrite,
		tracingapi.MsgGenericKprobeArgFile{Index: 0, Value: excluded})
	require.Nil(t, GetProcessFileIntegrity(event))
}
