// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/fileintegrity"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestFileIntegrityKProbes(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		FileIntegrity: []v1alpha1.FileIntegritySpec{{
			Paths:      []string{"/etc/passwd", "/var/lib/app/"},
			Operations: []string{"write", "truncate", "rename"},
			Message:    "protected file modified",
			Tags:       []string{"security"},
		}},
	}

	kprobes, err := fileIntegrityKProbes(spec)
	require.NoError(t, err)

	byCall := map[string][]v1alpha1.KProbeSpec{}
	for _, kp := range kprobes {
		byCall[kp.Call] = append(byCall[kp.Call], kp)
	}

	require.Len(t, byCall[fileIntegrityWriteHook], 1)
	require.Len(t, byCall[fileIntegrityMmapHook], 1)
	require.Len(t, byCall[fileIntegrityTruncate], 1)
	require.Len(t, byCall[fileIntegrityPTruncate], 1)
	require.Len(t, byCall[fileIntegrityRename], 1)
	require.Empty(t, byCall[fileIntegrityUnlink], "delete is not enabled")

	write := byCall[fileIntegrityWriteHook][0]
	require.Equal(t, "protected file modified", write.Message)
	require.Contains(t, write.Tags, "security")
	require.Contains(t, write.Tags, fileintegrity.OperationTag(v1alpha1.FileIntegrityOperationWrite))
	require.NotNil(t, write.Ignore)
	require.False(t, write.Ignore.CallNotFound)
	require.Len(t, write.Selectors, 2)
	require.Equal(t, uint32(0), write.Selectors[0].MatchArgs[0].Index)
	require.Equal(t, "Equal", write.Selectors[0].MatchArgs[0].Operator)
	require.Equal(t, []string{"/etc/passwd"}, write.Selectors[0].MatchArgs[0].Values)
	require.Equal(t, "Prefix", write.Selectors[1].MatchArgs[0].Operator)
	require.Equal(t, []string{"/var/lib/app"}, write.Selectors[1].MatchArgs[0].Values)
	require.Equal(t, uint32(1), write.Selectors[0].MatchArgs[1].Index)
	require.Equal(t, "Mask", write.Selectors[0].MatchArgs[1].Operator)
	require.Equal(t, []string{"2"}, write.Selectors[0].MatchArgs[1].Values)

	mmap := byCall[fileIntegrityMmapHook][0]
	require.Len(t, mmap.Selectors[0].MatchArgs, 3)
	require.Equal(t, []string{"2"}, mmap.Selectors[0].MatchArgs[1].Values)
	require.Equal(t, []string{"1"}, mmap.Selectors[0].MatchArgs[2].Values)

	for _, call := range []string{fileIntegrityTruncate, fileIntegrityPTruncate} {
		truncate := byCall[call][0]
		require.True(t, truncate.Ignore.CallNotFound)
	}

	renameArgs := map[uint32]bool{}
	for _, rename := range byCall[fileIntegrityRename] {
		require.Contains(t, rename.Tags, fileintegrity.OperationTag(v1alpha1.FileIntegrityOperationRename))
		for _, selector := range rename.Selectors {
			renameArgs[selector.MatchArgs[0].Index] = true
		}
		require.Len(t, rename.Args, 2)
	}
	require.Equal(t, map[uint32]bool{1: true, 3: true}, renameArgs)
}

func TestFileIntegrityKProbesCombinedWithKprobes(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{{
			Call: "sys_read",
			Args: []v1alpha1.KProbeArg{{Index: 0, Type: "int"}},
		}},
		FileIntegrity: []v1alpha1.FileIntegritySpec{{
			Paths:      []string{"/etc/passwd"},
			Operations: []string{"truncate"},
		}},
	}

	kprobes, err := fileIntegrityKProbes(spec)
	require.NoError(t, err)
	require.NotEmpty(t, kprobes)
	require.Equal(t, "sys_read", spec.KProbes[0].Call, "existing kprobes must not be mutated")
}

func TestFileIntegrityKProbesInvalidPolicy(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		FileIntegrity: []v1alpha1.FileIntegritySpec{{
			Paths: []string{"relative"},
		}},
	}
	_, err := fileIntegrityKProbes(spec)
	require.ErrorContains(t, err, "must be absolute")
}
