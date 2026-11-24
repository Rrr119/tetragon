// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileIntegrityTracingPolicyFromYAML(t *testing.T) {
	policy, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: file-integrity
spec:
  fileIntegrity:
  - paths:
    - /etc/passwd
    - /etc/ssh/
    excludePaths:
    - /etc/ssh/tmp/
    operations:
    - write
    - truncate
    - rename
    selectors:
    - matchBinaries:
      - operator: NotIn
        values:
        - /usr/bin/dpkg
    message: protected file modified
    tags:
    - fim
`)
	require.NoError(t, err)

	spec := policy.TpSpec()
	require.Len(t, spec.FileIntegrity, 1)
	require.Equal(t, []string{"/etc/passwd", "/etc/ssh/"}, spec.FileIntegrity[0].Paths)
	require.Equal(t, []string{"/etc/ssh/tmp/"}, spec.FileIntegrity[0].ExcludePaths)
	require.Equal(t, []string{"write", "truncate", "rename"}, spec.FileIntegrity[0].Operations)
	require.Equal(t, "protected file modified", spec.FileIntegrity[0].Message)
	require.Equal(t, []string{"fim"}, spec.FileIntegrity[0].Tags)
	require.Equal(t, "file-integrity", policy.TpName())
}

func TestFileIntegrityTracingPolicyRejectsUnknownOperation(t *testing.T) {
	_, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: file-integrity
spec:
  fileIntegrity:
  - paths:
    - /etc/passwd
    operations:
    - chmod
`)
	require.Error(t, err)
}
