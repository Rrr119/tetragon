// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fileintegrity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestPolicyTamperScenarios(t *testing.T) {
	policy, err := NewPolicy(v1alpha1.FileIntegritySpec{
		Paths: []string{
			"/etc/passwd",
			"/srv/www/",
			"/var/lib/app/*.conf",
		},
		ExcludePaths: []string{"/srv/www/cache/"},
		Operations:   []string{"write", "truncate", "rename"},
	})
	require.NoError(t, err)

	tests := []struct {
		name string
		op   v1alpha1.FileIntegrityOperation
		path string
		want bool
	}{
		{
			name: "direct write to exact path",
			op:   v1alpha1.FileIntegrityOperationWrite,
			path: "/etc/passwd",
			want: true,
		},
		{
			name: "truncate below monitored directory",
			op:   v1alpha1.FileIntegrityOperationTruncate,
			path: "/srv/www/index.html",
			want: true,
		},
		{
			name: "rename of glob matched file",
			op:   v1alpha1.FileIntegrityOperationRename,
			path: "/var/lib/app/production.conf",
			want: true,
		},
		{
			name: "normal write outside policy",
			op:   v1alpha1.FileIntegrityOperationWrite,
			path: "/tmp/application-cache",
			want: false,
		},
		{
			name: "write excluded from monitored directory",
			op:   v1alpha1.FileIntegrityOperationWrite,
			path: "/srv/www/cache/index.html",
			want: false,
		},
		{
			name: "unconfigured operation on monitored path",
			op:   v1alpha1.FileIntegrityOperationDelete,
			path: "/etc/passwd",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, policy.Matches(tt.op, tt.path))
		})
	}
}

func TestPolicyRenameMatchesOldOrNewPath(t *testing.T) {
	policy, err := NewPolicy(v1alpha1.FileIntegritySpec{
		Paths: []string{"/etc/shadow"},
	})
	require.NoError(t, err)

	require.False(t, policy.Matches(v1alpha1.FileIntegrityOperationRename, "/tmp/shadow"))
	require.True(t, policy.Matches(v1alpha1.FileIntegrityOperationRename, "/tmp/shadow", "/etc/shadow"))
	require.False(t, policy.Matches(v1alpha1.FileIntegrityOperationRename, "/tmp/shadow", "/tmp/other"))
}

func TestSelectorGroups(t *testing.T) {
	groups, err := SelectorGroups([]string{"/etc/passwd", "/srv/", "/var/lib/*.conf"})
	require.NoError(t, err)
	require.Equal(t, []SelectorGroup{
		{Operator: "Equal", Values: []string{"/etc/passwd"}},
		{Operator: "Prefix", Values: []string{"/srv"}},
		{Operator: "Prefix", Values: []string{"/var/lib/"}},
	}, groups)
}

func TestPolicyValidation(t *testing.T) {
	_, err := NewPolicy(v1alpha1.FileIntegritySpec{})
	require.ErrorContains(t, err, "at least one path")

	_, err = NewPolicy(v1alpha1.FileIntegritySpec{Paths: []string{"relative/path"}})
	require.ErrorContains(t, err, "must be absolute")

	_, err = NewPolicy(v1alpha1.FileIntegritySpec{
		Paths:      []string{"/etc/passwd"},
		Operations: []string{"chmod"},
	})
	require.ErrorContains(t, err, "unsupported")
}

func TestTags(t *testing.T) {
	tags := []string{"user-tag", OperationTag(v1alpha1.FileIntegrityOperationTruncate), IDTag(3)}

	op, ok := OperationFromTags(tags)
	require.True(t, ok)
	require.Equal(t, v1alpha1.FileIntegrityOperationTruncate, op)

	id, ok := IDFromTags(tags)
	require.True(t, ok)
	require.Equal(t, 3, id)

	require.Equal(t, []string{"user-tag"}, PublicTags(tags))
	require.Equal(t, "policy/3", RegistryKey("policy", 3))
}

func TestDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("hello\n"), 0600))

	digest, err := Digest(path)
	require.NoError(t, err)
	require.Equal(t, "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", digest)
}
