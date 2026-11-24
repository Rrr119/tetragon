// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package fileintegrity implements path matching and bookkeeping for
// TracingPolicy file integrity monitoring.
package fileintegrity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// MaxDigestSize is the maximum file size that is hashed for an event.
const MaxDigestSize = 64 << 20

var supportedOperations = []v1alpha1.FileIntegrityOperation{
	v1alpha1.FileIntegrityOperationWrite,
	v1alpha1.FileIntegrityOperationTruncate,
	v1alpha1.FileIntegrityOperationRename,
	v1alpha1.FileIntegrityOperationDelete,
}

// ParseOperation parses a file integrity operation.
func ParseOperation(op string) (v1alpha1.FileIntegrityOperation, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case string(v1alpha1.FileIntegrityOperationWrite), "mmap", "mmap_write":
		return v1alpha1.FileIntegrityOperationWrite, nil
	case string(v1alpha1.FileIntegrityOperationTruncate):
		return v1alpha1.FileIntegrityOperationTruncate, nil
	case string(v1alpha1.FileIntegrityOperationRename):
		return v1alpha1.FileIntegrityOperationRename, nil
	case string(v1alpha1.FileIntegrityOperationDelete), "unlink", "remove":
		return v1alpha1.FileIntegrityOperationDelete, nil
	default:
		return "", fmt.Errorf("unsupported file integrity operation %q", op)
	}
}

// NormalizeOperations returns the de-duplicated operation set from ops. If ops
// is empty, all supported operations are returned.
func NormalizeOperations(ops []string) ([]v1alpha1.FileIntegrityOperation, error) {
	if len(ops) == 0 {
		return append([]v1alpha1.FileIntegrityOperation(nil), supportedOperations...), nil
	}

	seen := make(map[v1alpha1.FileIntegrityOperation]struct{}, len(ops))
	ret := make([]v1alpha1.FileIntegrityOperation, 0, len(ops))
	for _, op := range ops {
		parsed, err := ParseOperation(op)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[parsed]; ok {
			continue
		}
		seen[parsed] = struct{}{}
		ret = append(ret, parsed)
	}
	return ret, nil
}

type pathSet struct {
	exact    []string
	subtrees []string
	globs    []string
}

// SelectorGroup is a path filter that can be pushed down to a kprobe
// selector. The operator is either "Equal" or "Prefix".
type SelectorGroup struct {
	Operator string
	Values   []string
}

// SelectorGroups returns kernel selector groups for paths. Glob paths are
// reduced to their static prefix; the full glob is checked again in
// userspace.
func SelectorGroups(paths []string) ([]SelectorGroup, error) {
	ps, err := newPathSet(paths)
	if err != nil {
		return nil, err
	}

	var ret []SelectorGroup
	if len(ps.exact) > 0 {
		ret = append(ret, SelectorGroup{Operator: "Equal", Values: ps.exact})
	}
	if len(ps.subtrees) > 0 {
		ret = append(ret, SelectorGroup{Operator: "Prefix", Values: ps.subtrees})
	}
	for _, pattern := range ps.globs {
		ret = append(ret, SelectorGroup{Operator: "Prefix", Values: []string{globPrefix(pattern)}})
	}
	return ret, nil
}

func globPrefix(pattern string) string {
	idx := strings.IndexAny(pattern, "*?[")
	if idx < 0 {
		return pattern
	}
	prefix := pattern[:idx]
	slash := strings.LastIndex(prefix, "/")
	if slash < 0 {
		return "/"
	}
	if slash == 0 {
		return "/"
	}
	return prefix[:slash+1]
}

func newPathSet(paths []string) (pathSet, error) {
	var ret pathSet
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			return pathSet{}, errors.New("file integrity path cannot be empty")
		}
		if !filepath.IsAbs(p) {
			return pathSet{}, fmt.Errorf("file integrity path %q must be absolute", p)
		}

		if strings.HasSuffix(p, "/**") {
			ret.subtrees = append(ret.subtrees, filepath.Clean(strings.TrimSuffix(p, "/**")))
			continue
		}
		if strings.HasSuffix(p, "/") {
			ret.subtrees = append(ret.subtrees, filepath.Clean(p))
			continue
		}
		if hasGlobMeta(p) {
			if _, err := filepath.Match(p, p); err != nil {
				return pathSet{}, fmt.Errorf("invalid file integrity glob %q: %w", p, err)
			}
			ret.globs = append(ret.globs, p)
			continue
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			ret.subtrees = append(ret.subtrees, filepath.Clean(p))
			continue
		}
		ret.exact = append(ret.exact, filepath.Clean(p))
	}
	return ret, nil
}

func hasGlobMeta(p string) bool {
	return strings.ContainsAny(p, "*?[")
}

func (s pathSet) match(p string) bool {
	p = filepath.Clean(p)
	for _, exact := range s.exact {
		if p == exact {
			return true
		}
	}
	for _, root := range s.subtrees {
		if root == string(filepath.Separator) {
			return true
		}
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
		}
	}
	for _, pattern := range s.globs {
		if ok, _ := filepath.Match(pattern, p); ok {
			return true
		}
	}
	return false
}

// Policy is a compiled file integrity policy.
type Policy struct {
	include    pathSet
	exclude    pathSet
	operations map[v1alpha1.FileIntegrityOperation]struct{}
	paths      []string
}

// NewPolicy compiles a FileIntegritySpec.
func NewPolicy(spec v1alpha1.FileIntegritySpec) (*Policy, error) {
	if len(spec.Paths) == 0 {
		return nil, errors.New("file integrity monitoring requires at least one path")
	}
	include, err := newPathSet(spec.Paths)
	if err != nil {
		return nil, err
	}
	exclude, err := newPathSet(spec.ExcludePaths)
	if err != nil {
		return nil, err
	}
	ops, err := NormalizeOperations(spec.Operations)
	if err != nil {
		return nil, err
	}
	opSet := make(map[v1alpha1.FileIntegrityOperation]struct{}, len(ops))
	for _, op := range ops {
		opSet[op] = struct{}{}
	}
	return &Policy{
		include:    include,
		exclude:    exclude,
		operations: opSet,
		paths:      append([]string(nil), spec.Paths...),
	}, nil
}

// Paths returns the configured include paths.
func (p *Policy) Paths() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.paths...)
}

// Matches reports whether any of paths matches the policy for op.
func (p *Policy) Matches(op v1alpha1.FileIntegrityOperation, paths ...string) bool {
	if p == nil {
		return false
	}
	if _, ok := p.operations[op]; !ok {
		return false
	}
	for _, path := range paths {
		if path == "" || p.exclude.match(path) {
			continue
		}
		if p.include.match(path) {
			return true
		}
	}
	return false
}

var policyRegistry sync.Map // map[string]*Policy

// Register registers a compiled policy by tracing policy name.
func Register(policyName string, policy *Policy) {
	if policyName == "" || policy == nil {
		return
	}
	policyRegistry.Store(policyName, policy)
}

// Unregister removes a policy from the registry.
func Unregister(policyName string) {
	policyRegistry.Delete(policyName)
}

// Lookup returns the policy registered for policyName.
func Lookup(policyName string) (*Policy, bool) {
	policy, ok := policyRegistry.Load(policyName)
	if !ok {
		return nil, false
	}
	return policy.(*Policy), true
}

// Matches checks a registered policy. If no policy is registered, it returns
// true so that events are not silently dropped by callers that did not load
// the policy through the sensor manager.
func Matches(policyName string, op v1alpha1.FileIntegrityOperation, paths ...string) bool {
	policy, ok := Lookup(policyName)
	if !ok {
		return true
	}
	return policy.Matches(op, paths...)
}

// Digest returns the SHA-256 digest of path in the "sha256:<hex>" format.
func Digest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > MaxDigestSize {
		return "", fmt.Errorf("file %q is too large to hash: %d bytes", path, info.Size())
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
