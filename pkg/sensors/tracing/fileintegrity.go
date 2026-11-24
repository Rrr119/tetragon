// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"slices"

	"github.com/cilium/tetragon/pkg/fileintegrity"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const (
	fileIntegrityWriteHook = "security_file_permission"
	fileIntegrityMmapHook  = "security_mmap_file"
	fileIntegrityTruncate  = "security_file_truncate"
	fileIntegrityPTruncate = "security_path_truncate"
	fileIntegrityRename    = "security_inode_rename"
	fileIntegrityUnlink    = "security_inode_unlink"
)

type fileIntegrityHook struct {
	call               string
	args               []v1alpha1.KProbeArg
	pathArgs           []int
	extraMatchArgs     []v1alpha1.ArgSelector
	ignoreCallNotFound bool
	operation          v1alpha1.FileIntegrityOperation
}

func fileIntegrityKProbes(spec *v1alpha1.TracingPolicySpec) ([]v1alpha1.KProbeSpec, error) {
	if len(spec.FileIntegrity) == 0 {
		return nil, nil
	}

	var ret []v1alpha1.KProbeSpec
	for i := range spec.FileIntegrity {
		fis := &spec.FileIntegrity[i]
		if len(fis.Tags) > TpMaxTags-2 {
			return nil, fmt.Errorf("fileIntegrity[%d]: at most %d tags are supported", i, TpMaxTags-2)
		}
		if _, err := fileintegrity.NewPolicy(*fis); err != nil {
			return nil, fmt.Errorf("fileIntegrity[%d]: %w", i, err)
		}
		groups, err := fileintegrity.SelectorGroups(fis.Paths)
		if err != nil {
			return nil, fmt.Errorf("fileIntegrity[%d]: %w", i, err)
		}
		operations, err := fileintegrity.NormalizeOperations(fis.Operations)
		if err != nil {
			return nil, fmt.Errorf("fileIntegrity[%d]: %w", i, err)
		}

		for _, hook := range fileIntegrityHooks(operations) {
			ret = append(ret, buildFileIntegrityKProbes(fis, hook, groups, i)...)
		}
	}
	return ret, nil
}

func registerFileIntegrityPolicies(policyName string, specs []v1alpha1.FileIntegritySpec) error {
	var registered *fileintegrity.Policy
	for i := range specs {
		policy, err := fileintegrity.NewPolicy(specs[i])
		if err != nil {
			return fmt.Errorf("fileIntegrity[%d]: %w", i, err)
		}
		fileintegrity.Register(fileintegrity.RegistryKey(policyName, i), policy)
		registered = policy
	}
	if len(specs) == 1 {
		fileintegrity.Register(policyName, registered)
	}
	return nil
}

func fileIntegrityHooks(operations []v1alpha1.FileIntegrityOperation) []fileIntegrityHook {
	var ret []fileIntegrityHook
	has := func(op v1alpha1.FileIntegrityOperation) bool {
		return slices.Contains(operations, op)
	}

	if has(v1alpha1.FileIntegrityOperationWrite) {
		ret = append(ret,
			fileIntegrityHook{
				call: fileIntegrityWriteHook,
				args: []v1alpha1.KProbeArg{
					{Index: 0, Type: "file"},
					{Index: 1, Type: "int"},
				},
				pathArgs:  []int{0},
				operation: v1alpha1.FileIntegrityOperationWrite,
				extraMatchArgs: []v1alpha1.ArgSelector{
					{Index: 1, Operator: "Mask", Values: []string{"2"}}, // MAY_WRITE
				},
			},
			fileIntegrityHook{
				call: fileIntegrityMmapHook,
				args: []v1alpha1.KProbeArg{
					{Index: 0, Type: "file"},
					{Index: 1, Type: "uint32"},
					{Index: 2, Type: "nop"},
				},
				pathArgs:  []int{0},
				operation: v1alpha1.FileIntegrityOperationWrite,
				extraMatchArgs: []v1alpha1.ArgSelector{
					{Index: 1, Operator: "Mask", Values: []string{"2"}}, // PROT_WRITE
					{Index: 2, Operator: "Mask", Values: []string{"1"}}, // MAP_SHARED
				},
			},
		)
	}
	if has(v1alpha1.FileIntegrityOperationTruncate) {
		ret = append(ret,
			fileIntegrityHook{
				call: fileIntegrityTruncate,
				args: []v1alpha1.KProbeArg{
					{Index: 0, Type: "file"},
				},
				pathArgs:           []int{0},
				operation:          v1alpha1.FileIntegrityOperationTruncate,
				ignoreCallNotFound: true,
			},
			fileIntegrityHook{
				call: fileIntegrityPTruncate,
				args: []v1alpha1.KProbeArg{
					{Index: 0, Type: "path"},
				},
				pathArgs:           []int{0},
				operation:          v1alpha1.FileIntegrityOperationTruncate,
				ignoreCallNotFound: true,
			},
		)
	}
	if has(v1alpha1.FileIntegrityOperationRename) {
		args := []v1alpha1.KProbeArg{
			{Index: 1, Type: "dentry", Label: "old_path"},
			{Index: 3, Type: "dentry", Label: "new_path"},
		}
		ret = append(ret, fileIntegrityHook{
			call:      fileIntegrityRename,
			args:      args,
			pathArgs:  []int{1, 3},
			operation: v1alpha1.FileIntegrityOperationRename,
		})
	}
	if has(v1alpha1.FileIntegrityOperationDelete) {
		ret = append(ret, fileIntegrityHook{
			call: fileIntegrityUnlink,
			args: []v1alpha1.KProbeArg{
				{Index: 0, Type: "nop"},
				{Index: 1, Type: "dentry"},
			},
			pathArgs:  []int{1},
			operation: v1alpha1.FileIntegrityOperationDelete,
		})
	}
	return ret
}

func buildFileIntegrityKProbes(
	spec *v1alpha1.FileIntegritySpec,
	hook fileIntegrityHook,
	groups []fileintegrity.SelectorGroup,
	id int,
) []v1alpha1.KProbeSpec {
	var selectors []v1alpha1.KProbeSelector
	userSelectors := spec.Selectors
	if len(userSelectors) == 0 {
		userSelectors = []v1alpha1.KProbeSelector{{}}
	}

	for _, userSelector := range userSelectors {
		for _, pathArg := range hook.pathArgs {
			for _, group := range groups {
				selector := cloneSelector(userSelector)
				selector.MatchArgs = append(selector.MatchArgs, v1alpha1.ArgSelector{
					Index:    uint32(pathArg),
					Operator: group.Operator,
					Values:   append([]string(nil), group.Values...),
				})
				for _, arg := range hook.extraMatchArgs {
					selector.MatchArgs = append(selector.MatchArgs, cloneArgSelector(arg))
				}
				selectors = append(selectors, selector)
			}
		}
	}

	tags := append([]string(nil), spec.Tags...)
	tags = append(tags, fileintegrity.OperationTag(hook.operation), fileintegrity.IDTag(id))

	message := spec.Message
	if message == "" {
		message = fmt.Sprintf("file integrity %s detected", hook.operation)
	}

	return []v1alpha1.KProbeSpec{{
		Call:      hook.call,
		Syscall:   false,
		Args:      append([]v1alpha1.KProbeArg(nil), hook.args...),
		Selectors: selectors,
		Message:   message,
		Tags:      tags,
		Ignore: &v1alpha1.KprobeIgnore{
			CallNotFound: hook.ignoreCallNotFound,
		},
	}}
}

func cloneSelector(selector v1alpha1.KProbeSelector) v1alpha1.KProbeSelector {
	ret := selector
	ret.MatchArgs = append([]v1alpha1.ArgSelector(nil), selector.MatchArgs...)
	ret.MatchData = append([]v1alpha1.ArgSelector(nil), selector.MatchData...)
	ret.MatchReturnArgs = append([]v1alpha1.ArgSelector(nil), selector.MatchReturnArgs...)
	ret.MatchPIDs = append([]v1alpha1.PIDSelector(nil), selector.MatchPIDs...)
	ret.MatchBinaries = append([]v1alpha1.BinarySelector(nil), selector.MatchBinaries...)
	ret.MatchParentBinaries = append([]v1alpha1.BinarySelector(nil), selector.MatchParentBinaries...)
	ret.MatchActions = append([]v1alpha1.ActionSelector(nil), selector.MatchActions...)
	ret.MatchReturnActions = append([]v1alpha1.ActionSelector(nil), selector.MatchReturnActions...)
	ret.MatchNamespaces = append([]v1alpha1.NamespaceSelector(nil), selector.MatchNamespaces...)
	ret.MatchNamespaceChanges = append([]v1alpha1.NamespaceChangesSelector(nil), selector.MatchNamespaceChanges...)
	ret.MatchCapabilities = append([]v1alpha1.CapabilitiesSelector(nil), selector.MatchCapabilities...)
	ret.MatchCapabilityChanges = append([]v1alpha1.CapabilitiesSelector(nil), selector.MatchCapabilityChanges...)
	ret.MatchUserCallers = append([]v1alpha1.UserCallerSelector(nil), selector.MatchUserCallers...)
	ret.MatchStates = append([]v1alpha1.StateSelector(nil), selector.MatchStates...)
	ret.Macros = append([]string(nil), selector.Macros...)
	return ret
}

func cloneArgSelector(selector v1alpha1.ArgSelector) v1alpha1.ArgSelector {
	ret := selector
	ret.Values = append([]string(nil), selector.Values...)
	return ret
}
