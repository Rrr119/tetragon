// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fileintegrity

import (
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const operationTagPrefix = "__tetragon_file_integrity__="
const idTagPrefix = "__tetragon_file_integrity_id__="

// OperationTag returns the internal tag used to carry the file integrity
// operation through the generic kprobe pipeline.
func OperationTag(op v1alpha1.FileIntegrityOperation) string {
	return operationTagPrefix + string(op)
}

// OperationFromTags extracts the file integrity operation from tags.
func OperationFromTags(tags []string) (v1alpha1.FileIntegrityOperation, bool) {
	for _, tag := range tags {
		if strings.HasPrefix(tag, operationTagPrefix) {
			return v1alpha1.FileIntegrityOperation(strings.TrimPrefix(tag, operationTagPrefix)), true
		}
	}
	return "", false
}

// IDTag returns the internal tag identifying a fileIntegrity section within a
// policy.
func IDTag(id int) string {
	return idTagPrefix + strconv.Itoa(id)
}

// IDFromTags extracts the fileIntegrity section id from tags.
func IDFromTags(tags []string) (int, bool) {
	for _, tag := range tags {
		if strings.HasPrefix(tag, idTagPrefix) {
			id, err := strconv.Atoi(strings.TrimPrefix(tag, idTagPrefix))
			if err != nil {
				return 0, false
			}
			return id, true
		}
	}
	return 0, false
}

// RegistryKey returns the registry key for a fileIntegrity section.
func RegistryKey(policyName string, id int) string {
	return policyName + "/" + strconv.Itoa(id)
}

// PublicTags returns tags without the internal file integrity tag.
func PublicTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	ret := make([]string, 0, len(tags))
	for _, tag := range tags {
		if strings.HasPrefix(tag, operationTagPrefix) || strings.HasPrefix(tag, idTagPrefix) {
			continue
		}
		ret = append(ret, tag)
	}
	return ret
}
