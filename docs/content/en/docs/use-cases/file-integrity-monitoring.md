---
title: "File integrity monitoring"
weight: 3
description: "Detect changes to critical files with path-based TracingPolicies"
---

The `fileIntegrity` section of a `TracingPolicy` monitors file modifications by
path. It uses the existing kprobe sensor and can be combined with `kprobes` in
the same policy.

The following policy protects critical host files:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-integrity-monitoring"
spec:
  fileIntegrity:
  - paths:
    - "/etc/passwd"
    - "/etc/shadow"
    - "/etc/ssh/"
    - "/root/.ssh/"
    - "/etc/kubernetes/"
    excludePaths:
    - "/etc/kubernetes/tmp/"
    operations:
    - "write"
    - "truncate"
    - "rename"
    - "delete"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values:
        - "/usr/bin/dpkg"
        - "/usr/bin/rpm"
    message: "critical file was modified"
    tags:
    - "fim"
    - "critical"
```

Apply it with:

```bash
kubectl apply -f examples/tracingpolicy/file_integrity_monitoring.yaml
```

Then watch file integrity events:

```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -e PROCESS_FILE_INTEGRITY -o compact
```

## Path matching

- An exact path, such as `/etc/passwd`, matches only that file.
- A path ending in `/` or `/**`, such as `/etc/ssh/`, matches the directory and
  all of its descendants. An existing directory is also treated as a subtree
  even without a trailing slash.
- Shell-style globs such as `/etc/*.conf` are supported. They are filtered in
  the kernel using their static prefix and checked again in user space.
- `excludePaths` always take precedence over `paths`.

## Operations

The supported operations are `write`, `truncate`, `rename` and `delete`.
Omitting `operations` enables all of them. Write detection covers both
`write(2)`-style access (`security_file_permission`) and shared writable
mappings (`security_mmap_file`).

`selectors` use the same syntax as kprobe selectors. Process filters are
combined with the path filter, so the policy only emits events for matching
processes and paths.

## Event

File integrity events are emitted as `process_file_integrity`:

```json
{
  "process_file_integrity": {
    "process": {
      "binary": "/usr/bin/vi",
      "arguments": "/etc/passwd"
    },
    "path": "/etc/passwd",
    "operation": "write",
    "digest": "sha256:...",
    "policy_name": "file-integrity-monitoring",
    "message": "critical file was modified",
    "function_name": "security_file_permission"
  }
}
```

For renames, `path` is the destination and `old_path` is the original path.
The digest is best effort and is empty when the agent cannot read the file.
