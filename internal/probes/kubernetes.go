package probes

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// K8sEnv maps a workload ("kind/name") to the environment references it
// declares — env names, secretKeyRef keys, configMapKeyRef keys, and
// envFrom secret/configmap names. Names only; values never exist here.
type K8sEnv map[string][]string

var k8sWorkloadKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true, "Pod": true, "ReplicaSet": true,
}

// K8sManifests walks dir for YAML files containing Kubernetes workload
// manifests and extracts every env reference each workload declares:
// "env:NAME" for plain entries, "secret:NAME" and "configmap:NAME" for
// valueFrom/envFrom references.
func K8sManifests(dir string) K8sEnv {
	out := K8sEnv{}
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if err == nil && d.IsDir() && (d.Name() == ".github" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// Cheap gate: k8s manifests all carry kind:/apiVersion:.
		if !strings.Contains(string(b), "kind:") || !strings.Contains(string(b), "apiVersion:") {
			return nil
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		for {
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				break
			}
			kind, _ := doc["kind"].(string)
			if !k8sWorkloadKinds[kind] {
				continue
			}
			meta, _ := doc["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			if name == "" {
				name = filepath.Base(path)
			}
			refs := k8sEnvRefs(doc)
			if len(refs) > 0 {
				out[kind+"/"+name] = refs
			}
		}
		return nil
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// k8sEnvRefs collects env references from every container env list in a
// workload document — walks the whole tree, so pod template nesting
// (spec.template.spec.containers) needs no special casing.
func k8sEnvRefs(doc map[string]any) []string {
	set := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		m, ok := v.(map[string]any)
		if !ok {
			if list, ok := v.([]any); ok {
				for _, item := range list {
					walk(item)
				}
			}
			return
		}
		// env list entries: {name: X} or {name: X, valueFrom: {…Ref: {name,key}}}
		if name, ok := m["name"].(string); ok {
			if _, hasVal := m["value"]; hasVal {
				set["env:"+name] = true
			}
			if vf, ok := m["valueFrom"].(map[string]any); ok {
				k8sRefFrom(vf, name, set)
			}
		}
		if vf, ok := m["valueFrom"].(map[string]any); ok {
			k8sRefFrom(vf, "", set)
		}
		if ef, ok := m["envFrom"].([]any); ok {
			for _, item := range ef {
				if em, ok := item.(map[string]any); ok {
					k8sRefFrom(em, "", set)
				}
			}
		}
		for _, v := range m {
			walk(v)
		}
	}
	walk(doc)
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// k8sRefFrom reads secretKeyRef/configMapKeyRef/secretRef/configMapRef
// entries out of a valueFrom or envFrom map.
func k8sRefFrom(m map[string]any, envName string, set map[string]bool) {
	for key, prefix := range map[string]string{
		"secretKeyRef":    "secret",
		"secretRef":       "secret",
		"configMapKeyRef": "configmap",
		"configMapRef":    "configmap",
	} {
		ref, ok := m[key].(map[string]any)
		if !ok {
			continue
		}
		name, _ := ref["name"].(string)
		if key2, _ := ref["key"].(string); key2 != "" && envName != "" {
			set[prefix+":"+name+"/"+key2] = true
			set["env:"+envName] = true
		} else if name != "" {
			set[prefix+":"+name] = true
		}
	}
}
