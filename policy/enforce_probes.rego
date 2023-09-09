package main

probeTypes := ["tcpSocket", "httpGet", "exec"]
probes := ["readinessProbe", "livenessProbe"]

probe_type_set = probe_types {
  probe_types := {type | type := probeTypes[_]}
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "Deployment"
  container := in_kind.spec.template.spec.containers[_]
  probe := probes[_]
  probe_is_missing(container, probe)
  msg := get_missing_probe_violation_message(container, in_kind, probe)
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "DaemonSet"
  container := in_kind.spec.template.spec.containers[_]
  probe := probes[_]
  probe_is_missing(container, probe)
  msg := get_missing_probe_violation_message(container, in_kind, probe)
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "StatefulSet"
  container := in_kind.spec.template.spec.containers[_]
  probe := probes[_]
  probe_is_missing(container, probe)
  msg := get_missing_probe_violation_message(container, in_kind, probe)
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "ReplicaSet"
  container := in_kind.spec.template.spec.containers[_]
  probe := probes[_]
  probe_is_missing(container, probe)
  msg := get_missing_probe_violation_message(container, in_kind, probe)
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "Pod"
  container := in_kind.spec.containers[_]
  probe := probes[_]
  probe_is_missing(container, probe)
  msg := get_missing_probe_violation_message(container, in_kind, probe)
}

get_missing_probe_violation_message(container, input_obj, probe) = msg {
  msg := sprintf("Container <%v> in <%v> <%v> has no <%v>", [container.name, input_obj.kind, input_obj.metadata.name, probe])
}

probe_is_missing(ctr, probe) = true {
  not ctr[probe]
}

probe_is_missing(ctr, probe) = true {
  probe_field_empty(ctr, probe)
}

probe_field_empty(ctr, probe) = true {
  probe_fields := {field | ctr[probe][field]}
  diff_fields := probe_type_set - probe_fields
  count(diff_fields) == count(probe_type_set)
}


