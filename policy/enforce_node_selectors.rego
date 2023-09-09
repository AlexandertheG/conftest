package main

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "Deployment"
  not in_kind.spec.template.spec.nodeSelector.nodetype == "worker"
  msg := sprintf("<%v> <%v> is missing nodeSelector nodetype: \"worker\"", [in_kind.kind, in_kind.metadata.name])
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "StatefulSet"
  not in_kind.spec.template.spec.nodeSelector.nodetype == "worker"
  msg := sprintf("<%v> <%v> is missing nodeSelector nodetype: \"worker\"", [in_kind.kind, in_kind.metadata.name])
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "ReplicaSet"
  not in_kind.spec.template.spec.nodeSelector.nodetype == "worker"
  msg := sprintf("<%v> <%v> is missing nodeSelector nodetype: \"worker\"", [in_kind.kind, in_kind.metadata.name])
}
