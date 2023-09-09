package main

deny[msg] {
  resource_violation[{"msg": msg}]          
}

resource_violation[{"msg": msg}] {
  in_kind := input[_].contents
  container := in_kind.spec.template.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("Container <%v> in <%v> <%v> has no cpu limits", [container.name, in_kind.kind, in_kind.metadata.name])
}

resource_violation[{"msg": msg}] {
  in_kind := input[_].contents
  container := in_kind.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container <%v> in <%v> <%v> has no memory limits", [container.name, in_kind.kind, in_kind.metadata.name])
}
