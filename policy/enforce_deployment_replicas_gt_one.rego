package main

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "Deployment"
  to_number(in_kind.spec.replicas) < 2
  msg := sprintf("Consider increasing number of replicas in <%v> <%v>", [in_kind.kind, in_kind.metadata.name])
}
