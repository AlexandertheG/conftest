package main

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "StatefulSet"
  in_kind.spec.replicas != 1
  not in_kind.spec.template.spec.affinity.podAntiAffinity
  msg := sprintf("Consider using podAntiAffinity in StatefulSet <%v>.\nRefer to https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#more-practical-use-cases", [in_kind.metadata.name])
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "Deployment"
  in_kind.spec.replicas != 1
  not in_kind.spec.template.spec.affinity.podAntiAffinity
  msg := sprintf("Consider using podAntiAffinity in Deployment <%v>.\nRefer to https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#more-practical-use-cases", [in_kind.metadata.name])
}
