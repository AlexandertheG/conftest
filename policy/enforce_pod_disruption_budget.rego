package main

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "Deployment"
  to_number(in_kind.spec.replicas) > 1
  not deployment_has_disruption_budget(in_kind)
  msg := sprintf("Consider using PodDisruptionBudget for <%v> <%v>.\nhttps://kubernetes.io/docs/tasks/run-application/configure-pdb/#specifying-a-poddisruptionbudget", [in_kind.kind, in_kind.metadata.name])
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "PodDisruptionBudget"
  has_non_matching_labels(in_kind)
  msg := sprintf("PodDisruptionBudget <%v> selector has no matching Pod template labels in Deployment. Please match them 1:1.", [in_kind.metadata.name])
}

deny[msg] {
  in_kind := input[_].contents
  in_kind.kind == "PodDisruptionBudget"
  has_non_matching_selectors(in_kind)
  msg := sprintf("PodDisruptionBudget <%v> selector has no matching Pod template labels in Deployment. Please match them 1:1.", [in_kind.metadata.name])
}

deployment_has_disruption_budget(deployment) {
  input[_].contents.kind == "PodDisruptionBudget"
}

has_non_matching_labels(pdb) {
  in_kind := input[_].contents
  in_kind.kind == "Deployment"
  pdb_matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
  depl_labels := { [label, value] | some label; value := in_kind.spec.template.metadata.labels[label] }
  count(depl_labels - pdb_matchLabels) > 0
}

has_non_matching_selectors(pdb) {
  in_kind := input[_].contents
  in_kind.kind == "Deployment"
  pdb_matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
  depl_labels := { [label, value] | some label; value := in_kind.spec.template.metadata.labels[label] }
  count(pdb_matchLabels - depl_labels) > 0
}
