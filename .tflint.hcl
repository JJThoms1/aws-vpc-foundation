plugin "aws" {
  enabled = true
  version = "0.33.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

config {
  module           = true
  force            = false
  call_module_type = "all"
}

rule "terraform_required_providers" { enabled = true }
rule "terraform_standard_module_structure" { enabled = false } # set true if you refactor to modules
