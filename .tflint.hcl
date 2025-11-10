plugin "aws" {
  enabled = true
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
  # You can pin, or let it pick a compatible version. Pin if CI needs reproducibility:
  version = "0.33.0"
}

config {
  force            = false
  call_module_type = "all"
}

rule "terraform_required_providers"        { enabled = true  }
rule "terraform_standard_module_structure" { enabled = false }
