# cfl-terraform-autogen
Auto Generation of Terraform Configuration &amp; State files for existing Cloudflare Zones.

## Features

- Auto Generation of Terraform Configuration, Variable & State files for Clouflare service provider
- Import existing Cloudflare resources for a zones under Terraform management
- Terraform Best Practices for efficient Resource management
- Automatically upload the configuration to Terraform Cloud Workspace
- Simple shell script based Utility using terraform cli & curl

### Reference
Cloudflare Provider
- [https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs)

Cloudflare API
- [https://api.cloudflare.com/](https://api.cloudflare.com/)

Terraform Cloud API
- [https://www.terraform.io/docs/cloud/api/index.html](https://www.terraform.io/docs/cloud/api/index.html)

Cloudflare Global API Key	
- [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)

Terraform User Api Token
- [https://app.terraform.io/app/settings/tokens](https://app.terraform.io/app/settings/tokens)


### Prerequisite
- Terraform CLI already installed
- Terraform Login using User token can connect to Terraform Cloud

### Usage
Replace the variable values accordingly

```
# Create a working directory
mkdir example-com
cd example-com

# Download the autogen file
curl -s https://raw.githubusercontent.com/sarubhai/cfl-terraform-autogen/master/cfl-tf-autogen.sh -o cfl-tf-autogen.sh
chmod +x cfl-tf-autogen.sh

# Cloudflare Config
export CLOUDFLARE_ACCOUNT_ID="12abc34abcde56uv7890x1a1a10abc10"
export CLOUDFLARE_API_KEY="1234abc1d567z12s1234z0a1a1abcdef7wxyz"
export CLOUDFLARE_EMAIL="john.doe@example.com"

# Site Config
export DOMAIN_NAME="example.com"

# Terraform Config
export ORGANIZATION_NAME="example-demo"
export TF_TOKEN="abOAB1XYZaZ7aZ.abcdef1.11xXmno7ZFZj8Sorr4zOeWweitYCQeQXr7FFXabZuv0AB7YZxPXuQUKmd9gKN4W3AyQ"

./cfl-tf-autogen.sh

```

Check the output of the autogen script in info.txt file

### Cloudflare Resources
The following resources are being handled currently:

- cloudflare_zone
- cloudflare_zone_settings_override
- cloudflare_record
- cloudflare_filter
- cloudflare_firewall_rule
- cloudflare_waf_group
- cloudflare_worker_script



