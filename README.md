# cfl-terraform-autogen
Auto Generation of Terraform Configuration &amp; State files for existing Cloudflare Zones.

## Features

- Auto Generation of Terraform Configuration, Variable & State files for Clouflare service provider
- Import existing Cloudflare resources for a zones under Terraform management
- Terraform Best Practices for efficient Resource management
- Automatically upload the configuration to Terraform Cloud Workspace
- Simple shell script based Utility using terraform cli & curl

### Reference
- `https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs`
- `https://api.cloudflare.com/`
- `https://www.terraform.io/docs/cloud/api/index.html`


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
