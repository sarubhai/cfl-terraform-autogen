#!/bin/bash
# cfl-tf-autogen.sh
# Owner: Saurav Mitra
# Description: This shell script will generate main.tf, variables.tf & terraform.tfstate with Terraform best practices
# for Cloudflare resources for a zone as returned by Cloudflare API
# Reference:
# https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs
# https://api.cloudflare.com/
# https://www.terraform.io/docs/cloud/api/index.html

START_TIME=`date "+%F | %H:%M:%S"`

#~~~~~~~~~~~~~~~~~#
# Cloudflare Config
#~~~~~~~~~~~~~~~~~#
# export CLOUDFLARE_ACCOUNT_ID="12abc34abcde56uv7890x1a1a10abc10"
# export CLOUDFLARE_API_KEY="1234abc1d567z12s1234z0a1a1abcdef7wxyz"
# export CLOUDFLARE_EMAIL="john.doe@example.com"

#~~~~~~~~~~~#
# Site Config
#~~~~~~~~~~~#
# export DOMAIN_NAME="example.com"

#~~~~~~~~~~~~~~~~#
# Terraform Config
#~~~~~~~~~~~~~~~~#
# export ORGANIZATION_NAME="example-demo"
# export TF_TOKEN="abOAB1XYZaZ7aZ.abcdef1.11xXmno7ZFZj8Sorr4zOeWweitYCQeQXr7FFXabZuv0AB7YZxPXuQUKmd9gKN4W3AyQ"
export WORKSPACE_NAME=`echo ${DOMAIN_NAME} | sed -e "s/\./-/g"`


# cURL Headers
export CF_API="https://api.cloudflare.com/client/v4"
declare -a CF_HEADER=('-H' "Content-Type:application/json" '-H' "X-Auth-Email:${CLOUDFLARE_EMAIL}" '-H' "X-Auth-Key:${CLOUDFLARE_API_KEY}")
export TF_API="https://app.terraform.io/api/v2"
declare -a TF_HEADER=('-H' "Content-Type:application/vnd.api+json" '-H' "Authorization: Bearer ${TF_TOKEN}")


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
# Shell Settings:
# Generic Functions to write configurations
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
function main () {
  echo "${@}" >> main.tf
}

function variables () {
  echo "${@}" >> variables.tf
}

function tfvars () {
  echo "${@}" >> terraform.tfvars
}

function info () {
  echo "`date "+%F %H:%M:%S"` |  ${@}" >> info.txt
}

function interrupt () {
  echo "Press [ENTER] to continue"
  read -s key
}


# CLEANUP (REMOVE LATER) #
rm -rf main.tf variables.tf terraform.tfvars outputs.tf terraform.tfstate terraform.tfstate.backup .terraform.lock.hcl .terraform
rm -rf scripts info.txt before.json after.json .gitignore

# ----------------------------------------------------------------------------------------------

#########################
# Terraform Configuration
#########################
# Terraform Settings
main "# Configure Terraform"
main "terraform {"
main "  required_providers {"
main "    cloudflare = {"
main "      source  = \"cloudflare/cloudflare\""
main "      version = \"2.18.0\""
main "    }"
main "  }"
main "}"
main ""


# Provider Settings
main "# Configure Cloudflare Provider"
main "provider \"cloudflare\" {"
main "}"
main ""

# Initialize Provider
info "Initializing Terraform & Cloudflare Providers"
terraform init



#################
# CLOUDFLARE ZONE
#################
CLOUDFLARE_ZONE=`curl -s -X GET "${CF_API}/zones?name=${DOMAIN_NAME}" "${CF_HEADER[@]}" | jq ".result[0]"`
CLOUDFLARE_ZONE_ID=`echo $CLOUDFLARE_ZONE | jq ".id" | tr -d '"'`
DOMAIN_PLAN=`echo ${CLOUDFLARE_ZONE} | jq '.plan.legacy_id' | tr -d '"'`
# CONFIG
main "# Cloudflare Zone"
main "resource \"cloudflare_zone\" \"site\" {"
main "  zone = var.domain_name"
main "  plan = var.domain_plan"
main "  type = `echo ${CLOUDFLARE_ZONE} | jq '.type'`"
main "}"
main ""


# VARIABLES
variables "# Cloudflare Zone"
variables "variable \"domain_name\" {"
variables "  description = \"The DNS zone or Domain name.\""
variables "}"
variables ""

variables "variable \"domain_plan\" {"
variables "  description = \"The name of the commercial plan to apply to the zone.\""
variables "  default     = \"${DOMAIN_PLAN}\""
variables "}"
variables ""


# SENSITIVE VARIABLES
tfvars "domain_name = \"${DOMAIN_NAME}\""


# IMPORT STATE
terraform plan | grep Plan:
info "cloudflare_zone_id: ${CLOUDFLARE_ZONE_ID}"
terraform import cloudflare_zone.site ${CLOUDFLARE_ZONE_ID}



##########################
# CLOUDFLARE ZONE SETTINGS
##########################
ZONE_SETTINGS=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/settings" "${CF_HEADER[@]}" | jq`
echo $ZONE_SETTINGS | jq >> before.json
ZONE_SETTING_COUNT=`echo ${ZONE_SETTINGS} | jq ".result" | jq length`

# CONFIG
main "# Zone Settings"
main "resource \"cloudflare_zone_settings_override\" \"site_settings\" {"
main "  zone_id = cloudflare_zone.site.id"
main "  settings {"

for (( n=0; n<${ZONE_SETTING_COUNT}; n++ ))
do
    SETTING=`echo ${ZONE_SETTINGS} | jq ".result[${n}]"`
    KEY=`echo ${SETTING} | jq ".id" | tr -d '"'`
    VALUE=`echo ${SETTING} | jq ".value"`
    EDITABLE=`echo ${SETTING} | jq ".editable"`
    if [ "${EDITABLE}" == "true" ]
    then
        if [ "${KEY}" == "tls_1_2_only" ] || [ "${KEY}" == "0rtt" ] || [ "${KEY}" == "ciphers" ] || [ "${KEY}" == "edge_cache_ttl" ] || [ "${KEY}" == "log_to_cloudflare" ] || [ "${KEY}" == "orange_to_orange" ] || [ "${KEY}" == "visitor_ip" ]
        then
            echo "Excluding Cloudflare Unsupported argument"
        elif [ "${KEY}" == "minify" ]
        then
            main "    ${KEY} {"
            CSS=`echo ${VALUE} | jq ".css"`
            main "      css = ${CSS}"
            HTML=`echo ${VALUE} | jq ".html"`
            main "      html = ${HTML}"
            JS=`echo ${VALUE} | jq ".js"`
            main "      js = ${JS}"
            main "    }"
        elif [ "${KEY}" == "mobile_redirect" ]
        then
            main "    ${KEY} {"
            MOBILE_SUBDOMAIN=`echo ${VALUE} | jq ".mobile_subdomain" | sed -e "s/null/\"\"/g"`
            main "      mobile_subdomain = ${MOBILE_SUBDOMAIN}"
            STATUS=`echo ${VALUE} | jq ".status"`
            main "      status = ${STATUS}"
            STRIP_URI=`echo ${VALUE} | jq ".strip_uri"`
            main "      strip_uri = ${STRIP_URI}"
            main "    }"
        elif [ "${KEY}" == "security_header" ]
        then
            main "    ${KEY} {"
            ENABLED=`echo ${VALUE} | jq ".strict_transport_security.enabled"`
            main "      enabled = ${ENABLED}"
            INCLUDE_SUBDOMAINS=`echo ${VALUE} | jq ".strict_transport_security.include_subdomains"`
            main "      include_subdomains = ${INCLUDE_SUBDOMAINS}"
            MAX_AGE=`echo ${VALUE} | jq ".strict_transport_security.max_age"`
            main "      max_age = ${MAX_AGE}"
            NOSNIFF=`echo ${VALUE} | jq ".strict_transport_security.nosniff"`
            main "      nosniff = ${NOSNIFF}"
            PRELOAD=`echo ${VALUE} | jq ".strict_transport_security.preload"`
            main "      preload = ${PRELOAD}"
            main "    }"
        else
            main "    ${KEY} = ${VALUE}"
        fi
    fi
done

main "  }"
main "}"
main ""


# APPLY SETTINGS & MANAGE STATE
terraform plan | grep Plan:
terraform apply -auto-approve -refresh=false

ZONE_SETTINGS=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/settings" "${CF_HEADER[@]}" | jq`
echo $ZONE_SETTINGS | jq >> after.json

SETTINGS_DIFF_COUNT=`diff -U 0 before.json after.json | grep ^@ | wc -l`
if [ $SETTINGS_DIFF_COUNT != 2 ]
then
    echo "WARNING: Zone Settings Before & After is Different"
    info "WARNING: Zone Settings Before & After is Different"
else
    echo "NOTE: Zone Settings Before & After is Same"
    info "NOTE: Zone Settings Before & After is Same"
fi



###################
# CLOUDFLARE RECORD
###################
RECORDS=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/dns_records" "${CF_HEADER[@]}" | jq`
RECORD_COUNT=`echo ${RECORDS} | jq ".result" | jq length`
info "Count of Records: ${RECORD_COUNT}"

main "# Cloudflare Records"

for (( n=0; n<${RECORD_COUNT}; n++ ))
do
    index=`expr $n + 1`
    RECORD=`echo ${RECORDS} | jq ".result[${n}]"`
    RECORD_ID=`echo ${RECORD} | jq ".id" | tr -d '"'`
    RECORD_NAME=`echo ${RECORD} | jq ".name" | tr -d '"'`
    if [ ${RECORD_NAME} != ${DOMAIN_NAME} ]
    then
        RECORD_NAME=`echo $RECORD_NAME | sed -e "s/${DOMAIN_NAME}//g" | sed 's/.$//'`
    fi

    info "cloudflare_record_${index}:${RECORD_NAME} - ${RECORD_ID}"

    # CONFIG
    main "resource \"cloudflare_record\" \"record${index}\" {"
    main "  zone_id = cloudflare_zone.site.id"
    main "  name    = \"${RECORD_NAME}\""
    main "  value   = `echo ${RECORD} | jq ".content"`"
    main "  type    = `echo ${RECORD} | jq ".type"`"
    main "  ttl     = `echo ${RECORD} | jq ".ttl"`"
    main "  proxied = `echo ${RECORD} | jq ".proxied"`"
    main "}"
    main ""


    # IMPORT STATE
    terraform plan -refresh=false | grep Plan:
    terraform import cloudflare_record.record${index} ${CLOUDFLARE_ZONE_ID}/${RECORD_ID}
done



###################################
# CLOUDFLARE FIREWALL RULE & FILTER
###################################
RULES=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/firewall/rules" "${CF_HEADER[@]}" | jq`
RULE_COUNT=`echo ${RULES} | jq ".result" | jq length`
info "Count of Rules: ${RULE_COUNT}"

# CONFIG
main "# Filter"
main "resource \"cloudflare_filter\" \"firewall_filter\" {"
main "  for_each = var.filters"
main ""
main "  zone_id     = cloudflare_zone.site.id"
# Remove Below in DBS
main "  description = each.value[\"description\"]"
main "  expression  = each.value[\"expression\"]"
# Remove Below in DBS
main "  ref         = each.key"
main "}"
main ""

main "# Firewall Rule"
main "resource \"cloudflare_firewall_rule\" \"firewall_rule\" {"
main "  for_each = var.filters"
main ""
main "  zone_id     = cloudflare_zone.site.id"
main "  description = each.value[\"description\"]"
main "  filter_id   = cloudflare_filter.firewall_filter[each.key].id"
main "  action      = each.value[\"action\"]"
main "  priority    = each.value[\"priority\"]"
main "  paused      = each.value[\"paused\"]"
main "}"
main ""


# VARIABLES
variables "# Firewall Rule Filters"
variables "variable \"filters\" {"
variables "  description = \"Firewall Rule with Filters.\""
variables "  type        = map(any)"
variables "  default = {"

for (( n=0; n<${RULE_COUNT}; n++ ))
do
    index=`expr $n + 1`
    RULE=`echo ${RULES} | jq ".result[${n}]"`
    V_RULE="filter${index} = { description = `echo ${RULE} | jq ".description"`, expression = `echo ${RULE} | jq ".filter.expression"`, action = `echo ${RULE} | jq ".action"`, priority = `echo ${RULE} | jq ".priority"`, paused = `echo ${RULE} | jq ".paused"` }"
    variables "    ${V_RULE}"
done

variables "  }"
variables "}"
variables ""


# IMPORT STATE
terraform plan -refresh=false | grep Plan:
for (( n=0; n<${RULE_COUNT}; n++ ))
do
    index=`expr $n + 1`
    RULE=`echo ${RULES} | jq ".result[${n}]"`
    FILTER_REF="filter${index}"
 
    CLOUDFLARE_FILTER_ID=`echo $RULE | jq ".filter.id" | tr -d '"'`
    info "cloudflare_filter_id[${n}]: ${CLOUDFLARE_FILTER_ID}"
    terraform import cloudflare_filter.firewall_filter[\"${FILTER_REF}\"] ${CLOUDFLARE_ZONE_ID}/${CLOUDFLARE_FILTER_ID}
    
    CLOUDFLARE_RULE_ID=`echo $RULE | jq ".id" | tr -d '"'`
    info "cloudflare_rule_id[${n}]: ${CLOUDFLARE_RULE_ID}"
    terraform import cloudflare_firewall_rule.firewall_rule[\"${FILTER_REF}\"] ${CLOUDFLARE_ZONE_ID}/${CLOUDFLARE_RULE_ID}
done



############################
# CLOUDFLARE WAF GROUP RULES
############################
# CONFIG
# Cloudflare WAF
main "# Cloudflare WAF Rule Groups"
main "data \"cloudflare_waf_groups\" \"cloudflare_waf\" {"
main "  zone_id = cloudflare_zone.site.id"
main "  filter {"
main "    name = \".*Cloudflare.*\""
main "  }"
main "}"
main ""

main "resource \"cloudflare_waf_group\" \"cloudflare_waf_group\" {"
main "  count    = length(data.cloudflare_waf_groups.cloudflare_waf.groups)"
main "  zone_id  = cloudflare_zone.site.id"
main "  group_id = data.cloudflare_waf_groups.cloudflare_waf.groups[count.index].id"
main "  mode     = \"on\""
main "}"
main ""


# OWASP WAF
main "# OWASP WAF Rule Groups"
main "data \"cloudflare_waf_groups\" \"owasp_waf\" {"
main "  zone_id = cloudflare_zone.site.id"
main "  filter {"
main "    name = \".*OWASP.*\""
main "  }"
main "}"
main ""

main "resource \"cloudflare_waf_group\" \"owasp_waf_group\" {"
main "  count    = length(data.cloudflare_waf_groups.owasp_waf.groups)"
main "  zone_id  = cloudflare_zone.site.id"
main "  group_id = data.cloudflare_waf_groups.owasp_waf.groups[count.index].id"
main "  mode     = \"on\""
main "}"
main ""


# IMPORT STATE
terraform plan | grep Plan:
CLOUDFLARE_PACKAGE_ID=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/firewall/waf/packages?name=CloudFlare" "${CF_HEADER[@]}" | jq '.result[0].id' | tr -d '"'`
info "cloudflare_package_id: ${CLOUDFLARE_PACKAGE_ID}"

CLOUDFLARE_GROUPS=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/firewall/waf/packages/${CLOUDFLARE_PACKAGE_ID}/groups" "${CF_HEADER[@]}" | jq`

count=`echo $CLOUDFLARE_GROUPS | jq '.result | length'`
for (( n=0; n<count; n++ ))
do
  RULE_GROUP_ID=`echo $CLOUDFLARE_GROUPS | jq ".result[${n}].id" | tr -d '"'`
  info "cloudflare_group_id_${n}: ${RULE_GROUP_ID}"

  terraform import cloudflare_waf_group.cloudflare_waf_group[${n}] ${CLOUDFLARE_ZONE_ID}/${RULE_GROUP_ID}
done


terraform plan | grep Plan:
OWASP_PACKAGE_ID=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/firewall/waf/packages?name=OWASP" "${CF_HEADER[@]}" | jq '.result[0].id' | tr -d '"'`
info  "owasp_package_id: ${OWASP_PACKAGE_ID}"

OWASP_GROUPS=`curl -s -X GET "${CF_API}/zones/${CLOUDFLARE_ZONE_ID}/firewall/waf/packages/${OWASP_PACKAGE_ID}/groups" "${CF_HEADER[@]}" | jq`

count=`echo $OWASP_GROUPS | jq '.result | length'`
for (( n=0; n<count; n++ ))
do
  RULE_GROUP_ID=`echo $OWASP_GROUPS | jq ".result[${n}].id" | tr -d '"'`
  info "owasp_group_id_${n}: ${RULE_GROUP_ID}"

  terraform import cloudflare_waf_group.owasp_waf_group[${n}] ${CLOUDFLARE_ZONE_ID}/${RULE_GROUP_ID}
done



##########################
# CLOUDFLARE WORKER SCRIPT
##########################
# CONFIG
main "# Worker Script"
main "resource \"cloudflare_worker_script\" \"worker_script\" {"
main "  for_each = fileset(\"\${path.module}/scripts\", \"*.js\")"
main ""
main "  name    = trim(each.value, \".js\")"
main "  content = file(\"\${path.module}/scripts/\${each.value}\")"
main "}"
main ""


SCRIPT_DIR=scripts
mkdir ${SCRIPT_DIR}

# SCRIPTS
SCRIPTS=`curl -s -X GET "${CF_API}/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts" "${CF_HEADER[@]}" | jq`
SCRIPT_COUNT=`echo ${SCRIPTS} | jq ".result" | jq length`
info "Count of Scripts: ${SCRIPT_COUNT}"

for (( n=0; n<${SCRIPT_COUNT}; n++ ))
do
    SCRIPT=`echo ${SCRIPTS} | jq ".result[${n}]"`
    SCRIPT_NAME=`echo ${SCRIPT} | jq ".id" | tr -d '"'`
    SCRIPT_FILE=`echo "${SCRIPT_NAME}.js"`
    echo "worker_script_${FILENAME}_script: ${SCRIPT_NAME}"

    SCRIPT_CONTENT=`curl -s -X GET "${CF_API}/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}" "${CF_HEADER[@]}"`
    
    # Write WorkerScript to file
    echo -n "${SCRIPT_CONTENT}" > ${SCRIPT_DIR}/${SCRIPT_FILE}
    # printf "${SCRIPT_CONTENT}" > ${SCRIPT_DIR}/${SCRIPT_FILE}
    
    # IMPORT STATE
    terraform plan -refresh=false | grep Plan:
    terraform import cloudflare_worker_script.worker_script[\"${SCRIPT_FILE}\"] ${SCRIPT_NAME}
done


# FINALIZING IMPORT
terraform plan | grep Plan:
info "terraform plan"
terraform plan >> info.txt



#################################
# Terraform Backend Configuration
#################################
# Terraform Backend
main "# Terraform Backend"
main "terraform {"
main "  backend \"remote\" {"
main "    hostname     = \"app.terraform.io\""
main "    organization = \"${ORGANIZATION_NAME}\""
main ""
main "    workspaces {"
main "      name = \"${WORKSPACE_NAME}\""
main "    }"
main "  }"
main "}"
main ""


# FORMAT FILES
terraform fmt
# INITIALIZE BACKEND
terraform init
# REMOVE LOCAL STATE FILE
rm -rf terraform.tfstate terraform.tfstate.backup


#####################
# Workspace Variables
#####################
WORKSPACE=`curl -s -X GET "${TF_API}/organizations/${ORGANIZATION_NAME}/workspaces/${WORKSPACE_NAME}" "${TF_HEADER[@]}" | jq`
WORKSPACE_ID=`echo ${WORKSPACE} | jq ".data".id | tr -d '"'`
info "workspace_id: ${WORKSPACE_ID}"

# Environment Variables
payload="{\"data\": {\"type\":\"vars\",\"attributes\": {\"key\":\"CLOUDFLARE_EMAIL\",\"value\":\"${CLOUDFLARE_EMAIL}\",\
\"description\":\"The email associated with the Cloudflare account.\",\"category\":\"env\",\"hcl\":false,\"sensitive\":true}}}"
curl -s -X POST "${TF_API}/workspaces/${WORKSPACE_ID}/vars" "${TF_HEADER[@]}" -d  "${payload}" | jq

payload="{\"data\": {\"type\":\"vars\",\"attributes\": {\"key\":\"CLOUDFLARE_API_KEY\",\"value\":\"${CLOUDFLARE_API_KEY}\",\
\"description\":\"The Cloudflare API key.\",\"category\":\"env\",\"hcl\":false,\"sensitive\":true}}}"
curl -s -X POST "${TF_API}/workspaces/${WORKSPACE_ID}/vars" "${TF_HEADER[@]}" -d  "${payload}" | jq

payload="{\"data\": {\"type\":\"vars\",\"attributes\": {\"key\":\"CLOUDFLARE_ACCOUNT_ID\",\"value\":\"${CLOUDFLARE_ACCOUNT_ID}\",\
\"description\":\"The Cloudflare Account ID.\",\"category\":\"env\",\"hcl\":false,\"sensitive\":true}}}"
curl -s -X POST "${TF_API}/workspaces/${WORKSPACE_ID}/vars" "${TF_HEADER[@]}" -d  "${payload}" | jq

payload="{\"data\": {\"type\":\"vars\",\"attributes\": {\"key\":\"CLOUDFLARE_API_CLIENT_LOGGING\",\"value\":\"true\",\
\"description\":\"Print logs from the API client.\",\"category\":\"env\",\"hcl\":false,\"sensitive\":false}}}"
curl -s -X POST "${TF_API}/workspaces/${WORKSPACE_ID}/vars" "${TF_HEADER[@]}" -d  "${payload}" | jq


# Terraform Variables
payload="{\"data\": {\"type\":\"vars\",\"attributes\": {\"key\":\"domain_plan\",\"value\":\"${DOMAIN_PLAN}\",\
\"description\":\"The name of the commercial plan to apply to the zone.\",\"category\":\"terraform\",\"hcl\":false,\"sensitive\":false}}}"
curl -s -X POST "${TF_API}/workspaces/${WORKSPACE_ID}/vars" "${TF_HEADER[@]}" -d  "${payload}" | jq

payload="{\"data\": {\"type\":\"vars\",\"attributes\": {\"key\":\"domain_name\",\"value\":\"${DOMAIN_NAME}\",\
\"description\":\"The DNS zone or Domain name.\",\"category\":\"terraform\",\"hcl\":false,\"sensitive\":false}}}"
curl -s -X POST "${TF_API}/workspaces/${WORKSPACE_ID}/vars" "${TF_HEADER[@]}" -d  "${payload}" | jq


VARIABLES=`curl -s -X GET "${TF_API}/workspaces/${WORKSPACE_ID}/vars" "${TF_HEADER[@]}" | jq`
VARIABLE_COUNT=`echo ${VARIABLES} | jq ".data" | jq length`
info "Workspace variables count: ${VARIABLE_COUNT}"



################
# Add Git Ignore
################
echo "# Local .terraform directories"   > .gitignore
echo "**/.terraform/*"                  >> .gitignore
echo ""                                 >> .gitignore
echo "# Exclude all .tfstate files"     >> .gitignore
echo "*.tfstate"                        >> .gitignore
echo "*.tfstate.*"                      >> .gitignore
echo ""                                 >> .gitignore
echo "# Crash log files"                >> .gitignore
echo "crash.log"                        >> .gitignore
echo ""                                 >> .gitignore
echo "# Exclude all .tfvars files, which are likely to contain sentitive data" >> .gitignore
echo "*.tfvars"                         >> .gitignore
echo ""                                 >> .gitignore
echo "# Ignore override files as they are usually used to override resources locally" >> .gitignore
echo "override.tf"                      >> .gitignore
echo "override.tf.json"                 >> .gitignore
echo "*_override.tf"                    >> .gitignore
echo "*_override.tf.json"               >> .gitignore
echo ""                                 >> .gitignore
echo "# Include tfplan files to ignore the plan output of command: terraform plan -out=tfplan" >> .gitignore
echo "*tfplan*"                         >> .gitignore
echo ""                                 >> .gitignore
echo "# Ignore CLI configuration files" >> .gitignore
echo ".terraformrc"                     >> .gitignore
echo "terraform.rc"                     >> .gitignore
echo ""                                 >> .gitignore
echo "# Ignore auto generated files"    >> .gitignore
echo "auto.sh"                          >> .gitignore
echo "info.txt"                         >> .gitignore
echo "before.json"                      >> .gitignore
echo "after.json"                       >> .gitignore




END_TIME=`date "+%F | %H:%M:%S"`

echo "############################"
echo "Script execution completed"
echo "Start: ${START_TIME}"
echo "End:   ${END_TIME}"
echo "############################"
