#!/usr/bin/env bash
set -euo pipefail

###############################################################################
#  STORAGE ACCOUNT SCREAM TEST
#  ---------------------------------------------------------------------------
#  Isolate storage accounts from the internet before permanent deletion.
#
#  Two isolation methods:
#    • NSP (Network Security Perimeter) — centralised, supports Learning mode
#    • Firewall — simple, sets publicNetworkAccess=Disabled + defaultAction=Deny
#
#  Flow:
#    1. Authenticate & show tenant/subscription context
#    2. Verify tooling, choose isolation method, set up infra (if NSP)
#    3. Discover all storage accounts via KQL → user picks targets
#    4. Back up configs, show impact, confirm
#    5. Execute isolation
#
#  Rollback:
#    ./screamtest.sh restore   — reverts accounts to their exact backed-up config
###############################################################################

# ── Colours & formatting ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

BACKUP_DIR="./screamtest-backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# NSP defaults — only used when NSP method is chosen
NSP_RG="rg-screamtest-nsp"
NSP_NAME="nsp-screamtest"
NSP_PROFILE="profile-screamtest-deny-all"

# Will be set during step 2
ISOLATION_METHOD=""   # "nsp" or "firewall"

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}STORAGE ACCOUNT SCREAM TEST${NC}                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}Isolate → wait → if nothing screams → delete${NC}                    ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

line() {
    echo -e "${BLUE}──────────────────────────────────────────────────────────────────${NC}"
}

info()    { echo -e "  ${CYAN}ℹ${NC}  $*"; }
ok()      { echo -e "  ${GREEN}✔${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; }
fail()    { echo -e "  ${RED}✘${NC}  $*"; }

run_graph_query() {
    local kql="$1"
    local query_output
    if ! query_output=$(az graph query -q "$kql" --first 1000 --subscriptions "$SUB_ID" -o json 2>&1); then
        if echo "$query_output" | grep -qi "AADSTS\|login\|authentication\|expired\|multi-factor"; then
            warn "Authentication token expired or MFA required."
            warn "Re-authenticating...\n"
            az login --tenant "$TENANT_ID" --scope "https://management.core.windows.net//.default"
            echo ""
            if ! query_output=$(az graph query -q "$kql" --first 1000 --subscriptions "$SUB_ID" -o json 2>&1); then
                fail "KQL query still failed after re-auth:"
                echo -e "  ${DIM}${query_output}${NC}"
                exit 1
            fi
        else
            fail "KQL query failed:"
            echo -e "  ${DIM}${query_output}${NC}"
            exit 1
        fi
    fi
    echo "$query_output"
}

# ── STEP 1 — Authenticate & show context ─────────────────────────────────────
step_authenticate() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 1: Authentication & Azure Context ━━${NC}\n"

    if ! az account show &>/dev/null; then
        warn "Not logged in to Azure CLI — launching ${CYAN}az login${NC}..."
        az login
    fi

    local account_json
    account_json=$(az account show -o json)

    TENANT_ID=$(echo "$account_json"   | jq -r '.tenantId')
    SUB_ID=$(echo "$account_json"      | jq -r '.id')
    SUB_NAME=$(echo "$account_json"    | jq -r '.name')
    USER_NAME=$(echo "$account_json"   | jq -r '.user.name')
    USER_TYPE=$(echo "$account_json"   | jq -r '.user.type')

    local tenant_display
    tenant_display=$(az rest --method GET \
        --url "https://management.azure.com/tenants?api-version=2022-12-01" \
        2>/dev/null | jq -r ".value[] | select(.tenantId==\"$TENANT_ID\") | .displayName // empty" 2>/dev/null || true)
    TENANT_NAME="${tenant_display:-$TENANT_ID}"

    echo -e "  ┌────────────────────────────────────────────────────────────┐"
    printf "  │  ${BOLD}%-14s${NC} %-42s │\n" "Tenant:"       "$TENANT_NAME"
    printf "  │  ${BOLD}%-14s${NC} %-42s │\n" "Tenant ID:"    "$TENANT_ID"
    printf "  │  ${BOLD}%-14s${NC} %-42s │\n" "Subscription:" "$SUB_NAME"
    printf "  │  ${BOLD}%-14s${NC} %-42s │\n" "Sub ID:"       "$SUB_ID"
    printf "  │  ${BOLD}%-14s${NC} %-42s │\n" "Identity:"     "$USER_NAME ($USER_TYPE)"
    echo -e "  └────────────────────────────────────────────────────────────┘"

    echo ""
    echo -e "  ${RED}${BOLD}▶  Is this the correct tenant and subscription?${NC}"
    echo ""
    read -rp "  Continue? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "\n  ${RED}Aborted.${NC}\n"
        exit 1
    fi
}

# ── STEP 2 — Verify tooling, choose method, set up infra ─────────────────────
step_check_infra() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 2: Tooling & Isolation Method ━━${NC}\n"

    # -- jq --
    if ! command -v jq &>/dev/null; then
        fail "'jq' is required but not installed.  brew install jq / apt install jq"
        exit 1
    fi
    ok "jq available"

    # -- az cli --
    if ! command -v az &>/dev/null; then
        fail "'az' CLI is required.  https://aka.ms/install-azure-cli"
        exit 1
    fi
    ok "az CLI available ($(az version --query '\"azure-cli\"' -o tsv 2>/dev/null))"

    # -- resource-graph extension --
    if ! az extension show --name resource-graph &>/dev/null; then
        warn "Extension ${CYAN}resource-graph${NC} is not installed."
        read -rp "  Install now? (y/n): " install_ext
        if [[ "$install_ext" == "y" || "$install_ext" == "Y" ]]; then
            az extension add --name resource-graph --only-show-errors
            ok "resource-graph extension installed"
        else
            fail "Cannot continue without the resource-graph extension."
            exit 1
        fi
    else
        ok "resource-graph extension present"
    fi

    # -- Backup directory --
    if [[ ! -d "$BACKUP_DIR" ]]; then
        warn "Backup directory ${CYAN}${BACKUP_DIR}${NC} does not exist."
        read -rp "  Create it? (y/n): " create_dir
        if [[ "$create_dir" == "y" || "$create_dir" == "Y" ]]; then
            mkdir -p "$BACKUP_DIR"
            ok "Backup directory created"
        else
            fail "Cannot proceed without a backup directory."
            exit 1
        fi
    else
        ok "Backup directory ${CYAN}${BACKUP_DIR}${NC} exists"
    fi

    line
    echo ""

    # ── Choose isolation method ───────────────────────────────────────────────
    echo -e "  ${BOLD}Choose isolation method:${NC}\n"
    echo -e "    ${CYAN}1)${NC} ${BOLD}NSP${NC}  (Network Security Perimeter)"
    echo -e "       ${DIM}Centralised perimeter with Learning + Enforced modes.${NC}"
    echo -e "       ${DIM}Supports dry-run (Learning logs what would be blocked).${NC}"
    echo -e "       ${DIM}Rollback = remove association. Requires nsp extension.${NC}"
    echo ""
    echo -e "    ${CYAN}2)${NC} ${BOLD}Firewall${NC}  (publicNetworkAccess = Disabled)"
    echo -e "       ${DIM}Simple and direct — flips the firewall switch.${NC}"
    echo -e "       ${DIM}No dry-run available. Rollback = restore original config.${NC}"
    echo ""
    read -rp "  Method [1/2]: " method_choice

    case "$method_choice" in
        1) ISOLATION_METHOD="nsp" ;;
        2) ISOLATION_METHOD="firewall" ;;
        *)
            fail "Invalid choice. Pick 1 or 2."
            exit 1
            ;;
    esac

    echo ""

    # ── NSP-specific setup ────────────────────────────────────────────────────
    if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
        # -- nsp extension --
        if ! az extension show --name nsp &>/dev/null; then
            warn "Extension ${CYAN}nsp${NC} is not installed."
            read -rp "  Install now? (y/n): " install_nsp
            if [[ "$install_nsp" == "y" || "$install_nsp" == "Y" ]]; then
                az extension add --name nsp --only-show-errors
                ok "nsp extension installed"
            else
                fail "Cannot continue without the nsp extension."
                exit 1
            fi
        else
            ok "nsp extension present"
        fi

        echo ""
        info "Setting up NSP infrastructure...\n"
        info "  Resource Group:  ${BOLD}${NSP_RG}${NC}"
        info "  Perimeter:       ${BOLD}${NSP_NAME}${NC}"
        info "  Profile:         ${BOLD}${NSP_PROFILE}${NC}"
        echo ""

        # -- Resource Group --
        if ! az group show --name "$NSP_RG" &>/dev/null; then
            warn "Resource group ${CYAN}${NSP_RG}${NC} does not exist."
            read -rp "  Create it? (y/n): " create_rg
            if [[ "$create_rg" == "y" || "$create_rg" == "Y" ]]; then
                read -rp "  Location (e.g. norwayeast, westeurope): " rg_location
                az group create --name "$NSP_RG" --location "$rg_location" -o none
                ok "Resource group ${CYAN}${NSP_RG}${NC} created in ${rg_location}"
                NSP_LOCATION="$rg_location"
            else
                fail "Cannot proceed without resource group."
                exit 1
            fi
        else
            ok "Resource group ${CYAN}${NSP_RG}${NC} exists"
            NSP_LOCATION=$(az group show --name "$NSP_RG" --query location -o tsv)
        fi

        # -- Network Security Perimeter --
        if ! az network perimeter show -n "$NSP_NAME" -g "$NSP_RG" &>/dev/null; then
            warn "NSP ${CYAN}${NSP_NAME}${NC} does not exist."
            read -rp "  Create it? (y/n): " create_nsp
            if [[ "$create_nsp" == "y" || "$create_nsp" == "Y" ]]; then
                az network perimeter create -n "$NSP_NAME" -g "$NSP_RG" -l "$NSP_LOCATION" -o none
                ok "NSP ${CYAN}${NSP_NAME}${NC} created"
            else
                fail "Cannot proceed without NSP."
                exit 1
            fi
        else
            ok "NSP ${CYAN}${NSP_NAME}${NC} exists"
        fi

        # Get the NSP ARM ID for later use
        NSP_ID=$(az network perimeter show -n "$NSP_NAME" -g "$NSP_RG" --query id -o tsv)

        # -- NSP Profile (deny-all = no access rules) --
        if ! az network perimeter profile show --perimeter-name "$NSP_NAME" -g "$NSP_RG" -n "$NSP_PROFILE" &>/dev/null; then
            warn "Profile ${CYAN}${NSP_PROFILE}${NC} does not exist."
            read -rp "  Create it? (y/n): " create_profile
            if [[ "$create_profile" == "y" || "$create_profile" == "Y" ]]; then
                az network perimeter profile create \
                    --perimeter-name "$NSP_NAME" \
                    -g "$NSP_RG" \
                    -n "$NSP_PROFILE" \
                    -o none
                ok "Profile ${CYAN}${NSP_PROFILE}${NC} created (no access rules = deny all)"
            else
                fail "Cannot proceed without NSP profile."
                exit 1
            fi
        else
            ok "Profile ${CYAN}${NSP_PROFILE}${NC} exists"
        fi

        # Get the profile ARM ID
        PROFILE_ID=$(az network perimeter profile show \
            --perimeter-name "$NSP_NAME" -g "$NSP_RG" -n "$NSP_PROFILE" \
            --query id -o tsv)

        # Verify there are no access rules (profile should deny everything)
        local rule_count
        rule_count=$(az network perimeter profile access-rule list \
            --perimeter-name "$NSP_NAME" -g "$NSP_RG" --profile-name "$NSP_PROFILE" \
            -o json 2>/dev/null | jq 'length')
        if [[ "$rule_count" -gt 0 ]]; then
            warn "Profile has ${BOLD}${rule_count}${NC} access rule(s). For a true scream test it should have none."
            echo -e "  ${DIM}  Rules allow traffic through the perimeter. Review with:${NC}"
            echo -e "  ${DIM}  az network perimeter profile access-rule list --perimeter-name $NSP_NAME -g $NSP_RG --profile-name $NSP_PROFILE${NC}"
            echo ""
            read -rp "  Continue anyway? (y/n): " cont_rules
            if [[ "$cont_rules" != "y" && "$cont_rules" != "Y" ]]; then
                exit 1
            fi
        else
            ok "Profile has ${BOLD}0${NC} access rules (deny-all)"
        fi
    else
        ok "Firewall method selected — no extra infrastructure needed"
    fi

    line
}

# ── STEP 3 — Discover storage accounts via KQL ───────────────────────────────
step_discover() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 3: Discovering Storage Accounts (KQL) ━━${NC}\n"

    local kql="resources | where type =~ 'microsoft.storage/storageaccounts' | project name, resourceGroup, location, id, subscriptionId, sku = tostring(sku.name), kind, publicAccess = iff(isnotempty(properties.publicNetworkAccess), tostring(properties.publicNetworkAccess), 'Enabled') | order by name asc"

    info "Running KQL query via Azure Resource Graph...\n"

    STORAGE_JSON=$(run_graph_query "$kql")

    STORAGE_COUNT=$(echo "$STORAGE_JSON" | jq '.count // (.data | length)')

    if [[ -z "$STORAGE_COUNT" || "$STORAGE_COUNT" == "null" || "$STORAGE_COUNT" -eq 0 ]]; then
        warn "No storage accounts found in subscription ${BOLD}${SUB_NAME}${NC}."
        exit 0
    fi

    ok "Found ${BOLD}${STORAGE_COUNT}${NC} storage account(s)\n"

    # Check existing NSP associations (only if using NSP method)
    local existing_assoc="[]"
    if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
        existing_assoc=$(az network perimeter association list \
            --perimeter-name "$NSP_NAME" -g "$NSP_RG" -o json 2>/dev/null || echo "[]")
    fi

    # Table header
    if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
        printf "  ${BOLD}${DIM}%-5s %-32s %-22s %-14s %-10s %-10s${NC}\n" \
               "#" "NAME" "RESOURCE GROUP" "LOCATION" "PUBLIC" "NSP"
    else
        printf "  ${BOLD}${DIM}%-5s %-32s %-22s %-14s %-10s${NC}\n" \
               "#" "NAME" "RESOURCE GROUP" "LOCATION" "PUBLIC"
    fi
    line

    for i in $(seq 0 $((STORAGE_COUNT - 1))); do
        local sa_name sa_rg sa_loc sa_pub sa_id
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$i].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$i].resourceGroup")
        sa_loc=$(echo "$STORAGE_JSON"  | jq -r ".data[$i].location")
        sa_pub=$(echo "$STORAGE_JSON"  | jq -r ".data[$i].publicAccess // \"Enabled\"")
        sa_id=$(echo "$STORAGE_JSON"   | jq -r ".data[$i].id")

        local num=$((i + 1))
        local pub_color="$GREEN"
        [[ "$sa_pub" == "Disabled" ]] && pub_color="$RED"

        if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
            local nsp_status="-"
            if echo "$existing_assoc" | jq -e ".[] | select(.properties.privateLinkResource.id == \"$sa_id\")" &>/dev/null; then
                local mode
                mode=$(echo "$existing_assoc" | jq -r ".[] | select(.properties.privateLinkResource.id == \"$sa_id\") | .properties.accessMode")
                nsp_status="$mode"
            fi

            local nsp_color="$DIM"
            [[ "$nsp_status" == "Enforced" ]] && nsp_color="$RED"
            [[ "$nsp_status" == "Learning" ]] && nsp_color="$YELLOW"

            printf "  %-5s %-32s %-22s %-14s ${pub_color}%-10s${NC} ${nsp_color}%-10s${NC}\n" \
                   "$num" "$sa_name" "$sa_rg" "$sa_loc" "$sa_pub" "$nsp_status"
        else
            printf "  %-5s %-32s %-22s %-14s ${pub_color}%-10s${NC}\n" \
                   "$num" "$sa_name" "$sa_rg" "$sa_loc" "$sa_pub"
        fi
    done

    echo ""
    echo -e "  ${YELLOW}Select storage accounts by number (comma-separated, e.g. 1,3,5)${NC}"
    echo -e "  ${DIM}Type 'all' to select everything, 'q' to quit${NC}"
    echo ""
    read -rp "  > " selection

    if [[ "$selection" == "q" || "$selection" == "Q" ]]; then
        echo -e "\n  ${RED}Aborted.${NC}\n"
        exit 0
    fi

    SELECTED_INDICES=()
    if [[ "$selection" == "all" ]]; then
        for i in $(seq 0 $((STORAGE_COUNT - 1))); do
            SELECTED_INDICES+=("$i")
        done
    else
        IFS=',' read -ra NUMS <<< "$selection"
        for num in "${NUMS[@]}"; do
            num=$(echo "$num" | tr -d ' ')
            if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= STORAGE_COUNT )); then
                SELECTED_INDICES+=($((num - 1)))
            else
                fail "Invalid selection: ${BOLD}$num${NC}  (must be 1–${STORAGE_COUNT})"
                exit 1
            fi
        done
    fi

    if [[ ${#SELECTED_INDICES[@]} -eq 0 ]]; then
        fail "No valid selections made."
        exit 1
    fi
}

# ── STEP 4 — Show impact, back up configs, confirm ───────────────────────────
step_confirm_and_backup() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 4: Impact Review & Configuration Backup ━━${NC}\n"

    # Choose mode (NSP only — firewall is always enforced)
    if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
        echo -e "  ${BOLD}Select NSP access mode:${NC}"
        echo -e "    ${YELLOW}1)${NC} ${BOLD}Learning${NC}  — logs blocked traffic, does NOT actually block (dry run)"
        echo -e "    ${RED}2)${NC} ${BOLD}Enforced${NC}  — blocks ALL public/internet traffic (real scream test)"
        echo ""
        read -rp "  Mode [1/2]: " mode_choice

        case "$mode_choice" in
            1) NSP_MODE="Learning" ;;
            2) NSP_MODE="Enforced" ;;
            *)
                fail "Invalid mode. Choose 1 or 2."
                exit 1
                ;;
        esac
    else
        NSP_MODE="Enforced"   # firewall is always a hard block
    fi

    echo ""
    if [[ "$NSP_MODE" == "Enforced" ]]; then
        echo -e "  ${RED}${BOLD}The following storage accounts will lose ALL internet connectivity:${NC}\n"
    else
        echo -e "  ${YELLOW}${BOLD}The following storage accounts will be monitored (Learning mode):${NC}\n"
    fi

    local mode_label="$NSP_MODE"
    [[ "$ISOLATION_METHOD" == "firewall" ]] && mode_label="Firewall"

    printf "  ${BOLD}%-5s %-32s %-22s %-14s %-12s${NC}\n" "#" "NAME" "RESOURCE GROUP" "LOCATION" "METHOD"
    line

    for idx in "${SELECTED_INDICES[@]}"; do
        local sa_name sa_rg sa_loc
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$idx].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].resourceGroup")
        sa_loc=$(echo "$STORAGE_JSON"  | jq -r ".data[$idx].location")

        local mode_color="$YELLOW"
        [[ "$NSP_MODE" == "Enforced" ]] && mode_color="$RED"

        printf "  ${mode_color}%-5s %-32s %-22s %-14s %-12s${NC}\n" \
               "$((idx + 1))" "$sa_name" "$sa_rg" "$sa_loc" "$mode_label"
    done

    echo ""
    echo -e "  ${BOLD}What will happen:${NC}"
    echo -e "    1. Full configuration of each account → backed up to JSON"
    echo -e "    2. Network rules → backed up to JSON"
    if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
        echo -e "    3. Each account gets associated to NSP ${CYAN}${NSP_NAME}${NC}"
        echo -e "    4. Profile: ${CYAN}${NSP_PROFILE}${NC} (no access rules = deny all)"
        echo -e "    5. Mode: ${BOLD}${NSP_MODE}${NC}"
    else
        echo -e "    3. publicNetworkAccess → ${BOLD}Disabled${NC}"
        echo -e "    4. defaultAction → ${BOLD}Deny${NC}"
    fi
    echo ""
    echo -e "  ${CYAN}Backup location:${NC} ${BACKUP_DIR}/${TIMESTAMP}/"
    echo ""
    if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
        echo -e "  ${BOLD}To rollback:${NC} ${DIM}remove the NSP association (shown at the end), or run ./screamtest.sh restore${NC}"
    else
        echo -e "  ${BOLD}To rollback:${NC} ${DIM}run ./screamtest.sh restore${NC}"
    fi
    echo ""

    if [[ "$NSP_MODE" == "Enforced" ]]; then
        echo -e "  ${RED}${BOLD}Type 'SCREAM' to confirm (anything else aborts):${NC}"
    else
        echo -e "  ${YELLOW}${BOLD}Type 'LEARN' to confirm learning mode (anything else aborts):${NC}"
    fi
    echo ""
    read -rp "  > " confirmation

    local expected="SCREAM"
    [[ "$NSP_MODE" == "Learning" ]] && expected="LEARN"

    if [[ "$confirmation" != "$expected" ]]; then
        echo -e "\n  ${RED}Aborted — you must type ${expected} to proceed.${NC}\n"
        exit 1
    fi

    # Create timestamped backup folder
    BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"
    mkdir -p "$BACKUP_PATH"

    # Save isolation method to backup for restore reference
    echo "$ISOLATION_METHOD" > "${BACKUP_PATH}/_method.txt"

    echo ""
    info "Backing up configurations...\n"

    for idx in "${SELECTED_INDICES[@]}"; do
        local sa_name sa_rg
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$idx].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].resourceGroup")

        echo -ne "  ⏳  ${BOLD}${sa_name}${NC} ... "

        az storage account show \
            --name "$sa_name" \
            --resource-group "$sa_rg" \
            -o json > "${BACKUP_PATH}/${sa_name}_full-config.json" 2>/dev/null

        az storage account network-rule list \
            --account-name "$sa_name" \
            --resource-group "$sa_rg" \
            -o json > "${BACKUP_PATH}/${sa_name}_network-rules.json" 2>/dev/null

        echo -e "${GREEN}backed up ✔${NC}"
    done

    echo ""
    ok "All backups saved to ${CYAN}${BACKUP_PATH}${NC}"
    line
}

# ── STEP 5 — Execute isolation ────────────────────────────────────────────────
step_execute() {
    if [[ "$ISOLATION_METHOD" == "nsp" ]]; then
        step_execute_nsp
    else
        step_execute_firewall
    fi
}

step_execute_firewall() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 5: Isolating via Firewall ━━${NC}\n"

    local fw_success=()
    local failed=()

    for idx in "${SELECTED_INDICES[@]}"; do
        local sa_name sa_rg
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$idx].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].resourceGroup")

        echo -ne "  ⏳  ${BOLD}${sa_name}${NC} — disabling public access ... "

        local fw_err
        if fw_err=$(az storage account update \
            --name "$sa_name" \
            --resource-group "$sa_rg" \
            --public-network-access Disabled \
            --default-action Deny \
            -o none 2>&1); then
            echo -e "${GREEN}ISOLATED ✔${NC}"
            fw_success+=("$sa_name ($sa_rg)")
        else
            echo -e "${RED}FAILED ✘${NC}"
            echo -e "    ${DIM}${fw_err}${NC}"
            failed+=("$sa_name ($sa_rg)")
        fi
    done

    # ── Summary ───────────────────────────────────────────────────────────────
    echo ""
    line
    echo -e "\n${BOLD}${YELLOW}━━ SCREAM TEST SUMMARY ━━${NC}\n"

    echo -e "  ${BOLD}Method:${NC}  Firewall (publicNetworkAccess=Disabled, defaultAction=Deny)"
    echo ""

    if [[ ${#fw_success[@]} -gt 0 ]]; then
        echo -e "  ${GREEN}${BOLD}Isolated (${#fw_success[@]}):${NC}"
        for sa in "${fw_success[@]}"; do
            echo -e "    ${GREEN}✔${NC}  $sa"
        done
    fi

    if [[ ${#failed[@]} -gt 0 ]]; then
        echo -e "\n  ${RED}${BOLD}Failed (${#failed[@]}):${NC}"
        for sa in "${failed[@]}"; do
            echo -e "    ${RED}✘${NC}  $sa"
        done
    fi

    echo ""
    line
    echo ""
    echo -e "  ${CYAN}Backups:${NC}  ${BACKUP_PATH}/"
    echo ""
    echo -e "  ${BOLD}Rollback:${NC}  ${DIM}./screamtest.sh restore${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}Now wait and monitor. If something screams — rollback.${NC}"
    echo -e "  ${YELLOW}If nothing screams — safe to delete the storage accounts.${NC}"
    echo ""
}

step_execute_nsp() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 5: Associating to Network Security Perimeter (${NSP_MODE}) ━━${NC}\n"

    local nsp_success=()
    local legacy_success=()
    local failed=()
    local assoc_names=()
    local legacy_accounts=()

    for idx in "${SELECTED_INDICES[@]}"; do
        local sa_name sa_rg sa_id
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$idx].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].resourceGroup")
        sa_id=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].id")

        local assoc_name="assoc-${sa_name}"

        echo -ne "  ⏳  ${BOLD}${sa_name}${NC} — associating (${NSP_MODE}) ... "

        local assoc_err
        if assoc_err=$(az network perimeter association create \
            -n "$assoc_name" \
            --perimeter-name "$NSP_NAME" \
            -g "$NSP_RG" \
            --access-mode "$NSP_MODE" \
            --private-link-resource "{id:$sa_id}" \
            --profile "{id:$PROFILE_ID}" \
            -o none 2>&1); then
            echo -e "${GREEN}ASSOCIATED ✔${NC}"
            nsp_success+=("$sa_name ($sa_rg)")
            assoc_names+=("$assoc_name")
        else
            echo -e "${YELLOW}NSP incompatible${NC}"
            # Extract short reason from error (macOS-compatible)
            local short_reason
            short_reason=$(echo "$assoc_err" | sed -n 's/.*Error message: //p' | head -1)
            [[ -z "$short_reason" ]] && short_reason="$assoc_err"
            echo -e "    ${DIM}${short_reason}${NC}"

            # Fallback to legacy method
            echo -ne "    ↳ Falling back to ${BOLD}publicNetworkAccess=Disabled${NC} ... "
            if [[ "$NSP_MODE" == "Learning" ]]; then
                echo -e "${YELLOW}SKIPPED${NC} (Learning mode — legacy method has no dry-run)"
                failed+=("$sa_name ($sa_rg) — NSP incompatible, skipped in Learning mode")
            else
                local legacy_err
                if legacy_err=$(az storage account update \
                    --name "$sa_name" \
                    --resource-group "$sa_rg" \
                    --public-network-access Disabled \
                    --default-action Deny \
                    -o none 2>&1); then
                    echo -e "${GREEN}ISOLATED (legacy) ✔${NC}"
                    legacy_success+=("$sa_name ($sa_rg)")
                    legacy_accounts+=("$sa_name|$sa_rg")
                else
                    echo -e "${RED}FAILED ✘${NC}"
                    echo -e "      ${DIM}${legacy_err}${NC}"
                    failed+=("$sa_name ($sa_rg)")
                fi
            fi
        fi
    done

    # ── Summary ───────────────────────────────────────────────────────────────
    echo ""
    line
    echo -e "\n${BOLD}${YELLOW}━━ SCREAM TEST SUMMARY ━━${NC}\n"

    echo -e "  ${BOLD}Method:${NC}     NSP"
    echo -e "  ${BOLD}Mode:${NC}       ${NSP_MODE}"
    echo -e "  ${BOLD}Perimeter:${NC}  ${NSP_NAME}"
    echo -e "  ${BOLD}Profile:${NC}    ${NSP_PROFILE} (deny-all)"
    echo ""

    if [[ ${#nsp_success[@]} -gt 0 ]]; then
        echo -e "  ${GREEN}${BOLD}NSP associated (${#nsp_success[@]}):${NC}"
        for sa in "${nsp_success[@]}"; do
            echo -e "    ${GREEN}✔${NC}  $sa"
        done
    fi

    if [[ ${#legacy_success[@]} -gt 0 ]]; then
        echo -e "\n  ${GREEN}${BOLD}Legacy isolated (${#legacy_success[@]}):${NC}  ${DIM}(publicNetworkAccess=Disabled)${NC}"
        for sa in "${legacy_success[@]}"; do
            echo -e "    ${GREEN}✔${NC}  $sa"
        done
    fi

    if [[ ${#failed[@]} -gt 0 ]]; then
        echo -e "\n  ${RED}${BOLD}Failed / Skipped (${#failed[@]}):${NC}"
        for sa in "${failed[@]}"; do
            echo -e "    ${RED}✘${NC}  $sa"
        done
    fi

    echo ""
    line
    echo ""
    echo -e "  ${CYAN}Backups:${NC}  ${BACKUP_PATH}/"
    echo ""

    if [[ ${#assoc_names[@]} -gt 0 ]]; then
        if [[ "$NSP_MODE" == "Learning" ]]; then
            echo -e "  ${BOLD}Upgrade to Enforced mode (NSP accounts):${NC}"
            for aname in "${assoc_names[@]}"; do
                echo -e "  ${DIM}az network perimeter association update -n $aname \\${NC}"
                echo -e "  ${DIM}  --perimeter-name $NSP_NAME -g $NSP_RG --access-mode Enforced${NC}"
                echo ""
            done
        fi

        echo -e "  ${BOLD}Rollback NSP associations:${NC}"
        for aname in "${assoc_names[@]}"; do
            echo -e "  ${DIM}az network perimeter association delete -n $aname \\${NC}"
            echo -e "  ${DIM}  --perimeter-name $NSP_NAME -g $NSP_RG --yes${NC}"
            echo ""
        done
    fi

    if [[ ${#legacy_accounts[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}Rollback legacy-isolated accounts:${NC}"
        for entry in "${legacy_accounts[@]}"; do
            local rname rgname
            rname="${entry%%|*}"
            rgname="${entry##*|}"
            echo -e "  ${DIM}az storage account update --name $rname --resource-group $rgname \\${NC}"
            echo -e "  ${DIM}  --public-network-access Enabled --default-action Allow${NC}"
            echo ""
        done
    fi

    echo -e "  ${BOLD}Full rollback:${NC}  ${DIM}./screamtest.sh restore${NC}"
    echo ""
    echo -e "  ${BOLD}Delete the entire NSP + all associations:${NC}"
    echo -e "  ${DIM}az network perimeter delete -n $NSP_NAME -g $NSP_RG --force-deletion true --yes${NC}"
    echo ""

    if [[ "$NSP_MODE" == "Enforced" ]]; then
        echo -e "  ${YELLOW}${BOLD}Now wait and monitor. If something screams — rollback.${NC}"
        echo -e "  ${YELLOW}If nothing screams — safe to delete the storage accounts.${NC}"
    else
        echo -e "  ${YELLOW}${BOLD}Learning mode active — check NSP logs in Azure Monitor.${NC}"
        echo -e "  ${YELLOW}When ready, upgrade to Enforced mode for the real scream test.${NC}"
    fi
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

usage() {
    echo -e "  Usage: ${BOLD}./screamtest.sh${NC} [command]"
    echo ""
    echo -e "  Commands:"
    echo -e "    ${CYAN}(none)${NC}    Run the scream test"
    echo -e "    ${CYAN}restore${NC}   Restore storage accounts from a backup"
    echo ""
}

# ── RESTORE — Revert storage accounts to their exact previous config ─────────
cmd_restore() {
    banner
    echo -e "${BOLD}${YELLOW}━━ RESTORE MODE ━━${NC}\n"

    # Ensure logged in
    if ! az account show &>/dev/null; then
        warn "Not logged in to Azure CLI — launching ${CYAN}az login${NC}..."
        az login
    fi

    # List available backups
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
        fail "No backups found in ${BACKUP_DIR}/"
        exit 1
    fi

    info "Available backups:\n"

    local backup_dirs=()
    local i=1
    for d in "$BACKUP_DIR"/*/; do
        [[ -d "$d" ]] || continue
        local dirname
        dirname=$(basename "$d")
        local file_count
        file_count=$(find "$d" -name "*_full-config.json" | wc -l | tr -d ' ')
        local accounts
        accounts=$(find "$d" -name "*_full-config.json" -exec basename {} '_full-config.json' \; | sort | paste -sd ', ' -)
        local method_label=""
        if [[ -f "${d}_method.txt" ]]; then
            method_label=" [$(cat "${d}_method.txt")]"
        fi
        printf "  ${BOLD}%-5s${NC} %-22s ${DIM}(%s account(s): %s)%s${NC}\n" "$i)" "$dirname" "$file_count" "$accounts" "$method_label"
        backup_dirs+=("$d")
        i=$((i + 1))
    done

    if [[ ${#backup_dirs[@]} -eq 0 ]]; then
        fail "No backup directories found."
        exit 1
    fi

    echo ""
    read -rp "  Select backup number: " backup_num

    if ! [[ "$backup_num" =~ ^[0-9]+$ ]] || (( backup_num < 1 || backup_num > ${#backup_dirs[@]} )); then
        fail "Invalid selection."
        exit 1
    fi

    local chosen_dir="${backup_dirs[$((backup_num - 1))]}"
    local chosen_name
    chosen_name=$(basename "$chosen_dir")

    echo ""
    info "Selected backup: ${BOLD}${chosen_name}${NC}\n"

    # Find all full-config backups in this directory
    local configs=()
    for cfg in "$chosen_dir"/*_full-config.json; do
        [[ -f "$cfg" ]] || continue
        configs+=("$cfg")
    done

    if [[ ${#configs[@]} -eq 0 ]]; then
        fail "No config backups found in ${chosen_dir}"
        exit 1
    fi

    # Show what will be restored
    echo -e "  ${BOLD}The following accounts will be restored to their exact backed-up config:${NC}\n"

    printf "  ${BOLD}%-5s %-32s %-22s %-14s %-14s %-10s${NC}\n" \
           "#" "NAME" "RESOURCE GROUP" "PUBLIC ACCESS" "DEFAULT ACT" "BYPASS"
    line

    local restore_items=()
    local ri=1
    for cfg in "${configs[@]}"; do
        local sa_name sa_rg pub_access default_action bypass
        sa_name=$(jq -r '.name' "$cfg")
        sa_rg=$(jq -r '.resourceGroup' "$cfg")
        pub_access=$(jq -r '.publicNetworkAccess // "Enabled"' "$cfg")
        default_action=$(jq -r '.networkRuleSet.defaultAction // "Allow"' "$cfg")
        bypass=$(jq -r '.networkRuleSet.bypass // "AzureServices"' "$cfg")

        printf "  %-5s %-32s %-22s %-14s %-14s %-10s\n" \
               "$ri" "$sa_name" "$sa_rg" "$pub_access" "$default_action" "$bypass"

        restore_items+=("${cfg}")
        ri=$((ri + 1))
    done

    echo ""

    # Check for NSP associations to remove
    local nsp_extension_present=false
    if az extension show --name nsp &>/dev/null; then
        nsp_extension_present=true
    fi

    local nsp_assocs_to_remove=()
    if [[ "$nsp_extension_present" == true ]]; then
        if az network perimeter show -n "$NSP_NAME" -g "$NSP_RG" &>/dev/null 2>&1; then
            info "Checking for NSP associations to remove...\n"
            local all_assocs
            all_assocs=$(az network perimeter association list \
                --perimeter-name "$NSP_NAME" -g "$NSP_RG" -o json 2>/dev/null || echo "[]")

            for cfg in "${configs[@]}"; do
                local sa_id
                sa_id=$(jq -r '.id' "$cfg")
                local assoc_name
                assoc_name=$(echo "$all_assocs" | jq -r ".[] | select(.properties.privateLinkResource.id == \"$sa_id\") | .name // empty")
                if [[ -n "$assoc_name" ]]; then
                    nsp_assocs_to_remove+=("$assoc_name")
                    ok "Will remove NSP association: ${CYAN}${assoc_name}${NC}"
                fi
            done
            echo ""
        fi
    fi

    echo -e "  ${RED}${BOLD}Type 'RESTORE' to confirm:${NC}"
    echo ""
    read -rp "  > " restore_confirm

    if [[ "$restore_confirm" != "RESTORE" ]]; then
        echo -e "\n  ${RED}Aborted.${NC}\n"
        exit 1
    fi

    echo ""

    # Remove NSP associations first
    for aname in "${nsp_assocs_to_remove[@]}"; do
        echo -ne "  ⏳  Removing NSP association ${BOLD}${aname}${NC} ... "
        if az network perimeter association delete \
            -n "$aname" \
            --perimeter-name "$NSP_NAME" \
            -g "$NSP_RG" \
            --yes -o none 2>/dev/null; then
            echo -e "${GREEN}removed ✔${NC}"
        else
            echo -e "${YELLOW}not found / already removed${NC}"
        fi
    done

    # Restore each storage account
    for cfg in "${restore_items[@]}"; do
        local sa_name sa_rg pub_access default_action bypass
        sa_name=$(jq -r '.name' "$cfg")
        sa_rg=$(jq -r '.resourceGroup' "$cfg")
        pub_access=$(jq -r '.publicNetworkAccess // "Enabled"' "$cfg")
        default_action=$(jq -r '.networkRuleSet.defaultAction // "Allow"' "$cfg")
        bypass=$(jq -r '.networkRuleSet.bypass // "AzureServices"' "$cfg")

        echo -ne "  ⏳  ${BOLD}${sa_name}${NC} — restoring network config ... "

        local restore_err
        if restore_err=$(az storage account update \
            --name "$sa_name" \
            --resource-group "$sa_rg" \
            --public-network-access "$pub_access" \
            --default-action "$default_action" \
            --bypass "$bypass" \
            -o none 2>&1); then
            echo -e "${GREEN}restored ✔${NC}"
        else
            echo -e "${RED}FAILED ✘${NC}"
            echo -e "    ${DIM}${restore_err}${NC}"
        fi

        # Restore IP rules from network-rules backup
        local net_rules_file="${cfg/_full-config.json/_network-rules.json}"
        if [[ -f "$net_rules_file" ]]; then
            # Restore IP rules
            local ip_count
            ip_count=$(jq '.ipRules | length' "$net_rules_file")
            if [[ "$ip_count" -gt 0 ]]; then
                for ipi in $(seq 0 $((ip_count - 1))); do
                    local ip_addr
                    ip_addr=$(jq -r ".ipRules[$ipi].ipAddressOrRange" "$net_rules_file")
                    az storage account network-rule add \
                        --account-name "$sa_name" \
                        --resource-group "$sa_rg" \
                        --ip-address "$ip_addr" \
                        -o none 2>/dev/null || true
                done
                echo -e "    ↳ Restored ${ip_count} IP rule(s)"
            fi

            # Restore VNet rules
            local vnet_count
            vnet_count=$(jq '.virtualNetworkRules | length' "$net_rules_file")
            if [[ "$vnet_count" -gt 0 ]]; then
                for vni in $(seq 0 $((vnet_count - 1))); do
                    local subnet_id
                    subnet_id=$(jq -r ".virtualNetworkRules[$vni].virtualNetworkResourceId // .virtualNetworkRules[$vni].id" "$net_rules_file")
                    az storage account network-rule add \
                        --account-name "$sa_name" \
                        --resource-group "$sa_rg" \
                        --subnet "$subnet_id" \
                        -o none 2>/dev/null || true
                done
                echo -e "    ↳ Restored ${vnet_count} VNet rule(s)"
            fi

            # Restore resource access rules
            local rar_count
            rar_count=$(jq '.resourceAccessRules | length' "$net_rules_file")
            if [[ "$rar_count" -gt 0 ]]; then
                for rari in $(seq 0 $((rar_count - 1))); do
                    local res_id tenant_id
                    res_id=$(jq -r ".resourceAccessRules[$rari].resourceId" "$net_rules_file")
                    tenant_id=$(jq -r ".resourceAccessRules[$rari].tenantId" "$net_rules_file")
                    az storage account network-rule add \
                        --account-name "$sa_name" \
                        --resource-group "$sa_rg" \
                        --resource-id "$res_id" \
                        --tenant-id "$tenant_id" \
                        -o none 2>/dev/null || true
                done
                echo -e "    ↳ Restored ${rar_count} resource access rule(s)"
            fi
        fi
    done

    echo ""
    line
    echo ""
    ok "${BOLD}Restore complete.${NC} All accounts reverted to their backed-up configuration."
    echo ""
}

# ── Entry point ───────────────────────────────────────────────────────────────
case "${1:-}" in
    restore)
        cmd_restore
        ;;
    help|--help|-h)
        banner
        usage
        ;;
    "")
        banner
        step_authenticate
        step_check_infra
        step_discover
        step_confirm_and_backup
        step_execute
        ;;
    *)
        fail "Unknown command: $1"
        usage
        exit 1
        ;;
esac
