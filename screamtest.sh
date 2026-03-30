#!/usr/bin/env bash
set -euo pipefail

###############################################################################
#  STORAGE ACCOUNT SCREAM TEST
#  ---------------------------------------------------------------------------
#  Cuts internet access to selected Azure Storage Accounts as a safe
#  middle-step before permanent deletion. If nothing "screams", it's safe
#  to delete.
#
#  Flow:
#    1. Authenticate & show tenant/subscription context
#    2. Verify required tooling (resource-graph extension, jq)
#    3. Discover all storage accounts via KQL (Azure Resource Graph)
#    4. User picks accounts → backup configs → confirm
#    5. Disable public network access & set default-action Deny
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

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}STORAGE ACCOUNT SCREAM TEST${NC}                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}Disable internet → wait → if nothing screams → delete${NC}          ${CYAN}║${NC}"
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

# ── STEP 1 — Authenticate & show context ─────────────────────────────────────
step_authenticate() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 1: Authentication & Azure Context ━━${NC}\n"

    # Ensure logged in
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

    # Try to get a friendly tenant name (falls back to ID)
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

# ── STEP 2 — Verify required infra & tooling ─────────────────────────────────
step_check_infra() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 2: Checking Required Infrastructure ━━${NC}\n"

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
}

# ── STEP 3 — Discover storage accounts via KQL ───────────────────────────────
step_discover() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 3: Discovering Storage Accounts (KQL) ━━${NC}\n"

    local kql="resources | where type =~ 'microsoft.storage/storageaccounts' | project name, resourceGroup, location, subscriptionId, sku = tostring(sku.name), kind, publicAccess = iff(isnotempty(properties.publicNetworkAccess), tostring(properties.publicNetworkAccess), 'Enabled') | order by name asc"

    info "Running KQL query via Azure Resource Graph (all subscriptions)...\n"

    local query_output
    if ! query_output=$(az graph query -q "$kql" --first 1000 --subscriptions "$SUB_ID" -o json 2>&1); then
        fail "KQL query failed:"
        echo -e "  ${DIM}${query_output}${NC}"
        exit 1
    fi
    STORAGE_JSON="$query_output"

    STORAGE_COUNT=$(echo "$STORAGE_JSON" | jq '.count // (.data | length)')

    if [[ -z "$STORAGE_COUNT" || "$STORAGE_COUNT" == "null" || "$STORAGE_COUNT" -eq 0 ]]; then
        warn "No storage accounts found in subscription ${BOLD}${SUB_NAME}${NC}."
        exit 0
    fi

    if [[ "$STORAGE_COUNT" -eq 0 ]]; then
        warn "No storage accounts found in subscription ${BOLD}${SUB_NAME}${NC}."
        exit 0
    fi

    ok "Found ${BOLD}${STORAGE_COUNT}${NC} storage account(s)\n"

    # Table header
    printf "  ${BOLD}${DIM}%-5s %-36s %-26s %-16s %-14s %-10s${NC}\n" \
           "#" "NAME" "RESOURCE GROUP" "LOCATION" "SKU" "PUBLIC"
    line

    for i in $(seq 0 $((STORAGE_COUNT - 1))); do
        local sa_name sa_rg sa_loc sa_sku sa_pub
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$i].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$i].resourceGroup")
        sa_loc=$(echo "$STORAGE_JSON"  | jq -r ".data[$i].location")
        sa_sku=$(echo "$STORAGE_JSON"  | jq -r ".data[$i].sku")
        sa_pub=$(echo "$STORAGE_JSON"  | jq -r ".data[$i].publicAccess // \"Enabled\"")

        local num=$((i + 1))
        if [[ "$sa_pub" == "Disabled" ]]; then
            printf "  ${DIM}%-5s %-36s %-26s %-16s %-14s ${RED}%-10s${NC}\n" \
                   "$num" "$sa_name" "$sa_rg" "$sa_loc" "$sa_sku" "$sa_pub"
        else
            printf "  %-5s %-36s %-26s %-16s %-14s ${GREEN}%-10s${NC}\n" \
                   "$num" "$sa_name" "$sa_rg" "$sa_loc" "$sa_sku" "$sa_pub"
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

    # Parse selection into SELECTED_INDICES (0-based)
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

    echo -e "  ${RED}${BOLD}The following storage accounts will lose ALL internet connectivity:${NC}\n"

    printf "  ${BOLD}%-5s %-36s %-26s %-16s${NC}\n" "#" "NAME" "RESOURCE GROUP" "LOCATION"
    line

    for idx in "${SELECTED_INDICES[@]}"; do
        local sa_name sa_rg sa_loc
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$idx].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].resourceGroup")
        sa_loc=$(echo "$STORAGE_JSON"  | jq -r ".data[$idx].location")
        printf "  ${RED}%-5s %-36s %-26s %-16s${NC}\n" "$((idx + 1))" "$sa_name" "$sa_rg" "$sa_loc"
    done

    echo ""
    echo -e "  ${BOLD}What will happen:${NC}"
    echo -e "    1. Full configuration of each account → backed up to JSON"
    echo -e "    2. Network rules → backed up to JSON"
    echo -e "    3. ${RED}publicNetworkAccess${NC} → ${RED}Disabled${NC}"
    echo -e "    4. Default firewall action → ${RED}Deny${NC}"
    echo ""
    echo -e "  ${CYAN}Backup location:${NC} ${BACKUP_DIR}/${TIMESTAMP}/"
    echo ""

    echo -e "  ${RED}${BOLD}Type 'SCREAM' to confirm (anything else aborts):${NC}"
    echo ""
    read -rp "  > " confirmation

    if [[ "$confirmation" != "SCREAM" ]]; then
        echo -e "\n  ${RED}Aborted — you must type SCREAM to proceed.${NC}\n"
        exit 1
    fi

    # Create timestamped backup folder
    BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"
    mkdir -p "$BACKUP_PATH"

    echo ""
    info "Backing up configurations...\n"

    for idx in "${SELECTED_INDICES[@]}"; do
        local sa_name sa_rg
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$idx].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].resourceGroup")

        echo -ne "  ⏳  ${BOLD}${sa_name}${NC} ... "

        # Full config
        az storage account show \
            --name "$sa_name" \
            --resource-group "$sa_rg" \
            -o json > "${BACKUP_PATH}/${sa_name}_full-config.json" 2>/dev/null

        # Network rules
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

# ── STEP 5 — Execute the scream test ─────────────────────────────────────────
step_execute() {
    echo -e "\n${BOLD}${YELLOW}━━ STEP 5: Executing Scream Test ━━${NC}\n"

    local success=()
    local failed=()

    for idx in "${SELECTED_INDICES[@]}"; do
        local sa_name sa_rg
        sa_name=$(echo "$STORAGE_JSON" | jq -r ".data[$idx].name")
        sa_rg=$(echo "$STORAGE_JSON"   | jq -r ".data[$idx].resourceGroup")

        echo -ne "  ⏳  ${BOLD}${sa_name}${NC} — disabling public access ... "

        if az storage account update \
            --name "$sa_name" \
            --resource-group "$sa_rg" \
            --public-network-access Disabled \
            --default-action Deny \
            -o none 2>/dev/null; then
            echo -e "${GREEN}ISOLATED ✔${NC}"
            success+=("$sa_name ($sa_rg)")
        else
            echo -e "${RED}FAILED ✘${NC}"
            failed+=("$sa_name ($sa_rg)")
        fi
    done

    # ── Summary ───────────────────────────────────────────────────────────────
    echo ""
    line
    echo -e "\n${BOLD}${YELLOW}━━ SCREAM TEST SUMMARY ━━${NC}\n"

    if [[ ${#success[@]} -gt 0 ]]; then
        echo -e "  ${GREEN}${BOLD}Successfully isolated (${#success[@]}):${NC}"
        for sa in "${success[@]}"; do
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
    echo -e "  ${BOLD}To restore a storage account:${NC}"
    echo -e "  ${DIM}az storage account update \\${NC}"
    echo -e "  ${DIM}  --name <name> --resource-group <rg> \\${NC}"
    echo -e "  ${DIM}  --public-network-access Enabled --default-action Allow${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}Now wait and monitor. If something screams — restore from backup.${NC}"
    echo -e "  ${YELLOW}If nothing screams — safe to delete.${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
banner
step_authenticate
step_check_infra
step_discover
step_confirm_and_backup
step_execute
