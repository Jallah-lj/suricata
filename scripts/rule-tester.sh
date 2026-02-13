#!/usr/bin/env bash
#
# Suricata Rule Testing Script
#
# This script helps test and validate Suricata rules by:
# - Testing rule syntax with suricata -T
# - Validating custom rule files
# - Running Suricata against sample PCAP files
# - Displaying alerts generated from PCAP tests
# - Cleaning up temporary files
#
# Usage Examples:
#   ./rule-tester.sh --rules custom.rules                 # Test rule syntax only
#   ./rule-tester.sh --rules custom.rules --pcap test.pcap  # Test with PCAP
#   ./rule-tester.sh --pcap test.pcap                     # Test with default config
#   ./rule-tester.sh --rules custom.rules --config my.yaml  # Custom config
#

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
RULES_FILE=""
PCAP_FILE=""
CONFIG_FILE=""
TEMP_DIR=""
CLEANUP=true
VERBOSE=false

# Print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo ""
    echo -e "${CYAN}===================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}===================================================${NC}"
}

# Display help
show_help() {
    cat << EOF
Suricata Rule Testing Script

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -r, --rules FILE        Custom rules file to test
    -p, --pcap FILE         PCAP file to test rules against
    -c, --config FILE       Custom suricata.yaml config file
    -n, --no-cleanup        Don't clean up temporary files
    -v, --verbose           Verbose output

EXAMPLES:
    # Test rule file syntax only
    $0 --rules custom.rules

    # Test rules with PCAP file
    $0 --rules custom.rules --pcap test.pcap

    # Test with PCAP using default configuration
    $0 --pcap test.pcap

    # Use custom configuration
    $0 --rules custom.rules --pcap test.pcap --config my.yaml

    # Keep temporary files for inspection
    $0 --rules custom.rules --pcap test.pcap --no-cleanup

NOTES:
    - If no rules file is specified, uses rules from config file
    - If no config is specified, uses default Suricata config
    - Temporary files are created in /tmp and cleaned up by default

EOF
    exit 0
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -r|--rules)
                RULES_FILE="$2"
                shift 2
                ;;
            -p|--pcap)
                PCAP_FILE="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -n|--no-cleanup)
                CLEANUP=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                ;;
        esac
    done
}

# Check if Suricata is installed
check_suricata() {
    print_info "Checking for Suricata installation..."
    
    if ! command -v suricata &> /dev/null; then
        print_error "Suricata is not installed or not in PATH"
        print_info "Install Suricata first:"
        print_info "  Ubuntu/Debian: sudo apt-get install suricata"
        print_info "  CentOS/RHEL:   sudo yum install suricata"
        exit 1
    fi
    
    local version=$(suricata --version 2>&1 | head -n 1)
    print_success "Found $version"
}

# Validate rules file exists
validate_rules_file() {
    if [[ -z "$RULES_FILE" ]]; then
        return 0
    fi
    
    if [[ ! -f "$RULES_FILE" ]]; then
        print_error "Rules file not found: $RULES_FILE"
        exit 1
    fi
    
    print_success "Rules file found: $RULES_FILE"
    
    # Show basic info about rules file
    local rule_count=$(grep -cE "^(alert|drop|reject|pass)" "$RULES_FILE" 2>/dev/null || echo "0")
    print_info "Found $rule_count rules in file"
}

# Validate PCAP file exists
validate_pcap_file() {
    if [[ -z "$PCAP_FILE" ]]; then
        return 0
    fi
    
    if [[ ! -f "$PCAP_FILE" ]]; then
        print_error "PCAP file not found: $PCAP_FILE"
        exit 1
    fi
    
    print_success "PCAP file found: $PCAP_FILE"
    
    # Show basic info about PCAP if capinfos is available
    if command -v capinfos &> /dev/null; then
        print_info "PCAP file information:"
        capinfos "$PCAP_FILE" 2>/dev/null | grep -E "(Number of packets|File size|Capture duration)" || true
    fi
}

# Find or validate config file
setup_config() {
    if [[ -n "$CONFIG_FILE" ]]; then
        if [[ ! -f "$CONFIG_FILE" ]]; then
            print_error "Config file not found: $CONFIG_FILE"
            exit 1
        fi
        print_success "Using custom config: $CONFIG_FILE"
        return 0
    fi
    
    # Try to find default config
    local default_configs=(
        "/etc/suricata/suricata.yaml"
        "/usr/local/etc/suricata/suricata.yaml"
    )
    
    for config in "${default_configs[@]}"; do
        if [[ -f "$config" ]]; then
            CONFIG_FILE="$config"
            print_info "Using default config: $CONFIG_FILE"
            return 0
        fi
    done
    
    # If testing only rules syntax and no PCAP, we can proceed without config
    if [[ -n "$RULES_FILE" ]] && [[ -z "$PCAP_FILE" ]]; then
        print_warning "No config file found, will test basic syntax only"
        return 0
    fi
    
    print_error "No Suricata configuration file found"
    print_info "Specify config with --config or install Suricata properly"
    exit 1
}

# Setup temporary directory
setup_temp_dir() {
    TEMP_DIR=$(mktemp -d -t suricata-test-XXXXXX)
    print_info "Created temporary directory: $TEMP_DIR"
    
    # Create subdirectories
    mkdir -p "$TEMP_DIR/log"
    mkdir -p "$TEMP_DIR/rules"
}

# Test rule syntax
test_rule_syntax() {
    if [[ -z "$RULES_FILE" ]]; then
        print_info "No rules file specified, skipping syntax test"
        return 0
    fi
    
    print_section "Testing Rule Syntax"
    
    # Basic syntax checks
    print_info "Performing basic syntax validation..."
    
    local errors=0
    local warnings=0
    local line_num=0
    
    while IFS= read -r line; do
        ((line_num++))
        
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Check if line starts with valid action
        if [[ "$line" =~ ^(alert|drop|reject|pass|log) ]]; then
            # Check for basic rule structure
            if ! [[ "$line" =~ \(.*\) ]]; then
                print_warning "Line $line_num: Missing rule options (parentheses)"
                ((warnings++))
            fi
            
            # Check for required fields: msg and sid
            if ! [[ "$line" =~ msg: ]]; then
                print_error "Line $line_num: Missing 'msg' field"
                ((errors++))
            fi
            
            if ! [[ "$line" =~ sid: ]]; then
                print_error "Line $line_num: Missing 'sid' field"
                ((errors++))
            fi
        else
            if [[ ! "$line" =~ ^[[:space:]]*$ ]]; then
                print_warning "Line $line_num: Does not start with valid action"
                ((warnings++))
            fi
        fi
    done < "$RULES_FILE"
    
    echo ""
    print_info "Basic syntax check complete"
    print_info "  Potential errors:   $errors"
    print_info "  Warnings:           $warnings"
    
    if [[ $errors -gt 0 ]]; then
        print_warning "Found potential syntax errors, but continuing with Suricata validation..."
    fi
    
    # Test with Suricata if config is available
    if [[ -n "$CONFIG_FILE" ]]; then
        print_info "Validating rules with Suricata..."
        
        # Create temporary config with our rules
        local temp_config="$TEMP_DIR/suricata.yaml"
        cp "$CONFIG_FILE" "$temp_config"
        
        # Add our rules file to config
        local rules_line="  - $RULES_FILE"
        if grep -q "rule-files:" "$temp_config"; then
            # Append to existing rule-files section
            sed -i "/rule-files:/a\\$rules_line" "$temp_config"
        else
            # Add rule-files section
            echo "" >> "$temp_config"
            echo "rule-files:" >> "$temp_config"
            echo "$rules_line" >> "$temp_config"
        fi
        
        # Run Suricata test
        if $VERBOSE; then
            suricata -T -c "$temp_config" -l "$TEMP_DIR/log" 2>&1 | tee "$TEMP_DIR/test-output.log"
        else
            suricata -T -c "$temp_config" -l "$TEMP_DIR/log" > "$TEMP_DIR/test-output.log" 2>&1
        fi
        
        if grep -q "Configuration provided was successfully loaded" "$TEMP_DIR/test-output.log"; then
            print_success "✓ Rule syntax validation PASSED"
        else
            print_error "✗ Rule syntax validation FAILED"
            print_info "Error details:"
            grep -i "error" "$TEMP_DIR/test-output.log" || cat "$TEMP_DIR/test-output.log"
            return 1
        fi
    else
        print_warning "Cannot perform full validation without config file"
    fi
    
    return 0
}

# Run Suricata with PCAP
run_pcap_test() {
    if [[ -z "$PCAP_FILE" ]]; then
        print_info "No PCAP file specified, skipping PCAP test"
        return 0
    fi
    
    print_section "Running PCAP Test"
    
    local temp_config="$CONFIG_FILE"
    
    # If we have custom rules, create modified config
    if [[ -n "$RULES_FILE" ]]; then
        temp_config="$TEMP_DIR/suricata.yaml"
        cp "$CONFIG_FILE" "$temp_config"
        
        # Add our rules file
        local rules_line="  - $RULES_FILE"
        if grep -q "rule-files:" "$temp_config"; then
            sed -i "/rule-files:/a\\$rules_line" "$temp_config"
        else
            echo "" >> "$temp_config"
            echo "rule-files:" >> "$temp_config"
            echo "$rules_line" >> "$temp_config"
        fi
        
        print_info "Using custom rules: $RULES_FILE"
    fi
    
    print_info "Running Suricata with PCAP file..."
    print_info "Command: suricata -c $temp_config -r $PCAP_FILE -l $TEMP_DIR/log"
    
    # Run Suricata
    if $VERBOSE; then
        suricata -c "$temp_config" -r "$PCAP_FILE" -l "$TEMP_DIR/log" 2>&1 | tee "$TEMP_DIR/run-output.log"
    else
        suricata -c "$temp_config" -r "$PCAP_FILE" -l "$TEMP_DIR/log" > "$TEMP_DIR/run-output.log" 2>&1
    fi
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "✓ PCAP processing completed"
    else
        print_error "✗ PCAP processing failed with exit code: $exit_code"
        if [[ -f "$TEMP_DIR/run-output.log" ]]; then
            print_info "Error details:"
            cat "$TEMP_DIR/run-output.log"
        fi
        return 1
    fi
}

# Display alerts from PCAP test
display_alerts() {
    if [[ -z "$PCAP_FILE" ]]; then
        return 0
    fi
    
    print_section "Alert Results"
    
    local eve_log="$TEMP_DIR/log/eve.json"
    local fast_log="$TEMP_DIR/log/fast.log"
    
    # Check for fast.log
    if [[ -f "$fast_log" ]] && [[ -s "$fast_log" ]]; then
        print_info "Alerts from fast.log:"
        echo ""
        cat "$fast_log"
        echo ""
        
        local alert_count=$(wc -l < "$fast_log")
        print_info "Total alerts: $alert_count"
    elif [[ -f "$fast_log" ]]; then
        print_success "No alerts generated (clean test)"
    else
        print_warning "fast.log not found"
    fi
    
    # Check for eve.json
    if [[ -f "$eve_log" ]] && [[ -s "$eve_log" ]]; then
        local alert_count=$(grep -c '"event_type":"alert"' "$eve_log" 2>/dev/null || echo "0")
        print_info "EVE alerts: $alert_count"
        
        if [[ $alert_count -gt 0 ]]; then
            print_info "Top alert signatures:"
            grep '"event_type":"alert"' "$eve_log" | \
                grep -o '"signature":"[^"]*"' | \
                sort | uniq -c | sort -rn | head -10 || true
        fi
    fi
    
    # Show log directory contents
    echo ""
    print_info "Log files created:"
    ls -lh "$TEMP_DIR/log/" 2>/dev/null || true
}

# Cleanup temporary files
cleanup_temp_files() {
    if [[ "$CLEANUP" == true ]] && [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
        print_info "Cleaning up temporary files..."
        rm -rf "$TEMP_DIR"
        print_success "Cleanup complete"
    elif [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
        print_info "Temporary files preserved at: $TEMP_DIR"
        print_info "  Logs:   $TEMP_DIR/log/"
        print_info "  Config: $TEMP_DIR/suricata.yaml"
    fi
}

# Main function
main() {
    echo "======================================"
    echo "  Suricata Rule Testing Script"
    echo "======================================"
    echo ""
    
    # Parse arguments
    parse_arguments "$@"
    
    # Validate we have something to do
    if [[ -z "$RULES_FILE" ]] && [[ -z "$PCAP_FILE" ]]; then
        print_error "No rules file or PCAP file specified"
        show_help
    fi
    
    # Setup
    check_suricata
    validate_rules_file
    validate_pcap_file
    setup_config
    setup_temp_dir
    
    # Run tests
    test_rule_syntax || {
        print_error "Rule syntax test failed"
        cleanup_temp_files
        exit 1
    }
    
    run_pcap_test || {
        print_error "PCAP test failed"
        cleanup_temp_files
        exit 1
    }
    
    display_alerts
    
    # Cleanup
    cleanup_temp_files
    
    print_section "Test Complete"
    print_success "All tests completed successfully!"
}

# Trap for cleanup on exit
trap cleanup_temp_files EXIT

# Run main
main "$@"
