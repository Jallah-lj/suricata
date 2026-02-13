#!/usr/bin/env bash
#
# Suricata IDS Setup Script
# 
# This script helps set up and configure Suricata IDS by:
# - Checking if Suricata is installed
# - Identifying available network interfaces
# - Setting up directory structure for logs
# - Creating symbolic links if needed
# - Setting proper permissions
# - Validating configuration files
#
# Usage Examples:
#   ./setup.sh                    # Run interactive setup
#   ./setup.sh --help             # Show this help message
#   ./setup.sh --check-only       # Only check installation without making changes
#   ./setup.sh --log-dir /custom  # Specify custom log directory
#

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_LOG_DIR="/var/log/suricata"
DEFAULT_RUN_DIR="/var/run/suricata"
DEFAULT_CONFIG="/etc/suricata/suricata.yaml"
CHECK_ONLY=false
LOG_DIR=""

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

# Display help message
show_help() {
    cat << EOF
Suricata IDS Setup Script

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -c, --check-only        Only check installation without making changes
    -l, --log-dir DIR       Specify custom log directory (default: $DEFAULT_LOG_DIR)
    -d, --run-dir DIR       Specify custom run directory (default: $DEFAULT_RUN_DIR)
    -f, --config FILE       Specify custom config file (default: $DEFAULT_CONFIG)

EXAMPLES:
    $0                      # Run full setup
    $0 --check-only         # Check installation only
    $0 --log-dir /custom    # Use custom log directory

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
            -c|--check-only)
                CHECK_ONLY=true
                shift
                ;;
            -l|--log-dir)
                LOG_DIR="$2"
                shift 2
                ;;
            -d|--run-dir)
                DEFAULT_RUN_DIR="$2"
                shift 2
                ;;
            -f|--config)
                DEFAULT_CONFIG="$2"
                shift 2
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                ;;
        esac
    done

    # Set default log dir if not specified
    if [[ -z "$LOG_DIR" ]]; then
        LOG_DIR="$DEFAULT_LOG_DIR"
    fi
}

# Check if running with sufficient privileges
check_privileges() {
    print_info "Checking privileges..."
    if [[ $EUID -eq 0 ]]; then
        print_success "Running with root privileges"
        return 0
    else
        print_warning "Not running as root. Some operations may require sudo."
        return 1
    fi
}

# Check if Suricata is installed
check_suricata_installation() {
    print_info "Checking Suricata installation..."
    
    if command -v suricata &> /dev/null; then
        local version=$(suricata --version 2>&1 | head -n 1)
        print_success "Suricata is installed: $version"
        
        # Get Suricata build info
        print_info "Suricata build information:"
        suricata --build-info 2>&1 | grep -E "Suricata|Features|Threading" || true
        return 0
    else
        print_error "Suricata is not installed or not in PATH"
        print_info "Install Suricata using your package manager:"
        print_info "  Ubuntu/Debian: sudo apt-get install suricata"
        print_info "  CentOS/RHEL:   sudo yum install suricata"
        print_info "  Fedora:        sudo dnf install suricata"
        return 1
    fi
}

# Identify and display network interfaces
identify_network_interfaces() {
    print_info "Identifying available network interfaces..."
    echo ""
    
    if command -v ip &> /dev/null; then
        # Use ip command (modern approach)
        while IFS= read -r line; do
            if [[ $line =~ ^[0-9]+:\ ([^:]+): ]]; then
                local iface="${BASH_REMATCH[1]}"
                if [[ "$iface" != "lo" ]]; then
                    print_info "Interface: $iface"
                    
                    # Get IP addresses
                    local ipv4=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
                    local ipv6=$(ip -6 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet6\s)[0-9a-f:]+' | head -1)
                    
                    # Get MAC address
                    local mac=$(ip link show "$iface" 2>/dev/null | grep -oP '(?<=link/ether\s)[0-9a-f:]+' | head -1)
                    
                    # Get interface state
                    local state=$(ip link show "$iface" 2>/dev/null | grep -oP '(?<=state\s)\w+' | head -1)
                    
                    echo "    IPv4: ${ipv4:-N/A}"
                    echo "    IPv6: ${ipv6:-N/A}"
                    echo "    MAC:  ${mac:-N/A}"
                    echo "    State: ${state:-N/A}"
                    
                    # Get statistics if available
                    if [[ -f "/sys/class/net/$iface/statistics/rx_packets" ]]; then
                        local rx_packets=$(cat "/sys/class/net/$iface/statistics/rx_packets" 2>/dev/null || echo "0")
                        local tx_packets=$(cat "/sys/class/net/$iface/statistics/tx_packets" 2>/dev/null || echo "0")
                        echo "    RX packets: $rx_packets"
                        echo "    TX packets: $tx_packets"
                    fi
                    echo ""
                fi
            fi
        done < <(ip link show)
    elif command -v ifconfig &> /dev/null; then
        # Fallback to ifconfig
        print_warning "Using legacy ifconfig command"
        ifconfig -a | grep -E "^[a-z]|inet |ether " | grep -v "127.0.0.1"
    else
        print_error "Neither 'ip' nor 'ifconfig' command found"
        return 1
    fi
    
    print_success "Network interface enumeration complete"
}

# Setup directory structure
setup_directories() {
    if [[ "$CHECK_ONLY" == true ]]; then
        print_info "Skipping directory setup (check-only mode)"
        return 0
    fi
    
    print_info "Setting up directory structure..."
    
    local dirs=("$LOG_DIR" "$DEFAULT_RUN_DIR")
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            print_success "Directory exists: $dir"
        else
            print_info "Creating directory: $dir"
            if mkdir -p "$dir" 2>/dev/null; then
                print_success "Created: $dir"
            else
                print_warning "Failed to create $dir (may need sudo)"
                if [[ $EUID -ne 0 ]]; then
                    print_info "Try running: sudo mkdir -p $dir"
                fi
            fi
        fi
    done
}

# Create symbolic links if needed
create_symlinks() {
    if [[ "$CHECK_ONLY" == true ]]; then
        print_info "Skipping symlink creation (check-only mode)"
        return 0
    fi
    
    print_info "Checking for symbolic links..."
    
    # Check if we're in a git repository with rules
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local repo_root="$(dirname "$script_dir")"
    
    if [[ -d "$repo_root/rules" ]]; then
        print_info "Found rules directory in repository: $repo_root/rules"
        
        # Suggest creating symlink to system location
        local system_rules="/etc/suricata/rules"
        if [[ -d "/etc/suricata" ]] && [[ ! -L "$system_rules" ]]; then
            print_info "You may want to create a symlink from $system_rules to $repo_root/rules"
            print_info "Run: sudo ln -sf $repo_root/rules $system_rules"
        fi
    fi
    
    print_success "Symlink check complete"
}

# Set proper permissions
set_permissions() {
    if [[ "$CHECK_ONLY" == true ]]; then
        print_info "Skipping permission changes (check-only mode)"
        return 0
    fi
    
    print_info "Setting proper permissions..."
    
    local has_root=false
    if [[ $EUID -eq 0 ]]; then
        has_root=true
    fi
    
    # Try to set permissions on log directory
    if [[ -d "$LOG_DIR" ]]; then
        if $has_root; then
            chmod 755 "$LOG_DIR" 2>/dev/null || print_warning "Could not set permissions on $LOG_DIR"
            print_success "Set permissions on $LOG_DIR"
        else
            print_warning "Root privileges needed to set permissions on $LOG_DIR"
        fi
    fi
    
    # Check if suricata user/group exists
    if getent passwd suricata > /dev/null 2>&1; then
        print_success "Suricata user exists"
        if $has_root && [[ -d "$LOG_DIR" ]]; then
            chown -R suricata:suricata "$LOG_DIR" 2>/dev/null || print_warning "Could not set ownership on $LOG_DIR"
        fi
    else
        print_warning "Suricata user does not exist (will run as root or current user)"
    fi
}

# Validate Suricata configuration
validate_configuration() {
    print_info "Validating Suricata configuration..."
    
    local config_file="$DEFAULT_CONFIG"
    
    # Check if config file exists
    if [[ ! -f "$config_file" ]]; then
        # Try to find config in common locations
        local alt_configs=(
            "/etc/suricata/suricata.yaml"
            "/usr/local/etc/suricata/suricata.yaml"
            "$(dirname "${BASH_SOURCE[0]}")/../configs/suricata.yaml"
        )
        
        for alt_config in "${alt_configs[@]}"; do
            if [[ -f "$alt_config" ]]; then
                config_file="$alt_config"
                print_info "Found config at: $config_file"
                break
            fi
        done
    fi
    
    if [[ ! -f "$config_file" ]]; then
        print_warning "Configuration file not found: $config_file"
        print_info "Common locations:"
        print_info "  - /etc/suricata/suricata.yaml"
        print_info "  - /usr/local/etc/suricata/suricata.yaml"
        return 1
    fi
    
    print_success "Configuration file found: $config_file"
    
    # Validate configuration syntax
    if command -v suricata &> /dev/null; then
        print_info "Running configuration test..."
        if suricata -T -c "$config_file" 2>&1 | grep -q "Configuration provided was successfully loaded"; then
            print_success "Configuration validation passed!"
        else
            print_error "Configuration validation failed"
            print_info "Run 'suricata -T -c $config_file' for details"
            return 1
        fi
    else
        print_warning "Cannot validate config: Suricata not installed"
    fi
    
    return 0
}

# Display summary
display_summary() {
    echo ""
    echo "======================================"
    print_info "SETUP SUMMARY"
    echo "======================================"
    echo ""
    echo "Log Directory:    $LOG_DIR"
    echo "Run Directory:    $DEFAULT_RUN_DIR"
    echo "Config File:      $DEFAULT_CONFIG"
    echo ""
    print_info "Next Steps:"
    echo "  1. Update Suricata rules: sudo suricata-update"
    echo "  2. Configure network interface in $DEFAULT_CONFIG"
    echo "  3. Start Suricata: sudo systemctl start suricata"
    echo "  4. Check status: sudo systemctl status suricata"
    echo ""
    print_success "Setup complete!"
}

# Main function
main() {
    echo "======================================"
    echo "  Suricata IDS Setup Script"
    echo "======================================"
    echo ""
    
    # Parse arguments
    parse_arguments "$@"
    
    # Run checks and setup
    check_privileges || true
    check_suricata_installation || exit 1
    echo ""
    
    identify_network_interfaces
    echo ""
    
    setup_directories
    echo ""
    
    create_symlinks
    echo ""
    
    set_permissions
    echo ""
    
    validate_configuration || true
    echo ""
    
    display_summary
}

# Run main function
main "$@"
