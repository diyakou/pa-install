#!/bin/bash

# Paqet Reverse Tunnel Troubleshooting Script
# Diagnoses common issues with paqet deployments

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "\n${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║ Paqet Troubleshooting Tool            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}\n"
}

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test 1: Check if running as root
check_privileges() {
    print_test "Checking privileges..."
    if [[ $EUID -eq 0 ]]; then
        print_pass "Running with root privileges"
        return 0
    else
        print_fail "Not running as root. Some tests require sudo."
        return 1
    fi
}

# Test 2: Check paqet binary
check_paqet_binary() {
    print_test "Checking paqet binary..."
    if command -v paqet &> /dev/null; then
        local version=$(paqet version 2>/dev/null || echo "unknown")
        print_pass "paqet found: $version"
        which paqet
        return 0
    else
        print_fail "paqet binary not found in PATH"
        print_warn "Try: export PATH=\$PATH:/path/to/paqet"
        return 1
    fi
}

# Test 3: Check libpcap
check_libpcap() {
    print_test "Checking libpcap..."
    if dpkg -l 2>/dev/null | grep -q libpcap; then
        print_pass "libpcap-dev installed"
        return 0
    elif rpm -q libpcap-devel &>/dev/null 2>&1; then
        print_pass "libpcap-devel installed"
        return 0
    else
        print_fail "libpcap not found"
        print_warn "Install: sudo apt-get install libpcap-dev (Debian/Ubuntu)"
        print_warn "        sudo yum install libpcap-devel (CentOS/RHEL)"
        return 1
    fi
}

# Test 4: Check configuration files
check_config_files() {
    print_test "Checking configuration files..."
    local found=0
    for config in config*.yaml; do
        if [ -f "$config" ]; then
            print_pass "Found: $config"
            found=1
        fi
    done
    if [ $found -eq 0 ]; then
        print_fail "No configuration files found"
        print_warn "Run: ./deploy-paqet-reverse-tunnel.sh --mode server"
        return 1
    fi
    return 0
}

# Test 5: Validate configuration syntax
validate_config() {
    print_test "Validating configuration syntax..."
    for config in config*.yaml; do
        if [ -f "$config" ]; then
            if grep -q "role:" "$config" && (grep -q "client\|server" "$config"); then
                print_pass "Configuration valid: $config"
            else
                print_fail "Invalid configuration: $config"
                return 1
            fi
        fi
    done
    return 0
}

# Test 6: Check network interfaces
check_network_interfaces() {
    print_test "Checking network interfaces..."
    if command -v ip &> /dev/null; then
        local interfaces=$(ip link show | grep "^[0-9]" | awk '{print $2}' | cut -d':' -f1)
        if [ -z "$interfaces" ]; then
            print_fail "No network interfaces found"
            return 1
        fi
        print_pass "Available interfaces: $interfaces"
        return 0
    else
        print_warn "ip command not found, cannot check interfaces"
        return 1
    fi
}

# Test 7: Check gateway connectivity
check_gateway() {
    print_test "Checking gateway..."
    if command -v ip &> /dev/null; then
        local gateway=$(ip route | grep default | awk '{print $3}')
        if [ -z "$gateway" ]; then
            print_fail "No default gateway found"
            return 1
        fi
        print_pass "Default gateway: $gateway"
        
        if ping -c 1 "$gateway" &>/dev/null 2>&1; then
            print_pass "Gateway is reachable"
        else
            print_fail "Gateway is not reachable"
            return 1
        fi
    fi
}

# Test 8: Check iptables rules
check_iptables() {
    print_test "Checking iptables rules..."
    if ! command -v iptables &> /dev/null; then
        print_warn "iptables not found"
        return 1
    fi
    
    local port=$(grep -h "port.*9999" config*.yaml 2>/dev/null | head -1 | grep -o "9999\|[0-9]\{4,5\}" | head -1)
    port=${port:-9999}
    
    print_test "Checking rules for port $port..."
    
    if sudo iptables -t raw -L PREROUTING -n 2>/dev/null | grep -q "$port"; then
        print_pass "PREROUTING NOTRACK rule present"
    else
        print_fail "PREROUTING NOTRACK rule missing"
        echo "  Run: sudo iptables -t raw -A PREROUTING -p tcp --dport $port -j NOTRACK"
    fi
    
    if sudo iptables -t mangle -L OUTPUT -n 2>/dev/null | grep -q "RST RST"; then
        print_pass "OUTPUT RST DROP rule present"
    else
        print_fail "OUTPUT RST DROP rule missing"
        echo "  Run: sudo iptables -t mangle -A OUTPUT -p tcp --sport $port --tcp-flags RST RST -j DROP"
    fi
}

# Test 9: Check service status
check_service_status() {
    print_test "Checking paqet service status..."
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet paqet-server; then
            print_pass "paqet-server is running"
            return 0
        else
            print_warn "paqet-server is not running"
            echo "  Start with: sudo systemctl start paqet-server"
            return 1
        fi
    else
        print_warn "systemctl not found, cannot check service status"
        return 1
    fi
}

# Test 10: Check listening ports
check_listening_ports() {
    print_test "Checking listening ports..."
    if command -v ss &> /dev/null; then
        local port=$(grep -h "port.*:" config*.yaml 2>/dev/null | head -1 | grep -o "9999\|[0-9]\{4,5\}" | head -1)
        port=${port:-9999}
        
        if ss -tlnp 2>/dev/null | grep -q ":$port"; then
            print_pass "Port $port is listening"
            ss -tlnp | grep ":$port"
            return 0
        else
            print_fail "Port $port is not listening"
            return 1
        fi
    elif command -v netstat &> /dev/null; then
        local port=$(grep -h "port.*:" config*.yaml 2>/dev/null | head -1 | grep -o "9999\|[0-9]\{4,5\}" | head -1)
        port=${port:-9999}
        
        if netstat -tlnp 2>/dev/null | grep -q ":$port"; then
            print_pass "Port $port is listening"
            netstat -tlnp | grep ":$port"
            return 0
        else
            print_fail "Port $port is not listening"
            return 1
        fi
    fi
}

# Test 11: Check firewall blocking
check_firewall_block() {
    print_test "Checking firewall blocking..."
    if command -v ufw &> /dev/null && ufw status | grep -q active; then
        local port=$(grep -h "port.*:" config*.yaml 2>/dev/null | head -1 | grep -o "9999\|[0-9]\{4,5\}" | head -1)
        port=${port:-9999}
        
        if ufw status | grep -q "9999"; then
            print_pass "Port $port is allowed in ufw"
        else
            print_warn "Port $port may be blocked by ufw"
            echo "  Run: sudo ufw allow $port/tcp"
        fi
    fi
}

# Test 12: Check encryption key
check_encryption_key() {
    print_test "Checking encryption keys..."
    local client_key=$(grep -h "key:" config-client*.yaml 2>/dev/null | head -1 | awk '{print $NF}')
    local server_key=$(grep -h "key:" config-server*.yaml 2>/dev/null | head -1 | awk '{print $NF}')
    
    if [ -z "$client_key" ] || [ -z "$server_key" ]; then
        print_fail "Could not find encryption keys in configuration"
        return 1
    fi
    
    if [ "$client_key" = "$server_key" ]; then
        print_pass "Client and server keys match"
        echo "  Key: ${client_key:0:20}..."
        return 0
    else
        print_fail "Client and server keys DO NOT MATCH!"
        echo "  Client key: ${client_key:0:20}..."
        echo "  Server key: ${server_key:0:20}..."
        return 1
    fi
}

# Test 13: Check packet capture
check_pcap_access() {
    print_test "Checking packet capture permissions..."
    if command -v tcpdump &> /dev/null; then
        if sudo tcpdump -D &>/dev/null 2>&1; then
            print_pass "tcpdump access working"
            return 0
        else
            print_fail "tcpdump access denied"
            return 1
        fi
    else
        print_warn "tcpdump not found"
        return 1
    fi
}

# Test 14: Network connectivity to server
check_server_connectivity() {
    print_test "Checking connectivity to server..."
    local server_addr=$(grep -h "addr:" config-client*.yaml 2>/dev/null | grep "server:" -A 1 | tail -1 | awk '{print $NF}' | sed 's/[":]*//g')
    
    if [ -z "$server_addr" ]; then
        print_warn "Could not determine server address"
        return 1
    fi
    
    local server_ip=$(echo "$server_addr" | cut -d':' -f1)
    
    if ping -c 1 "$server_ip" &>/dev/null 2>&1; then
        print_pass "Server $server_ip is reachable"
        return 0
    else
        print_fail "Server $server_ip is not reachable"
        return 1
    fi
}

# Test 15: Check disk space
check_disk_space() {
    print_test "Checking disk space..."
    local available=$(df /var/log | tail -1 | awk '{print $4}')
    if [ "$available" -gt 102400 ]; then  # 100MB
        print_pass "Sufficient disk space available: $(numfmt --to=iec $available 2>/dev/null || echo $available KB)"
        return 0
    else
        print_warn "Low disk space available"
        return 1
    fi
}

# Run all tests
run_all_tests() {
    echo ""
    local tests=(
        "check_privileges"
        "check_paqet_binary"
        "check_libpcap"
        "check_config_files"
        "validate_config"
        "check_network_interfaces"
        "check_gateway"
        "check_iptables"
        "check_service_status"
        "check_listening_ports"
        "check_firewall_block"
        "check_encryption_key"
        "check_pcap_access"
        "check_server_connectivity"
        "check_disk_space"
    )
    
    local passed=0
    local failed=0
    local warned=0
    
    for test in "${tests[@]}"; do
        if $test > /dev/null 2>&1; then
            ((passed++))
        else
            case $? in
                1) ((failed++)) ;;
                2) ((warned++)) ;;
            esac
        fi
    done
    
    echo -e "\n${CYAN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}Passed: $passed${NC}  ${YELLOW}Warned: $warned${NC}  ${RED}Failed: $failed${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}\n"
}

# Print quick diagnostics
print_diagnostics() {
    echo ""
    echo -e "${CYAN}Quick Diagnostics:${NC}"
    echo ""
    echo "Configuration files:"
    ls -la config*.yaml 2>/dev/null || echo "  (none found)"
    
    echo ""
    echo "paqet process:"
    ps aux | grep -i paqet | grep -v grep || echo "  (not running)"
    
    echo ""
    echo "Recent logs (last 5):"
    if command -v journalctl &> /dev/null; then
        sudo journalctl -u paqet-server -n 5 2>/dev/null || echo "  (no journal)"
    fi
}

# Main
print_header

case "${1:-all}" in
    all)
        run_all_tests
        print_diagnostics
        ;;
    network)
        check_network_interfaces
        check_gateway
        check_server_connectivity
        ;;
    config)
        check_config_files
        validate_config
        check_encryption_key
        ;;
    service)
        check_service_status
        check_listening_ports
        check_iptables
        ;;
    firewall)
        check_iptables
        check_firewall_block
        ;;
    diag)
        print_diagnostics
        ;;
    *)
        echo "Usage: $0 [all|network|config|service|firewall|diag]"
        echo ""
        echo "Examples:"
        echo "  $0 all          - Run all diagnostics"
        echo "  $0 network      - Check network connectivity"
        echo "  $0 config       - Validate configuration"
        echo "  $0 service      - Check paqet service"
        echo "  $0 firewall     - Check firewall rules"
        echo "  $0 diag         - Quick diagnostics"
        ;;
esac
