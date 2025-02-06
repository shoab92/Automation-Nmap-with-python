import nmap

def scan_network(target, scan_types):
    nm = nmap.PortScanner()

    # Convert scan types list to a single command argument
    scan_command = " ".join(scan_types)

    print("\n🔹 Starting Nmap Scan...")
    print(f"🔍 Target: {target}")
    print(f"📌 Selected Scans: {scan_command}")

    try:
        # Running all selected scans together in a single execution
        nm.scan(target, arguments=scan_command)
        display_results(nm)

        print("\n✅ Scan Completed Successfully!")

    except Exception as e:
        print(f"\n❌ Error: {e}")

def display_results(nm):
    """ Display results of the scan """
    for host in nm.all_hosts():
        print("\n==========================================")
        print(f"📌 Host: {host} ({nm[host].hostname()})")
        print(f"🟢 State: {nm[host].state()}")

        # OS Detection
        if 'osclass' in nm[host]:
            print("\n🛠 Possible OS Detected:")
            for os in nm[host]['osclass']:
                print(f"🔹 OS: {os['osfamily']} | Accuracy: {os['accuracy']}%")

        # Protocol & Port Scans
        for proto in nm[host].all_protocols():
            print(f"\n🖥 Protocol: {proto.upper()}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port].get('name', 'unknown')
                product = nm[host][proto][port].get('product', 'N/A')
                version = nm[host][proto][port].get('version', 'N/A')
                state = nm[host][proto][port]['state']
                print(f"  🔹 Port {port} | State: {state} | Service: {service} | Version: {product} {version}")

if __name__ == "__main__":
    print("\n🔹 Advanced Multi-Scan Nmap Automation Script")
    target_ip = input("📌 Enter target IP or range: ")

    print("\n🔍 Choose Scan Types (select multiple, comma-separated):")
    print("  1️⃣ SYN Scan (-sS) [Stealth Scan]")
    print("  2️⃣ TCP Connect Scan (-sT)")
    print("  3️⃣ ACK Scan (-sA)")
    print("  4️⃣ IP Protocol Scan (-sO)")
    print("  5️⃣ OS Detection (-O)")
    print("  6️⃣ Service & Version Detection (-sV)")
    print("  7️⃣ Aggressive Scan (-A) [Detailed Info]")

    scan_options = input("\n📌 Enter scan numbers (e.g., 1,3,5): ")

    scan_types_dict = {
        "1": "-sS",
        "2": "-sT",
        "3": "-sA",
        "4": "-sO",
        "5": "-O",
        "6": "-sV",
        "7": "-A"
    }

    selected_scans = [scan_types_dict[num] for num in scan_options.split(",") if num in scan_types_dict]

    if selected_scans:
        scan_network(target_ip, selected_scans)
    else:
        print("\n❌ Invalid selection! Please restart and select valid scan types.")
