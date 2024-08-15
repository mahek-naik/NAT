import tkinter as tk
from tkinter import ttk
import threading
import glob
import os
import scan
import ddos
import vuln

def main_window():
    # main window
    window = tk.Tk()
    window.title("Network Attack Tool")
    window.geometry("800x600")

    # 2 main frames
    frame1 = tk.Frame(window, width=600, height=200)
    frame2 = tk.Frame(window, width=600, height=300)
    frame1.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    frame2.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    # tabbed interface in frame1
    tabs = ttk.Notebook(frame1)
    network_tab = ttk.Frame(tabs)
    cve_tab = ttk.Frame(tabs)
    ddos_tab = ttk.Frame(tabs)

    tabs.add(network_tab, text="Network")
    tabs.add(cve_tab, text="CVEs")
    tabs.add(ddos_tab, text="DDoS")
    tabs.pack(expand=True, fill="both")

    # 3 subframes in frame2
    frame2_1 = tk.Frame(frame2)
    frame2_2 = tk.Frame(frame2, width=600, height=10)
    frame2_1.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)
    frame2_2.pack(side=tk.TOP, fill=tk.BOTH, expand=False, padx=10, pady=5)

    # Output text widgets for each tab
    output_text_widgets = {
        "network": None,
        "cve": None,
        "ddos": None
    }

    # Scrollbars for the output boxes
    scrollbars = {
        "network": None,
        "cve": None,
        "ddos": None
    }

    # Function to create an output box in frame2_1
    def create_output_box(tab_name):
        if output_text_widgets[tab_name] is None:
            output_text = tk.Text(frame2_1, bg="white", relief=tk.SUNKEN)
            scrollbar = tk.Scrollbar(frame2_1, command=output_text.yview)
            output_text.config(yscrollcommand=scrollbar.set)

            output_text_widgets[tab_name] = output_text
            scrollbars[tab_name] = scrollbar

        output_text_widgets[tab_name].pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        scrollbars[tab_name].pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)

    # Function to hide all output boxes
    def hide_all_output_boxes():
        for output_text in output_text_widgets.values():
            if output_text is not None:
                output_text.pack_forget()
        for scrollbar in scrollbars.values():
            if scrollbar is not None:
                scrollbar.pack_forget()

    # Function to delete JSON files
    def delete_json_files():
        files = glob.glob('*.json')
        for f in files:
            os.remove(f)

    # Function to append text to the output box
    def append_to_output(tab_name, text):
        if output_text_widgets[tab_name] is not None:
            output_text_widgets[tab_name].insert(tk.END, text + '\n')
            output_text_widgets[tab_name].see(tk.END)

    # Configuration of Network tab
    def create_network_layout():
        hide_all_output_boxes()
        tk.Label(network_tab, text="Network").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        tk.Label(network_tab, text="Analysis").grid(row=0, column=1, sticky="w", pady=10)
        tk.Label(network_tab, text="Target:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        target_entry = tk.Entry(network_tab)
        target_entry.grid(row=1, column=1, padx=10, pady=5)
        tk.Label(network_tab, text="Scan Options:").grid(row=1, column=2, sticky="w", padx=20, pady=5)
        options = ttk.Combobox(network_tab, values=["Host Scan", "Port Scan", "Service Scan", "OS Detection"], state="readonly")
        options.grid(row=1, column=3, padx=10, pady=5)
        tk.Button(network_tab, text="Scan", width=10, height=1, command=lambda: run_network_scan(target_entry.get(), options.get())).grid(row=1, column=4, sticky="w", padx=10, pady=5)
        tk.Button(network_tab, text="New Scan", width=10, height=1, command=lambda: new_scan()).grid(row=1, column=5, sticky="w", padx=10, pady=5)
        create_output_box("network")

    # Function for new scan button
    def new_scan():
        delete_json_files()
        append_to_output("network", "Ready for new scan.\n")

    # Function of scan options in network tab
    def run_network_scan(target, option):
        if option == "Host Scan":
            append_to_output("network", f"\nScanning for active hosts in '{target}'...\n")
            result = scan.host_scan(target)
            if result:
                append_to_output("network", f"Active Host(s):\n")
                for active_host in result:
                    append_to_output("network", f"{active_host}")
            else:
                append_to_output("network", f"No active host found in '{target}'.")
                
        elif option == "Port Scan":
            append_to_output("network", f"\nScanning for open ports in '{target}'...\n")
            result = scan.port_scan(target)
            if result:
                for active_host, ports in result.items():
                    append_to_output("network", f"Host: {active_host}")
                    append_to_output("network", f"\tPort\tProtocol")
                    for port, proto in ports.items():
                        append_to_output("network", f"\t{port}\t{proto}")
            else:
                append_to_output("network", f"No open ports found in '{target}'.")

        elif option == "Service Scan":
            append_to_output("network", f"\nScanning for services on open ports in '{target}'...\n")
            result = scan.service_scan(target)
            if result:
                for ip, ports in result.items():
                    append_to_output("network", f"Host: {ip}")
                    append_to_output("network", f"\tPort\tProtocol\tService")
                    for port, details in ports.items():
                        proto = details['protocol']
                        service = details['service']
                        append_to_output("network", f"\t{port}\t{proto}\t{service}")
            else:
                append_to_output("network", f"No services found on open ports of '{target}'.")

        elif option == "OS Detection":
            append_to_output("network", f"\nDetecting OS for '{target}'...\n")
            result = scan.os_detection(target)
            if result:
                for active_host, details in result.items():
                    append_to_output("network", f"Host\t\tOS\t\tVersion")
                    os = details.get('os', 'N/A')
                    ver = details.get('version', 'N/A')
                
                append_to_output("network", f"{active_host}\t\t{os}\t\t{ver}")
            else:
                append_to_output("network", f"No OS detected in '{target}'.")
        append_to_output("network", f"\n--------------------------------------------------------------------------------------------")

    # Configuration of Exploit tab
    def create_exploit_layout():
        hide_all_output_boxes()
        tk.Label(cve_tab, text="CVE(s)").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        tk.Label(cve_tab, text="Service:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        service_entry = tk.Entry(cve_tab)
        service_entry.grid(row=1, column=1, padx=10, pady=5)
        tk.Button(cve_tab, text="Search", width=10, height=1, command=lambda: search_exploits(service_entry.get())).grid(row=1, column=2, sticky="w", padx=10, pady=5)
        create_output_box("cve")

    # Function to search for vulnerabilities
    def search_exploits(service_name):
        append_to_output("cve", f"Searching vulnerabilities for service '{service_name}'...\n")
        results = vuln.get_vulnerabilities(service_name)
        if results:
            for index, vuln_data in enumerate(results, start=1):
                cve = vuln_data.get('cve', {})
                cve_id = cve.get('id', 'N/A')
                description = cve.get('descriptions', [{}])[0].get('value', 'N/A')

                append_to_output("cve", f"{index}. CVE ID: {cve_id}")
                append_to_output("cve", f"Description: {description}")
                append_to_output("cve", "")  # Blank line for separation
        else:
            append_to_output("cve", f"No vulnerabilities found for service '{service_name}'.")
        append_to_output("cve", f"\n--------------------------------------------------------------------------------------------")

    # Configuration of DDoS tab
    def create_ddos_layout():
        hide_all_output_boxes()
        tk.Label(ddos_tab, text="DDoS Attack").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        tk.Label(ddos_tab, text="Target IP address:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        target_entry = tk.Entry(ddos_tab)
        target_entry.grid(row=1, column=1, padx=10, pady=5)
        tk.Label(ddos_tab, text="No. of threads:").grid(row=1, column=2, sticky="w", padx=20, pady=5)
        threads_entry = tk.Entry(ddos_tab)
        threads_entry.grid(row=1, column=3, padx=10, pady=5)
        tk.Button(ddos_tab, text="Attack", width=10, height=1, command=lambda: run_ddos_attack(target_entry.get(), int(threads_entry.get()))).grid(row=1, column=4, sticky="w", padx=10, pady=5)
        create_output_box("ddos")

    # DDoS attack functions
    def run_ddos_attack(target, threads):
        append_to_output("ddos", f"Starting DDoS attack on {target} with {threads} threads")
        for _ in range(threads):
            thread = threading.Thread(target=ddos.requests, args=(target,))
            thread.start()
        append_to_output("ddos", f"\n--------------------------------------------------------------------------------------------")

    # Function to delete json files and close the window
    def exit_window():
        delete_json_files()
        window.quit()  # Close the main window

    # Configuration of stop button in frame2_2
    stop_button = tk.Button(frame2_2, text="Stop", width=10, height=1, command=exit_window)
    stop_button.pack(side=tk.RIGHT, padx=38, pady=10)

    tabs.bind("<<NotebookTabChanged>>", lambda event: (
        create_network_layout() if tabs.index("current") == 0 else (
            create_exploit_layout() if tabs.index("current") == 1 else create_ddos_layout()
        )
    ))

    window.update_idletasks()  # Update the GUI to calculate the proper size

    create_network_layout()

    window.mainloop()