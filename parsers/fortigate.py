import re
import pandas as pd
import logging
import os
from datetime import datetime


class NATEntry:
    """
    Base class for NAT configuration entries.
    Holds common fields for both IP Pools and VIP entries.
    """

    def __init__(self, name, vdom=""):
        self.name = name
        self.vdom = vdom
        self.start_ip_range = ""
        self.mapped_ip = ""
        self.type = ""
        self.associated_interface = ""
        self.comment = ""
        # New fields for enhanced IP Pool information
        self.src_interfaces = set()  # Source interfaces from associated firewall rules
        self.dst_interfaces = set()  # Destination interfaces from associated firewall rules
        self.mapped_ips = set()      # Mapped IPs
        self.associated_fw_rules = set()  # Associated firewall rule IDs

    def to_dict(self):
        """
        Returns the NATEntry as a dictionary.
        """
        return {
            "Name": self.name,
            "VDOM": self.vdom,
            "Start IP/Range": self.start_ip_range,
            "Mapped IP": self.mapped_ip,
            "Type": self.type,
            "Associated Interface": self.associated_interface,
            "Comment": self.comment,
            "Src IF(s)": ", ".join(sorted(self.src_interfaces)),
            "Dst IF(s)": ", ".join(sorted(self.dst_interfaces)),
            "Mapped IP(s)": ", ".join(sorted(self.mapped_ips)),
            "Associated FW Rules": ", ".join(sorted(self.associated_fw_rules))
        }


class VRFEntry:
    """
    Class representing a VRF (VDOM) entry in the FortiGate configuration.
    """
    
    def __init__(self, name):
        self.name = name
        self.vrf_number = None  # Will be populated later if available
        self.interfaces = []    # List of interfaces in this VRF
    
    def to_dict(self):
        """
        Returns the VRFEntry as a dictionary.
        """
        return {
            "Name": self.name,
            "VRF Number": self.vrf_number if self.vrf_number else "",
            "Interface Count": len(self.interfaces)
        }


class InterfaceEntry:
    """
    Class representing an interface entry in the FortiGate configuration.
    """
    
    def __init__(self, name, vrf=None):
        self.name = name
        self.vrf = vrf              # Reference to the VRF object
        self.vrf_number = None      # VRF number if specified
        self.type = ""              # Interface type (physical, vlan, etc.)
        self.vlan_id = None         # VLAN ID if applicable
        self.management_ip = ""     # Management IP in CIDR format
        self.ip = ""                # IP address in CIDR format
        self.alias = ""             # Interface alias
        self.description = ""       # Interface description
        self.status = ""            # Interface status (up/down)
    
    def to_dict(self):
        """
        Returns the InterfaceEntry as a dictionary.
        """
        return {
            "Name": self.name,
            "VRF": self.vrf.name if self.vrf else "",
            "VRF Number": self.vrf_number if self.vrf_number else "",
            "Type": self.type,
            "VLAN ID": self.vlan_id if self.vlan_id else "",
            "Management IP": self.management_ip,
            "IP": self.ip,
            "Alias": self.alias,
            "Description": self.description,
            "Status": self.status
        }


class FirewallPolicyEntry:
    """
    Class representing a firewall policy entry in the FortiGate configuration.
    """
    
    def __init__(self, id, vdom=""):
        self.id = id
        self.vdom = vdom
        self.name = ""
        self.status = ""
        self.src_interface = ""
        self.dst_interface = ""
        self.action = ""
        self.src_address = ""
        self.dst_address = ""
        self.schedule = ""
        self.service = ""
        self.ips_sensor = ""
        self.ippool_status = "disable"
        self.nat_status = "disable"
        self.nat_ip = ""
        self.pool_name = ""
        self.comments = ""
    
    def to_dict(self):
        """
        Returns the FirewallPolicyEntry as a dictionary.
        """
        return {
            "Entry ID": self.id,
            "VDOM": self.vdom,
            "Name": self.name,
            "Status": self.status,
            "Src IF": self.src_interface,
            "Dst IF": self.dst_interface,
            "Action": self.action,
            "Src Address": self.src_address,
            "Dst Address": self.dst_address,
            "Schedule": self.schedule,
            "Service": self.service,
            "IPS Sensor": self.ips_sensor,
            "IPPool Status": self.ippool_status,
            "NAT Status": self.nat_status,
            "NAT IP": self.nat_ip,
            "Pool Name": self.pool_name,
            "Comments": self.comments
        }


class NATParser:
    """
    Parser for FortiGate NAT configuration file.

    This class parses the configuration file to extract:
      - The current VDOM from 'config vdom' sections.
      - NAT configuration entries from the 'config firewall ippool' section.
      - NAT configuration entries from the 'config firewall vip' section.
      - VRF (VDOM) information from 'config vdom' sections.
      - Interface information from 'config system interface' sections.
      - Firewall policy information from 'config firewall policy' sections.
    """

    def __init__(self, filename):
        self.filename = filename
        self.lines = []
        self.current_vdom = ""
        self.ippool_entries = []
        self.vip_entries = []
        self.vrf_entries = {}       # Dictionary of VRF entries by name
        self.interface_entries = [] # List of interface entries
        self.fw_policy_entries = [] # List of firewall policy entries
        self.ippool_dict = {}       # Dictionary of IP Pool entries by name for quick lookup
        
        # Compile commonly used regex patterns.
        self.re_config_vdom = re.compile(r'^\s*config vdom', re.IGNORECASE)
        self.re_edit_vdom = re.compile(r'^\s*edit\s+"?([^"\s]+)"?', re.IGNORECASE)
        self.re_config_ippool = re.compile(r'^\s*config firewall ippool', re.IGNORECASE)
        self.re_config_vip = re.compile(r'^\s*config firewall vip', re.IGNORECASE)
        self.re_config_interface = re.compile(r'^\s*config system interface', re.IGNORECASE)
        self.re_config_fw_policy = re.compile(r'^\s*config firewall policy', re.IGNORECASE)
        self.re_end = re.compile(r'^\s*end\s*$', re.IGNORECASE)
        self.re_set = re.compile(r'^\s*set\s+(\S+)\s+(.*)$', re.IGNORECASE)
        self.re_edit = re.compile(r'^\s*edit\s+"?([^"\s]+)"?', re.IGNORECASE)
        self.re_edit_number = re.compile(r'^\s*edit\s+(\d+)', re.IGNORECASE)
        logging.debug("Initialized NATParser with filename: %s", filename)

    def load_file(self):
        """
        Loads the configuration file into a list of lines.
        """
        logging.debug("Loading file: %s", self.filename)
        with open(self.filename, 'r') as f:
            self.lines = f.readlines()
        logging.debug("Loaded %d lines.", len(self.lines))

    def parse(self):
        """
        Main method to parse the configuration file.
        This method iterates through each line, updates the current VDOM,
        and calls parsing methods for ippool, vip, vdom, interface, and firewall policy sections.
        """
        self.load_file()
        i = 0
        in_ippool = False
        in_vip = False
        in_interface = False
        in_fw_policy = False
        current_entry = None
        current_interface = None
        current_fw_policy = None
        interface_section_level = 0  # Track the indentation level of the interface section
        fw_policy_section_level = 0  # Track the indentation level of the firewall policy section

        while i < len(self.lines):
            line = self.lines[i].strip()
            raw_line = self.lines[i]  # Get the original line with indentation
            logging.debug("Processing line %d: %s", i, line)

            # Detect a VDOM block and extract the VDOM name.
            if self.re_config_vdom.match(line):
                logging.info("Found config vdom at line %d", i)
                i = self.parse_vdom_section(i + 1)
                continue

            # Detect the start of the ippool section.
            if self.re_config_ippool.match(line):
                logging.info("Entering ippool section at line %d", i)
                in_ippool = True
                i += 1
                continue

            # Detect the start of the vip section.
            if self.re_config_vip.match(line):
                logging.info("Entering vip section at line %d", i)
                in_vip = True
                i += 1
                continue
                
            # Detect the start of the interface section.
            if self.re_config_interface.match(line):
                logging.info("Entering interface section at line %d", i)
                in_interface = True
                interface_section_level = len(raw_line) - len(raw_line.lstrip())  # Calculate indentation level
                i += 1
                continue
                
            # Detect the start of the firewall policy section.
            if self.re_config_fw_policy.match(line):
                logging.info("Entering firewall policy section at line %d", i)
                in_fw_policy = True
                fw_policy_section_level = len(raw_line) - len(raw_line.lstrip())  # Calculate indentation level
                i += 1
                continue

            # Process lines if inside the ippool section.
            if in_ippool:
                if line.startswith("edit"):
                    # Save previous entry if exists.
                    if current_entry is not None:
                        current_entry.vdom = self.current_vdom
                        self.ippool_entries.append(current_entry)
                        # Add to dictionary for quick lookup
                        self.ippool_dict[current_entry.name] = current_entry
                        logging.info("Saved ippool entry: %s", current_entry.name)
                    # Create a new NATEntry for ippool.
                    name = line.split("edit", 1)[1].strip().strip('"')
                    current_entry = NATEntry(name, self.current_vdom)
                    logging.info("Created new ippool entry with name: %s", name)
                else:
                    match_set = self.re_set.match(line)
                    if match_set and current_entry:
                        key = match_set.group(1).lower()
                        value = match_set.group(2).strip().strip('"')
                        logging.info("Found set command in ippool: %s = %s", key, value)
                        if key == "startip":
                            current_entry.start_ip_range = value
                            current_entry.mapped_ips.add(value)
                        elif key == "endip":
                            # Add the range to mapped_ips
                            if current_entry.start_ip_range:
                                current_entry.mapped_ips.add(f"{current_entry.start_ip_range}-{value}")
                        elif key == "type":
                            current_entry.type = value
                        elif key == "associated-interface":
                            current_entry.associated_interface = value
                        elif key == "comments":
                            current_entry.comment = value
                if self.re_end.match(line):
                    if current_entry is not None:
                        current_entry.vdom = self.current_vdom
                        self.ippool_entries.append(current_entry)
                        # Add to dictionary for quick lookup
                        self.ippool_dict[current_entry.name] = current_entry
                        logging.info("Ending ippool section, saved entry: %s", current_entry.name)
                        current_entry = None
                    in_ippool = False
                i += 1
                continue

            # Process lines if inside the vip section.
            if in_vip:
                if line.startswith("edit"):
                    # Save previous entry if exists.
                    if current_entry is not None:
                        current_entry.vdom = self.current_vdom
                        self.vip_entries.append(current_entry)
                        logging.info("Saved vip entry: %s", current_entry.name)
                    # Create a new NATEntry for vip.
                    name = line.split("edit", 1)[1].strip().strip('"')
                    current_entry = NATEntry(name, self.current_vdom)
                    logging.info("Created new vip entry with name: %s", name)
                else:
                    match_set = self.re_set.match(line)
                    if match_set and current_entry:
                        key = match_set.group(1).lower()
                        value = match_set.group(2).strip().strip('"')
                        logging.info("Found set command in vip: %s = %s", key, value)
                        if key == "extip":
                            current_entry.start_ip_range = value
                        elif key == "mappedip":
                            current_entry.mapped_ip = value
                            current_entry.mapped_ips.add(value)
                        elif key == "type":
                            current_entry.type = value
                        elif key == "extintf":
                            current_entry.ext_interface = value
                        elif key == "associated-interface":
                            current_entry.associated_interface = value
                        elif key == "comments":
                            current_entry.comment = value
                if self.re_end.match(line):
                    if current_entry is not None:
                        current_entry.vdom = self.current_vdom
                        self.vip_entries.append(current_entry)
                        logging.info("Ending vip section, saved entry: %s", current_entry.name)
                        current_entry = None
                    in_vip = False
                i += 1
                continue
                
            # Process lines if inside the interface section.
            if in_interface:
                # Debug the current line to help troubleshoot
                logging.debug(f"Interface section line {i}: '{line}'")
                
                # Check if we've reached the end of the interface section
                indentation = len(raw_line) - len(raw_line.lstrip())
                
                # Only end the interface section if we see "end" at the same indentation as "config system interface"
                if line == "end" and indentation == interface_section_level:
                    logging.info(f"Ending interface section at line {i}")
                    # Save the last interface if it exists
                    if current_interface is not None:
                        self.interface_entries.append(current_interface)
                        logging.info(f"Saved final interface entry: {current_interface.name}")
                        current_interface = None
                    in_interface = False
                    i += 1
                    continue
                
                # Check for a new interface entry
                edit_match = re.match(r'^\s*edit\s+"?([^"\s]+)"?', line)
                if edit_match and indentation == interface_section_level + 4:  # +4 for indentation level
                    # Save previous interface if exists
                    if current_interface is not None:
                        self.interface_entries.append(current_interface)
                        logging.info(f"Saved interface entry: {current_interface.name}")
                    
                    # Extract interface name
                    name = edit_match.group(1)
                    # Create a new interface entry
                    current_interface = InterfaceEntry(name)
                    # Don't associate with VRF yet - we'll do that when we process the vdom attribute
                    logging.info(f"Created new interface entry with name: {name} at line {i}")
                elif line.startswith("next") and indentation == interface_section_level + 4:
                    # End of current interface
                    if current_interface is not None:
                        self.interface_entries.append(current_interface)
                        logging.info(f"Saved interface entry at 'next': {current_interface.name}")
                        current_interface = None
                elif current_interface is not None:
                    # Process interface attributes
                    match_set = self.re_set.match(line)
                    if match_set:
                        key = match_set.group(1).lower()
                        value = match_set.group(2).strip().strip('"')
                        logging.debug(f"Found set command in interface {current_interface.name}: {key} = {value}")
                        
                        # Process interface attributes
                        if key == "vdom":
                            # Link to the VRF object
                            vdom_name = value
                            if vdom_name in self.vrf_entries:
                                # Remove from previous VRF if it was assigned
                                if current_interface.vrf and current_interface in current_interface.vrf.interfaces:
                                    current_interface.vrf.interfaces.remove(current_interface)
                                
                                # Assign to new VRF
                                current_interface.vrf = self.vrf_entries[vdom_name]
                                # Add this interface to the VRF's interface list
                                self.vrf_entries[vdom_name].interfaces.append(current_interface)
                        elif key == "vrf":
                            current_interface.vrf_number = value
                        elif key == "type":
                            current_interface.type = value
                        elif key == "ip":
                            # Convert to CIDR format if netmask is provided
                            parts = value.split()
                            if len(parts) >= 2:
                                ip = parts[0]
                                netmask = parts[1]
                                # Convert netmask to CIDR notation
                                try:
                                    # Simple conversion for common netmasks
                                    if netmask == "255.255.255.0":
                                        cidr = "24"
                                    elif netmask == "255.255.0.0":
                                        cidr = "16"
                                    elif netmask == "255.0.0.0":
                                        cidr = "8"
                                    elif netmask == "255.255.255.255":
                                        cidr = "32"
                                    else:
                                        # For other netmasks, count the bits
                                        netmask_parts = netmask.split('.')
                                        binary = ''.join([bin(int(x))[2:].zfill(8) for x in netmask_parts])
                                        cidr = str(binary.count('1'))
                                    
                                    current_interface.ip = f"{ip}/{cidr}"
                                except Exception as e:
                                    logging.warning(f"Error converting netmask to CIDR: {e}")
                                    current_interface.ip = value  # Use original value if conversion fails
                            else:
                                current_interface.ip = value
                        elif key == "management-ip":
                            # Similar conversion for management IP
                            parts = value.split()
                            if len(parts) >= 2:
                                ip = parts[0]
                                netmask = parts[1]
                                # Only process if it's not 0.0.0.0
                                if ip != "0.0.0.0":
                                    try:
                                        if netmask == "255.255.255.0":
                                            cidr = "24"
                                        elif netmask == "255.255.0.0":
                                            cidr = "16"
                                        elif netmask == "255.0.0.0":
                                            cidr = "8"
                                        elif netmask == "255.255.255.255":
                                            cidr = "32"
                                        else:
                                            netmask_parts = netmask.split('.')
                                            binary = ''.join([bin(int(x))[2:].zfill(8) for x in netmask_parts])
                                            cidr = str(binary.count('1'))
                                        
                                        current_interface.management_ip = f"{ip}/{cidr}"
                                    except Exception as e:
                                        logging.warning(f"Error converting management netmask to CIDR: {e}")
                                        current_interface.management_ip = value
                            else:
                                current_interface.management_ip = value
                        elif key == "alias":
                            current_interface.alias = value
                        elif key == "description":
                            current_interface.description = value
                        elif key == "status":
                            current_interface.status = value
                        elif key == "vlanid":
                            current_interface.vlan_id = value
                
                i += 1
                continue
                
            # Process lines if inside the firewall policy section.
            if in_fw_policy:
                # Debug the current line to help troubleshoot
                logging.debug(f"Firewall policy section line {i}: '{line}'")
                
                # Check if we've reached the end of the firewall policy section
                indentation = len(raw_line) - len(raw_line.lstrip())
                
                # Only end the firewall policy section if we see "end" at the same indentation as "config firewall policy"
                if line == "end" and indentation == fw_policy_section_level:
                    logging.info(f"Ending firewall policy section at line {i}")
                    # Save the last firewall policy if it exists
                    if current_fw_policy is not None:
                        self.fw_policy_entries.append(current_fw_policy)
                        logging.info(f"Saved final firewall policy entry: {current_fw_policy.id}")
                        current_fw_policy = None
                    in_fw_policy = False
                    i += 1
                    continue
                
                # Check for a new firewall policy entry
                edit_match = self.re_edit_number.match(line)
                if edit_match and indentation == fw_policy_section_level + 4:  # +4 for indentation level
                    # Save previous firewall policy if exists
                    if current_fw_policy is not None:
                        self.fw_policy_entries.append(current_fw_policy)
                        logging.info(f"Saved firewall policy entry: {current_fw_policy.id}")
                    
                    # Extract firewall policy ID
                    policy_id = edit_match.group(1)
                    # Create a new firewall policy entry
                    current_fw_policy = FirewallPolicyEntry(policy_id, self.current_vdom)
                    logging.info(f"Created new firewall policy entry with ID: {policy_id} at line {i}")
                elif line.startswith("next") and indentation == fw_policy_section_level + 4:
                    # End of current firewall policy
                    if current_fw_policy is not None:
                        self.fw_policy_entries.append(current_fw_policy)
                        logging.info(f"Saved firewall policy entry at 'next': {current_fw_policy.id}")
                        current_fw_policy = None
                elif current_fw_policy is not None:
                    # Process firewall policy attributes
                    match_set = self.re_set.match(line)
                    if match_set:
                        key = match_set.group(1).lower()
                        value = match_set.group(2).strip().strip('"')
                        logging.debug(f"Found set command in firewall policy {current_fw_policy.id}: {key} = {value}")
                        
                        # Process firewall policy attributes
                        if key == "name":
                            current_fw_policy.name = value
                        elif key == "status":
                            current_fw_policy.status = value
                        elif key == "srcintf":
                            current_fw_policy.src_interface = value
                        elif key == "dstintf":
                            current_fw_policy.dst_interface = value
                        elif key == "action":
                            current_fw_policy.action = value
                        elif key == "srcaddr":
                            current_fw_policy.src_address = value
                        elif key == "dstaddr":
                            current_fw_policy.dst_address = value
                        elif key == "schedule":
                            current_fw_policy.schedule = value
                        elif key == "service":
                            current_fw_policy.service = value
                        elif key == "ips-sensor":
                            current_fw_policy.ips_sensor = value
                        elif key == "ippool":
                            current_fw_policy.ippool_status = value
                        elif key == "nat":
                            current_fw_policy.nat_status = value
                        elif key == "natip":
                            current_fw_policy.nat_ip = value
                        elif key == "poolname":
                            current_fw_policy.pool_name = value
                            # Link this firewall policy to the IP Pool
                            if value in self.ippool_dict:
                                ippool = self.ippool_dict[value]
                                ippool.associated_fw_rules.add(current_fw_policy.id)
                                if current_fw_policy.src_interface:
                                    ippool.src_interfaces.add(current_fw_policy.src_interface)
                                if current_fw_policy.dst_interface:
                                    ippool.dst_interfaces.add(current_fw_policy.dst_interface)
                        elif key == "comments":
                            current_fw_policy.comments = value
                
                i += 1
                continue

            i += 1

        # Add debug logging at the end
        logging.debug(f"Parsed {len(self.interface_entries)} interfaces")
        for idx, interface in enumerate(self.interface_entries):
            logging.debug(f"Interface {idx+1}: {interface.name} (Type: {interface.type}, VRF: {interface.vrf.name if interface.vrf else 'None'})")

        # Add VRF debug logs
        logging.debug(f"Parsed {len(self.vrf_entries)} VRFs")
        for vrf_name, vrf in self.vrf_entries.items():
            logging.debug(f"VRF {vrf_name}: {len(vrf.interfaces)} interfaces")
            
        # Add firewall policy debug logs
        logging.debug(f"Parsed {len(self.fw_policy_entries)} firewall policies")
        for idx, policy in enumerate(self.fw_policy_entries):
            logging.debug(f"Firewall Policy {idx+1}: ID {policy.id}, Name: {policy.name}, Pool: {policy.pool_name}")

    def parse_vdom_section(self, start_line):
        """
        Parse the VDOM section to extract VRF entries.
        Returns the line number after the end of the VDOM section.
        """
        i = start_line
        while i < len(self.lines):
            line = self.lines[i].strip()
            
            # Extract VDOM name from edit command
            match = self.re_edit_vdom.match(line)
            if match:
                vdom_name = match.group(1)
                self.current_vdom = vdom_name
                
                # Create a new VRF entry if it doesn't exist
                if vdom_name not in self.vrf_entries:
                    self.vrf_entries[vdom_name] = VRFEntry(vdom_name)
                    logging.info(f"Created new VRF entry: {vdom_name}")
            
            # End of VDOM section
            if self.re_end.match(line):
                return i + 1
                
            i += 1
        
        return i

    def get_ippool_entries(self):
        """
        Returns a list of dictionaries for IP Pool entries.
        """
        return [entry.to_dict() for entry in self.ippool_entries]

    def get_vip_entries(self):
        """
        Returns a list of dictionaries for VIP entries.
        """
        return [entry.to_dict() for entry in self.vip_entries]
        
    def get_vrf_entries(self):
        """
        Returns a list of dictionaries for VRF entries.
        """
        return [entry.to_dict() for entry in self.vrf_entries.values()]
        
    def get_interface_entries(self):
        """
        Returns a list of dictionaries for Interface entries.
        """
        return [entry.to_dict() for entry in self.interface_entries]
        
    def get_fw_policy_entries(self):
        """
        Returns a list of dictionaries for Firewall Policy entries.
        """
        return [entry.to_dict() for entry in self.fw_policy_entries]

    def export_to_excel(self, output_file="NAT_Configuration.xlsx"):
        """
        Exports the extracted IP Pool, VIP, VRF, Interface, and Firewall Policy entries to an Excel file.
        The Excel file is saved to the 'output' directory by default, with a timestamp appended to the filename.
        """
        # Define the output directory and create it if it doesn't exist.
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Append a timestamp to the filename to avoid conflicts.
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base, ext = os.path.splitext(output_file)
        full_output_file = f"{base}_{timestamp}{ext}"
        full_output_path = os.path.join(output_dir, full_output_file)

        # Define the columns for each sheet
        ippool_columns = ["Name", "VDOM", "Start IP/Range", "Mapped IP", "Type",
                        "Associated Interface", "Comment", "Src IF(s)", "Dst IF(s)", 
                        "Mapped IP(s)", "Associated FW Rules"]
        vip_columns = ["Name", "VDOM", "Start IP/Range", "Mapped IP", "Type",
                     "Associated Interface", "Comment", "Ext Interface"]
        vrf_columns = ["Name", "VRF Number", "Interface Count"]
        interface_columns = ["Name", "VRF", "VRF Number", "Type", "VLAN ID", 
                           "Management IP", "IP", "Alias", "Description", "Status"]
        fw_policy_columns = ["Entry ID", "VDOM", "Name", "Status", "Src IF", "Dst IF", 
                            "Action", "Src Address", "Dst Address", "Schedule", "Service", 
                            "IPS Sensor", "IPPool Status", "NAT Status", "NAT IP", 
                            "Pool Name", "Comments"]

        # Create DataFrames
        df_ippool = pd.DataFrame(self.get_ippool_entries(), columns=ippool_columns)
        df_vip = pd.DataFrame(self.get_vip_entries(), columns=vip_columns)
        df_vrf = pd.DataFrame(self.get_vrf_entries(), columns=vrf_columns)
        df_interface = pd.DataFrame(self.get_interface_entries(), columns=interface_columns)
        df_fw_policy = pd.DataFrame(self.get_fw_policy_entries(), columns=fw_policy_columns)

        # Write the data to an Excel file with five tabs.
        with pd.ExcelWriter(full_output_path) as writer:
            df_ippool.to_excel(writer, sheet_name="IP Pools", index=False)
            df_vip.to_excel(writer, sheet_name="VIP", index=False)
            df_vrf.to_excel(writer, sheet_name="VRF", index=False)
            df_interface.to_excel(writer, sheet_name="Interfaces", index=False)
            df_fw_policy.to_excel(writer, sheet_name="Firewall Policies", index=False)

        logging.info("Excel file '%s' has been created with five sheets: 'IP Pools', 'VIP', 'VRF', 'Interfaces', and 'Firewall Policies'.", 
                    full_output_path)
