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
        self.ext_interface = ""

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
            "Ext Interface": self.ext_interface
        }


class NATParser:
    """
    Parser for FortiGate NAT configuration file.

    This class parses the configuration file to extract:
      - The current VDOM from 'config vdom' sections.
      - NAT configuration entries from the 'config firewall ippool' section.
      - NAT configuration entries from the 'config firewall vip' section.
    """

    def __init__(self, filename):
        self.filename = filename
        self.lines = []
        self.current_vdom = ""
        self.ippool_entries = []
        self.vip_entries = []
        # Compile commonly used regex patterns.
        self.re_config_vdom = re.compile(r'^\s*config vdom', re.IGNORECASE)
        self.re_edit_vdom = re.compile(r'^\s*edit\s+"?([^"\s]+)"?', re.IGNORECASE)
        self.re_config_ippool = re.compile(r'^\s*config firewall ippool', re.IGNORECASE)
        self.re_config_vip = re.compile(r'^\s*config firewall vip', re.IGNORECASE)
        self.re_end = re.compile(r'^\s*end\s*$', re.IGNORECASE)
        self.re_set = re.compile(r'^\s*set\s+(\S+)\s+(.*)$', re.IGNORECASE)
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
        and calls parsing methods for ippool and vip sections.
        """
        self.load_file()
        i = 0
        in_ippool = False
        in_vip = False
        current_entry = None

        while i < len(self.lines):
            line = self.lines[i].strip()
            logging.debug("Processing line %d: %s", i, line)

            # Detect a VDOM block and extract the VDOM name.
            if self.re_config_vdom.match(line):
                logging.info("Found config vdom at line %d", i)
                i += 1
                while i < len(self.lines):
                    match_vdom = self.re_edit_vdom.match(self.lines[i].strip())
                    if match_vdom:
                        self.current_vdom = match_vdom.group(1)
                        logging.info("Set current VDOM to: %s", self.current_vdom)
                        break
                    i += 1
                i += 1
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

            # Process lines if inside the ippool section.
            if in_ippool:
                if line.startswith("edit"):
                    # Save previous entry if exists.
                    if current_entry is not None:
                        current_entry.vdom = self.current_vdom
                        self.ippool_entries.append(current_entry)
                        logging.info("Saved ippool entry: %s", current_entry.to_dict())
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
                        elif key == "endip":
                            if current_entry.start_ip_range:
                                current_entry.start_ip_range += "–" + value
                            else:
                                current_entry.start_ip_range = value
                        elif key == "type":
                            current_entry.type = value
                        elif key == "associated-interface":
                            current_entry.associated_interface = value
                        elif key == "comments":
                            current_entry.comment = value
                        elif key == "extintf":
                            current_entry.ext_interface = value
                if self.re_end.match(line):
                    if current_entry is not None:
                        current_entry.vdom = self.current_vdom
                        self.ippool_entries.append(current_entry)
                        logging.info("Ending ippool section, saved entry: %s", current_entry.to_dict())
                        current_entry = None
                    in_ippool = False
                i += 1
                continue

            # Process lines if inside the vip section.
            if in_vip:
                if line.startswith("edit"):
                    if current_entry is not None:
                        current_entry.vdom = self.current_vdom
                        self.vip_entries.append(current_entry)
                        logging.info("Saved vip entry: %s", current_entry.to_dict())
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
                        logging.info("Ending vip section, saved entry: %s", current_entry.to_dict())
                        current_entry = None
                    in_vip = False
                i += 1
                continue

            i += 1

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

    def export_to_excel(self, output_file="NAT_Configuration.xlsx"):
        """
        Exports the extracted IP Pool and VIP entries to an Excel file with two tabs.
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

        # Define the columns and create DataFrames.
        columns = ["Name", "VDOM", "Start IP/Range", "Mapped IP", "Type",
                   "Associated Interface", "Comment", "Ext Interface"]
        df_ippool = pd.DataFrame(self.get_ippool_entries(), columns=columns)
        df_vip = pd.DataFrame(self.get_vip_entries(), columns=columns)

        # Write the data to an Excel file with two tabs.
        with pd.ExcelWriter(full_output_path) as writer:
            df_ippool.to_excel(writer, sheet_name="IP Pools", index=False)
            df_vip.to_excel(writer, sheet_name="VIP", index=False)

        logging.info("Excel file '%s' has been created with two sheets: 'IP Pools' and 'VIP'.", full_output_path)
