# FortiGate NAT Configuration Extractor

This project provides a Python-based tool to extract configuration details from a FortiGate configuration file. The configuration file is expected to be in a text format containing sections such as `config vdom`, `config firewall ippool`, `config firewall vip`, and `config system interface`. The extracted data is then exported to an Excel file with multiple tabs.

## Project Structure

The code has been split into two main components:

- **main.py**:  
  This is the entry point of the program. It handles command-line arguments, logging configuration, and invokes the parser to process the input file.

- **parsers/fortigate.py**:  
  This module contains the classes responsible for parsing the FortiGate configuration file. It includes:
  - `NATEntry`: A class representing a single NAT entry (IP Pool or VIP).
  - `VRFEntry`: A class representing a VRF (VDOM) entry.
  - `InterfaceEntry`: A class representing an interface entry.
  - `NATParser`: A class that reads the configuration file, extracts the configuration sections, and exports the extracted data to an Excel file.

## Features

The tool extracts the following information from FortiGate configuration files:

1. **NAT Configuration**:
   - IP Pool entries
   - VIP entries

2. **VRF (VDOM) Information**:
   - VRF names
   - VRF numbers
   - Associated interfaces

3. **Interface Information**:
   - Interface names
   - Associated VRF
   - Interface types
   - VLAN IDs
   - IP addresses (in CIDR format)
   - Management IPs
   - Aliases
   - Descriptions
   - Interface status

## Requirements

- Python 3.x
- [pandas](https://pandas.pydata.org/)
- [openpyxl](https://openpyxl.readthedocs.io/) (for Excel export)
- Standard libraries: `argparse`, `logging`, `re`

Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

Run the program from the command line as follows:

```bash
python main.py "path/to/your/config.txt" -o "Configuration_Export.xlsx" -v
```

### Arguments
- input_file: Path to the FortiGate configuration .txt file.
- -o, --output: (Optional) Specify the output Excel file name (default is NAT_Configuration.xlsx).
- -v, --verbose: (Optional) Enable verbose logging for debugging.

## Output

The tool generates an Excel file with four tabs:
1. **IP Pools**: Contains NAT IP Pool configuration
2. **VIP**: Contains NAT VIP configuration
3. **VRF**: Contains VRF (VDOM) information
4. **Interfaces**: Contains interface configuration details

## Logging

The tool uses Python's built-in logging module. Use the -v flag to enable debug logging, which will output detailed information about the parsing process.

## License

This project is open source and available under the MIT License.
