# FortiGate NAT Configuration Extractor

This project provides a Python-based tool to extract NAT configuration details from a FortiGate configuration file. The configuration file is expected to be in a text format containing sections such as `config vdom`, `config firewall ippool`, and `config firewall vip`. The extracted data is then exported to an Excel file with two tabs ("IP Pools" and "VIP").

## Project Structure

The code has been split into two main components:

- **main.py**:  
  This is the entry point of the program. It handles command-line arguments, logging configuration, and invokes the parser to process the input file.

- **parsers/fortigate.py**:  
  This module contains the classes responsible for parsing the FortiGate configuration file. It includes:
  - `NATEntry`: A class representing a single NAT entry.
  - `NATParser`: A class that reads the configuration file, extracts the current VDOM, parses the NAT sections (ippool and vip), and exports the extracted data to an Excel file.

## Requirements

- Python 3.x
- [pandas](https://pandas.pydata.org/)  
- Standard libraries: `argparse`, `logging`, `re`

Install the required packages (if not already installed):

```bash
pip install pandas
```
## Usage
Run the program from the command line as follows:

```bash
python main.py "path/to/your/config.txt" -o "NAT_Configuration.xlsx" -v
```

### Arguments
- input_file: Path to the FortiGate configuration .txt file.
- -o, --output: (Optional) Specify the output Excel file name (default is NAT_Configuration.xlsx).
- -v, --verbose: (Optional) Enable verbose logging for debugging.

## Logging
The tool uses Python's built-in logging module. Use the -v flag to enable debug logging, which will output detailed information about the parsing process.

## License
This project is open source and available under the MIT License.
