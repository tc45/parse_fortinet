import logging
import argparse
import os
from datetime import datetime
from parsers.fortigate import NATParser

def main():
    """
    Main function to execute the NAT configuration extraction and export.
    """
    parser = argparse.ArgumentParser(
        description="Extract NAT configuration from a FortiGate config file and export to Excel."
    )
    parser.add_argument("input_file", help="Path to the FortiGate configuration .txt file")
    parser.add_argument("-o", "--output", default="NAT_Configuration.xlsx", help="Output Excel file name")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Enable verbose (debug) logging")
    parser.add_argument("-l", "--log", default="logs", help="Directory to store log files")

    args = parser.parse_args()

    # Create logs directory if it doesn't exist
    if not os.path.exists(args.log):
        os.makedirs(args.log)

    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(args.log, f"parser_log_{timestamp}.txt")

    # Configure logging based on verbosity flag.
    # Set logging level based on verbosity.
    if args.verbose >= 2:
        logging_level = logging.DEBUG
    elif args.verbose == 1:
        logging_level = logging.WARNING
    else:
        logging_level = logging.INFO

    # Configure logging to both console and file
    logging.basicConfig(
        level=logging_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()  # This will output to console
        ]
    )

    logging.info("Starting NAT configuration extraction")
    logging.info(f"Input file: {args.input_file}")
    logging.info(f"Log file created at: {log_filename}")
    
    nat_parser = NATParser(args.input_file)
    nat_parser.parse()

    logging.info("Extracted %d IP Pool entries, %d VIP entries, %d VRF entries, and %d Interface entries",
                 len(nat_parser.ippool_entries), len(nat_parser.vip_entries), 
                 len(nat_parser.vrf_entries), len(nat_parser.interface_entries))

    nat_parser.export_to_excel(args.output)
    logging.info("Finished processing.")


if __name__ == "__main__":
    main()