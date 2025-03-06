import logging
import argparse
from  parsers.fortigate import NATParser

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

    args = parser.parse_args()

    # Configure logging based on verbosity flag.
    # Set logging level based on verbosity.
    if args.verbose >= 2:
        logging_level = logging.DEBUG
    elif args.verbose == 1:
        logging_level = logging.INFO
    else:
        logging_level = logging.WARNING

    logging.basicConfig(level=logging_level, format="%(asctime)s - %(levelname)s - %(message)s")

    logging.info("Starting NAT configuration extraction")
    nat_parser = NATParser(args.input_file)
    nat_parser.parse()

    logging.info("Extracted %d IP Pool entries and %d VIP entries",
                 len(nat_parser.ippool_entries), len(nat_parser.vip_entries))

    nat_parser.export_to_excel(args.output)
    logging.info("Finished processing.")


if __name__ == "__main__":
    main()