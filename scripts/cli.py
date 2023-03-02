"""Run the sniffer on a specific interface and send the packets to the selected DB.

Usage:
  cli.py -h | --help
  cli.py [-c <config-file>]
  
Options:
  -h --help    Show this help message
  -c --config  Path for the ini file (default is: ./.packets2db.ini)
"""
import configparser
from os.path import exists

from docopt import docopt

from packets2db.sniffer import Sniffer
from packets2db.packet_storage import init_storage

DEFAULT_CONFIG_PATH = ".packets2db.ini"


def main():
    args = docopt(__doc__)
    if args["--config"]:
        config_path = args["<config-file>"]
    else:
        config_path = DEFAULT_CONFIG_PATH

    if not exists(config_path):
        raise FileNotFoundError(f"Config file doesn't exist: {config_path}")

    config = configparser.ConfigParser()
    config.read(config_path)
    db_config, sniff_config = config["DATABASE"], config["SNIFFER"]

    db = init_storage(config=db_config, interface=sniff_config["interface"])
    sniffer = Sniffer(db, sniff_config)
    sniffer.sniff()


if __name__ == "__main__":
    main()
