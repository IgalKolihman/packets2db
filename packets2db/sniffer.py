import configparser
from typing import Dict, Union
from collections import ChainMap
from configparser import SectionProxy

import loguru
from scapy.all import sniff
from pymongo import MongoClient

from databases import IDatabase, init_db

logger = loguru.logger

# client = MongoClient("mongodb://admin:admin@localhost")
# traffic_db = client["traffic"]["Legion"]


class Sniffer:
    NATIVE_VALUES = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))

    def __init__(self, database: IDatabase, conf: SectionProxy):
        self.db = database
        self.config = conf
        self.interface = self.config["interface"]
        self.verbosity_level = self.config.get("logging", None)

        excluded_fields = self.config.get("exclude_layers", None)
        only_fields = self.config.get("only_layers", None)

        if excluded_fields is not None:
            excluded_fields = excluded_fields.strip().split("\n")

        if only_fields is not None:
            only_fields = only_fields.strip().split("\n")

        self.excluded_fields = excluded_fields if excluded_fields else []
        self.only_fields = only_fields if only_fields else []

    def sniff(self):
        logger.info(f"Beginning sniff for interface {self.interface}")
        logger.info(f"Packets are sent to a '{self.db.TYPE}' database")
        sniff(prn=lambda pkt: self._handle_packet(pkt), iface=self.interface)

    def _handle_packet(self, packet):
        parsed_packet = self._parse_packet(packet)
        self._log_packet(packet, parsed_packet)

        self.db.upload_document(parsed_packet)

    def _log_packet(self, packet, parsed_packet):
        if self.verbosity_level is None:
            return

        elif self.verbosity_level == "v":
            logger.debug(packet.summary())

        elif self.verbosity_level == "vv":
            logger.debug(parsed_packet)

        elif self.verbosity_level == "vvv":
            packet.show()

    def _parse_packet(self, packet) -> Dict:
        """
        Turn every layer to dict, store in ChainMap type.
        """
        d = list()

        for i in range(len(packet.layers())):
            layer = packet.getlayer(i)

            if layer.name in self.excluded_fields:
                continue

            if not self.only_fields:
                d.append(self._parse_layer(layer))

            elif layer.name in self.only_fields:
                d.append(self._parse_layer(layer))

        return dict(ChainMap(*d))

    def _parse_layer(self, obj) -> Union[Dict, None]:
        layer = {}

        if not getattr(obj, "fields_desc", None):
            return

        for field in obj.fields_desc:
            value = getattr(obj, field.name)
            if value is None:
                value = None

            if not isinstance(value, self.NATIVE_VALUES):
                value = self._parse_layer(value)

            layer[field.name] = value

        return {obj.name: layer}


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read(".packets2db.ini")
    db_config, sniff_config = config["DATABASE"], config["SNIFFER"]

    db = init_db(config=db_config, interface=sniff_config["interface"])
    sniffer = Sniffer(db, sniff_config)
    sniffer.sniff()
