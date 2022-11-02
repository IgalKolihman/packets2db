import configparser
from collections import ChainMap
from configparser import SectionProxy
from typing import Dict, Union

import loguru
from pymongo import MongoClient
from scapy.all import sniff

from databases import IDatabase, init_db

logger = loguru.logger

client = MongoClient("mongodb://admin:admin@localhost")
traffic_db = client["traffic"]["Legion"]

_native_value = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))


class Packet2Dict:
    def __init__(self, packet):
        self.packet = packet

    def to_dict(self):
        """
        Turn every layer to dict, store in ChainMap type.
        :return: ChainMaq
        """
        d = list()
        count = 0

        while True:
            layer = self.packet.getlayer(count)
            if not layer:
                break
            d.append(self._layer2dict(layer))

            count += 1
        return dict(ChainMap(*d))

    def _layer2dict(self, obj):
        layer = {}

        if not getattr(obj, "fields_desc", None):
            return

        for field in obj.fields_desc:
            value = getattr(obj, field.name)
            if value is None:
                value = None

            if not isinstance(value, _native_value):
                value = self._layer2dict(value)
            layer[field.name] = value

        return {obj.name: layer}


class Sniffer:
    def __init__(self, database: IDatabase, conf: SectionProxy):
        self.db = database
        self.config = conf
        self.interface = self.config["interface"]
        self.verbosity_level = self.config.get("logging", None)
        ignored_fields = self.config.get("ignore_fields", None)

        if ignored_fields is not None:
            ignored_fields = ignored_fields.strip().split("\n")

        self.ignored_fields = ignored_fields

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
        count = 0

        while True:
            layer = packet.getlayer(count)
            if not layer:
                break

            d.append(self._parse_layer(layer))
            count += 1

        return dict(ChainMap(*d))

    def _parse_layer(self, obj) -> Union[Dict, None]:
        layer = {}

        if not getattr(obj, "fields_desc", None):
            return

        for field in obj.fields_desc:
            value = getattr(obj, field.name)
            if value is None:
                value = None

            if not isinstance(value, _native_value):
                value = self._parse_layer(value)
            layer[field.name] = value

        return {obj.name: layer}


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read("conf.ini")
    db_config, sniff_config = config["DATABASE"], config["SNIFFER"]
    import ipdb;

    ipdb.set_trace(context=20)
    exit()

    db = init_db(config=db_config, interface=sniff_config["interface"])
    sniffer = Sniffer(db, sniff_config)
    sniffer.sniff()
