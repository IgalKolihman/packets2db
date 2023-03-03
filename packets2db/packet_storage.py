"""Packet storage options"""
import platform
from collections import ChainMap
from configparser import SectionProxy
from typing import Dict, Tuple, Union

from pymongo import MongoClient
from scapy.packet import Packet
from scapy.utils import PcapWriter

from packets2db.common import NATIVE_VALUES


class IStorage:
    TYPE = NotImplemented

    def serialize(self, packet: Packet, filters: Tuple[list]):
        """Serialize the packet before storing it.

        Should be called inside the `store` and `store_multiple` functions.

        Args:
            packet (Packet): The packet to serialize.
            filters (Tuple[list]): [ [excluded_fields ... ], [only_fields ...]]

        Returns:
            object. The serialized packet.
        """
        pass

    def store(self, packet: Packet, **kwargs):
        """Stores the packet in the chosen storage."""
        pass


class MongoDB(IStorage):
    TYPE = "mongodb"

    def __init__(self, url: str, interface: str, collection: str = None):
        if collection is None:
            collection = f"{interface}"

        client = MongoClient(url)
        self.interface = interface
        self.collection = client[platform.node()][collection]

    def serialize(self, packet: Packet, filters: Tuple[list]):
        """Serializes the packet to a dict format after filtering the layers.

        Args:
            packet (Packet): The packet to serialize.
            filters (Tuple[list]): [ [excluded_fields ... ], [only_fields ...]]

        Returns:
            dict. Serialized and filtered packet.
        """
        d = list()
        excluded_fields = filters[0]
        only_fields = filters[1]

        for i in range(len(packet.layers())):
            layer = packet.getlayer(i)

            if layer.name in excluded_fields:
                continue

            if not only_fields:
                d.append(self._parse_layer(layer))

            elif layer.name in only_fields:
                d.append(self._parse_layer(layer))

        return dict(ChainMap(*d))

    def _parse_layer(self, obj) -> Union[Dict, None]:
        """Helper method used by the serialize method to parse a layer of the packet.

        Takes one argument obj, which is the layer to be parsed. The method returns a
        dictionary representation of the layer.

        Args:
            obj (Union[Dict, None]): Tha layer to parse.

        Returns:
            dict. Dictionary representation of the layer.
        """
        layer = {}

        if not getattr(obj, "fields_desc", None):
            return

        for field in obj.fields_desc:
            value = getattr(obj, field.name)
            if value is None:
                value = None

            if not isinstance(value, NATIVE_VALUES):
                value = self._parse_layer(value)

            layer[field.name] = value

        return {obj.name: layer}

    def store(self, packet: Packet, filters: Tuple[list] = None):
        """Stores the packet in the MongoDB collection specified in the constructor.

        Args:
            packet (Packet): Packet to store in the db.
            filters (Tuple[list]):  [ [excluded_fields ... ], [only_fields ...]]
        """
        self.collection.insert_one(self.serialize(packet, filters))


class Pcap(IStorage):
    """Used for storing packets in a Pcap file."""

    TYPE = "pcap"

    def __init__(self, path: str):
        self.pkt_dump = PcapWriter(path, append=True, sync=True)

    def store(self, packet: Packet, **kwargs):
        """Writes the packet to the Pcap file.

        Args:
            packet (Packet): The packet to store.
            **kwargs:
        """
        self.pkt_dump.write(packet)


def init_storage(config: SectionProxy, interface: str) -> IStorage:
    """Initialize the appropriate storage class based on the configuration parameters.

    Args:
        config (SectionProxy): Contains the configuration parameters
        interface (str): Name of the interface from which the packets are being captured
    """
    if config["type"] == MongoDB.TYPE:
        return MongoDB(
            url=config["url"],
            interface=interface,
            collection=config.get("collection", None),
        )

    elif config["type"] == Pcap.TYPE:
        return Pcap(
            path=config["path"],
        )

    raise NameError(f"Couldn't identify database type '{config['type']}'")
