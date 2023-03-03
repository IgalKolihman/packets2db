"""Packet sniffer"""
import traceback
from configparser import SectionProxy

import loguru
from scapy.all import sniff
from scapy.packet import Packet
from bson import InvalidDocument

from packets2db.packet_storage import IStorage

logger = loguru.logger


class Sniffer:
    """Handles the packet sniffing process."""

    def __init__(self, database: IStorage, conf: SectionProxy):
        self.db = database
        self.config = conf
        self.interface = self.config["interface"]
        self.verbosity_level = self.config.get("logging", None)

        self.packet_counter = 0

        excluded_fields = self.config.get("exclude_layers", None)
        only_fields = self.config.get("only_layers", None)

        if excluded_fields is not None:
            excluded_fields = excluded_fields.strip().split("\n")

        if only_fields is not None:
            only_fields = only_fields.strip().split("\n")

        self.excluded_fields = excluded_fields if excluded_fields else []
        self.only_fields = only_fields if only_fields else []

    def sniff(self):
        """Starts the packet sniffing process."""
        logger.info(f"Beginning sniff for interface {self.interface}")
        logger.info(f"Packets are stored in '{self.db.TYPE}'")
        sniff(prn=lambda pkt: self._handle_packet(pkt), iface=self.interface)

    def _handle_packet(self, packet: Packet):
        """Handles each packet that is captured by the sniffer.

        Args:
            packet (Packet): Captured packet by scapy's `sniff`
        """
        try:
            self._log_packet(packet)
            self.db.store(packet)

        except InvalidDocument:
            logger.error(f"Couldn't encode packet")
            self._log_error(packet)

    def _log_packet(self, packet):
        """Logs the packet information"""
        self.packet_counter += 1
        if self.verbosity_level is None:
            print(f"{self.packet_counter} Packets were captured.", end="\r")
            return

        elif self.verbosity_level == "v":
            logger.debug(packet.summary())

        elif self.verbosity_level in ["vv", "vvv"]:
            self.packet_counter += 1
            logger.debug(f"Packet number {self.packet_counter}")
            packet.show()

    def _log_error(self, packet):
        """Logs the error messages if the packet is invalid."""
        if self.verbosity_level is None:
            return

        elif self.verbosity_level == "v":
            logger.error(f"Couldn't store or encode packet {packet.summary()}")

        elif self.verbosity_level == "vv":
            logger.error(f"Couldn't store or encode packet:")
            packet.show()
            traceback.print_exc()

        elif self.verbosity_level == "vvv":
            logger.error(f"Couldn't store or encode packet:")
            packet.show()
            traceback.print_stack()
