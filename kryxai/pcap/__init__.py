"""Packet capture: reading, decoding, and reassembly.

Self-contained. KryxAI deliberately does not depend on dpkt or scapy so the
demo runs on a bare interpreter, offline, with no native build step.
"""

from kryxai.pcap.io import PcapFormatError, iter_packets, read_capture
from kryxai.pcap.models import Conversation, RawPacket, TcpDirection
from kryxai.pcap.tcp import reassemble, reassemble_file

__all__ = [
    "Conversation",
    "PcapFormatError",
    "RawPacket",
    "TcpDirection",
    "iter_packets",
    "read_capture",
    "reassemble",
    "reassemble_file",
]
