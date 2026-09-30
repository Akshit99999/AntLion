"""
Pure-Python CIC-IDS2017 style network flow feature extraction engine.
Parses packet captures or live packets into bidirectional flows with statistical features.
"""

from __future__ import annotations

import math
import socket
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from antlion.core.types import FlowRecord


@dataclass
class PacketMetadata:
    """Normalized metadata for a single network packet."""
    timestamp: float  # seconds with microsecond resolution
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    length: int
    tcp_flags: Dict[str, int] = field(default_factory=dict)


class FlowAccumulator:
    """Tracks state and packet dynamics for a single bidirectional flow."""

    def __init__(self, key: Tuple[str, str, int, int, int]):
        self.fwd_src_ip, self.fwd_dst_ip, self.fwd_src_port, self.fwd_dst_port, self.protocol = key
        self.start_time: Optional[float] = None
        self.last_time: Optional[float] = None

        self.fwd_packet_times: List[float] = []
        self.bwd_packet_times: List[float] = []
        self.fwd_packet_lens: List[int] = []
        self.bwd_packet_lens: List[int] = []

        self.all_packet_times: List[float] = []

        # Flags counts
        self.fwd_psh = 0
        self.bwd_psh = 0
        self.fwd_urg = 0
        self.bwd_urg = 0

        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0

    def add_packet(self, pkt: PacketMetadata) -> None:
        if self.start_time is None:
            self.start_time = pkt.timestamp
        self.last_time = pkt.timestamp
        self.all_packet_times.append(pkt.timestamp)

        is_fwd = (pkt.src_ip == self.fwd_src_ip and pkt.src_port == self.fwd_src_port)

        if is_fwd:
            self.fwd_packet_times.append(pkt.timestamp)
            self.fwd_packet_lens.append(pkt.length)
            if pkt.tcp_flags.get("PSH", 0):
                self.fwd_psh += 1
            if pkt.tcp_flags.get("URG", 0):
                self.fwd_urg += 1
        else:
            self.bwd_packet_times.append(pkt.timestamp)
            self.bwd_packet_lens.append(pkt.length)
            if pkt.tcp_flags.get("PSH", 0):
                self.bwd_psh += 1
            if pkt.tcp_flags.get("URG", 0):
                self.bwd_urg += 1

        self.fin_count += pkt.tcp_flags.get("FIN", 0)
        self.syn_count += pkt.tcp_flags.get("SYN", 0)
        self.rst_count += pkt.tcp_flags.get("RST", 0)
        self.psh_count += pkt.tcp_flags.get("PSH", 0)
        self.ack_count += pkt.tcp_flags.get("ACK", 0)
        self.urg_count += pkt.tcp_flags.get("URG", 0)

    def compute_features(self) -> Dict[str, float]:
        """Calculates CIC-IDS2017 compliant flow statistical features."""
        duration_sec = (self.last_time - self.start_time) if (self.last_time and self.start_time) else 0.0
        duration_usec = max(1.0, duration_sec * 1_000_000.0)

        total_fwd_pkts = len(self.fwd_packet_lens)
        total_bwd_pkts = len(self.bwd_packet_lens)
        total_pkts = total_fwd_pkts + total_bwd_pkts

        fwd_bytes = sum(self.fwd_packet_lens)
        bwd_bytes = sum(self.bwd_packet_lens)
        total_bytes = fwd_bytes + bwd_bytes

        # Flow rates
        flow_bytes_per_sec = (total_bytes / duration_sec) if duration_sec > 0 else 0.0
        flow_pkts_per_sec = (total_pkts / duration_sec) if duration_sec > 0 else 0.0

        # Packet length stats
        fwd_lens = self.fwd_packet_lens or [0]
        bwd_lens = self.bwd_packet_lens or [0]

        # Inter-arrival times (IAT)
        all_iats = self._calc_iats(self.all_packet_times)
        fwd_iats = self._calc_iats(self.fwd_packet_times)
        bwd_iats = self._calc_iats(self.bwd_packet_times)

        down_up_ratio = (total_bwd_pkts / total_fwd_pkts) if total_fwd_pkts > 0 else 0.0
        avg_pkt_size = (total_bytes / total_pkts) if total_pkts > 0 else 0.0

        return {
            "Flow Duration": float(duration_usec),
            "Total Fwd Packets": float(total_fwd_pkts),
            "Total Backward Packets": float(total_bwd_pkts),
            "Total Length of Fwd Packets": float(fwd_bytes),
            "Total Length of Bwd Packets": float(bwd_bytes),
            "Fwd Packet Length Max": float(max(fwd_lens)),
            "Fwd Packet Length Min": float(min(fwd_lens)),
            "Fwd Packet Length Mean": float(self._mean(fwd_lens)),
            "Fwd Packet Length Std": float(self._std(fwd_lens)),
            "Bwd Packet Length Max": float(max(bwd_lens)),
            "Bwd Packet Length Min": float(min(bwd_lens)),
            "Bwd Packet Length Mean": float(self._mean(bwd_lens)),
            "Bwd Packet Length Std": float(self._std(bwd_lens)),
            "Flow Bytes/s": float(flow_bytes_per_sec),
            "Flow Packets/s": float(flow_pkts_per_sec),
            "Flow IAT Mean": float(self._mean(all_iats)),
            "Flow IAT Std": float(self._std(all_iats)),
            "Flow IAT Max": float(max(all_iats) if all_iats else 0.0),
            "Flow IAT Min": float(min(all_iats) if all_iats else 0.0),
            "Fwd IAT Total": float(sum(fwd_iats)),
            "Fwd IAT Mean": float(self._mean(fwd_iats)),
            "Fwd IAT Std": float(self._std(fwd_iats)),
            "Fwd IAT Max": float(max(fwd_iats) if fwd_iats else 0.0),
            "Fwd IAT Min": float(min(fwd_iats) if fwd_iats else 0.0),
            "Bwd IAT Total": float(sum(bwd_iats)),
            "Bwd IAT Mean": float(self._mean(bwd_iats)),
            "Bwd IAT Std": float(self._std(bwd_iats)),
            "Bwd IAT Max": float(max(bwd_iats) if bwd_iats else 0.0),
            "Bwd IAT Min": float(min(bwd_iats) if bwd_iats else 0.0),
            "Fwd PSH Flags": float(self.fwd_psh),
            "Bwd PSH Flags": float(self.bwd_psh),
            "Fwd URG Flags": float(self.fwd_urg),
            "Bwd URG Flags": float(self.bwd_urg),
            "FIN Flag Count": float(self.fin_count),
            "SYN Flag Count": float(self.syn_count),
            "RST Flag Count": float(self.rst_count),
            "PSH Flag Count": float(self.psh_count),
            "ACK Flag Count": float(self.ack_count),
            "URG Flag Count": float(self.urg_count),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": float(avg_pkt_size),
        }

    @staticmethod
    def _calc_iats(times: List[float]) -> List[float]:
        if len(times) < 2:
            return [0.0]
        # In microseconds
        return [(times[i] - times[i - 1]) * 1_000_000.0 for i in range(1, len(times))]

    @staticmethod
    def _mean(values: List[Union[int, float]]) -> float:
        return sum(values) / len(values) if values else 0.0

    @staticmethod
    def _std(values: List[Union[int, float]]) -> float:
        if len(values) < 2:
            return 0.0
        m = sum(values) / len(values)
        var = sum((x - m) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(var)


class FlowFeatureExtractor:
    """Extracts bidirectional flow statistics from network packets or PCAP files."""

    def __init__(self):
        # Maps 5-tuple -> FlowAccumulator
        self.flows: Dict[Tuple[str, str, int, int, int], FlowAccumulator] = {}

    def process_packet(self, pkt: PacketMetadata) -> None:
        """Assigns packet to forward or backward direction of a bidirectional flow."""
        fwd_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        bwd_key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)

        if fwd_key in self.flows:
            self.flows[fwd_key].add_packet(pkt)
        elif bwd_key in self.flows:
            self.flows[bwd_key].add_packet(pkt)
        else:
            flow = FlowAccumulator(fwd_key)
            flow.add_packet(pkt)
            self.flows[fwd_key] = flow

    def extract_from_pcap(self, pcap_path: Union[str, Path]) -> List[FlowRecord]:
        """Parses a binary PCAP file directly in Python."""
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        with open(pcap_file, "rb") as f:
            header_bytes = f.read(24)
            if len(header_bytes) < 24:
                return []

            magic, major, minor, tz, sig, snaplen, linktype = struct.unpack(
                "<IHHiIII", header_bytes
            )
            # Check endianness
            if magic != 0xA1B2C3D4:
                if magic == 0xD4C3B2A1:
                    # Big endian
                    pass

            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
                timestamp = ts_sec + (ts_usec / 1_000_000.0)

                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                parsed_pkt = self._parse_ethernet_packet(pkt_data, timestamp)
                if parsed_pkt:
                    self.process_packet(parsed_pkt)

        return self.to_flow_records()

    def _parse_ethernet_packet(
        self, data: bytes, timestamp: float
    ) -> Optional[PacketMetadata]:
        # Minimal pure Python ethernet + IP + TCP/UDP parser
        if len(data) < 14:
            return None

        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type != 0x0800:  # IPv4 only
            return None

        ip_header = data[14:34]
        if len(ip_header) < 20:
            return None

        ver_ihl, tos, total_len, identification, flags_frag, ttl, protocol, chksum, src_ip_raw, dst_ip_raw = struct.unpack(
            "!BBHHHBBH4s4s", ip_header
        )
        ihl = (ver_ihl & 0x0F) * 4
        src_ip = socket.inet_ntoa(src_ip_raw)
        dst_ip = socket.inet_ntoa(dst_ip_raw)

        transport_data = data[14 + ihl :]
        src_port = 0
        dst_port = 0
        tcp_flags = {}

        if protocol == 6:  # TCP
            if len(transport_data) < 20:
                return None
            src_port, dst_port, seq, ack, offset_reserved, flags_byte = struct.unpack(
                "!HHIIBB", transport_data[:14]
            )
            tcp_flags = {
                "FIN": 1 if (flags_byte & 0x01) else 0,
                "SYN": 1 if (flags_byte & 0x02) else 0,
                "RST": 1 if (flags_byte & 0x04) else 0,
                "PSH": 1 if (flags_byte & 0x08) else 0,
                "ACK": 1 if (flags_byte & 0x10) else 0,
                "URG": 1 if (flags_byte & 0x20) else 0,
            }
        elif protocol == 17:  # UDP
            if len(transport_data) < 8:
                return None
            src_port, dst_port = struct.unpack("!HH", transport_data[:4])

        return PacketMetadata(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=total_len,
            tcp_flags=tcp_flags,
        )

    def to_flow_records(self) -> List[FlowRecord]:
        """Converts accumulated flows into Antlion FlowRecord domain models."""
        records: List[FlowRecord] = []
        for key, flow in self.flows.items():
            src_ip, dst_ip, src_port, dst_port, protocol = key
            flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
            features = flow.compute_features()
            records.append(
                FlowRecord(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    features=features,
                )
            )
        return records

    def to_dataframe(self) -> pd.DataFrame:
        """Emits flow features as a Pandas DataFrame."""
        rows = []
        for key, flow in self.flows.items():
            src_ip, dst_ip, src_port, dst_port, protocol = key
            feats = flow.compute_features()
            feats["src_ip"] = src_ip
            feats["dst_ip"] = dst_ip
            feats["src_port"] = src_port
            feats["dst_port"] = dst_port
            feats["protocol"] = protocol
            rows.append(feats)
        return pd.DataFrame(rows)

    def to_csv(self, filepath: Union[str, Path]) -> None:
        """Exports extracted features to CSV."""
        df = self.to_dataframe()
        df.to_csv(filepath, index=False)

    def to_parquet(self, filepath: Union[str, Path]) -> None:
        """Exports extracted features to Parquet."""
        df = self.to_dataframe()
        df.to_parquet(filepath, index=False)
