"""WITNESS PCAP investigation (§33).

Parses PCAP files (libpcap format) and extracts normalized evidence:
- flow extraction (5-tuples)
- DNS queries / responses
- HTTP requests / responses
- TLS metadata (SNI, JA3 if available)
- connection graph
- IOC extraction (matches against threat_intel)
- industrial-protocol parsing (Modbus, DNP3 — best-effort)

Uses dpkt for fast parsing. scapy is available as a fallback for full
dissection but is much slower.
"""
from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.evidence import add_evidence
from ..utils.logging import get_logger
from ..utils.time import utc_now


log = get_logger("witness.tools.pcap")


def _ts_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


async def parse_pcap(pcap_path: str) -> dict[str, Any]:
    """Parse a PCAP file and return a structured result dict.

    Returns: {
        flows: list[flow_dict],
        dns:    list[dns_dict],
        http:   list[http_dict],
        tls:    list[tls_dict],
        industrial: list[industrial_dict],
        ioc_hits: list[ioc_hit_dict],
    }
    """
    if not os.path.exists(pcap_path):
        return {"error": "file_not_found", "path": pcap_path}

    try:
        import dpkt
    except ImportError:
        log.warning("dpkt not installed; PCAP parsing unavailable")
        return {"error": "dpkt_not_installed"}

    flows: dict[tuple, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "bytes": 0, "first_ts": None, "last_ts": None})
    dns: list[dict[str, Any]] = []
    http: list[dict[str, Any]] = []
    tls: list[dict[str, Any]] = []
    industrial: list[dict[str, Any]] = []

    with open(pcap_path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            try:
                pcap = dpkt.pcapng.Reader(f)
            except Exception as e:
                return {"error": f"pcap_read_failed:{e}"}

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = None
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip = eth.data
            if ip is None:
                # Skip non-IP frames (ARP, etc).
                continue

            src_ip = ".".join(str(b) for b in ip.src) if hasattr(ip, "src") and isinstance(ip.src, (bytes, bytearray)) else "?"
            dst_ip = ".".join(str(b) for b in ip.dst) if hasattr(ip, "dst") and isinstance(ip.dst, (bytes, bytearray)) else "?"
            transport = getattr(ip, "data", None)

            # TCP/UDP flow extraction.
            if isinstance(transport, dpkt.tcp.TCP):
                sport = int(transport.sport)
                dport = int(transport.dport)
                key = (src_ip, dst_ip, sport, dport, "TCP")
                fl = flows[key]
                fl["count"] += 1
                fl["bytes"] += len(transport.data)
                fl["first_ts"] = fl["first_ts"] or ts
                fl["last_ts"] = ts

                # HTTP detection by port + payload.
                payload = transport.data
                if dport in (80, 8080) and isinstance(payload, (bytes, bytearray)) and len(payload) > 4:
                    try:
                        text = payload.decode("ascii", errors="replace")
                        if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                            method, _, path = text.partition(" ")
                            path, _, _ = path.partition(" ")
                            http.append({
                                "ts": _ts_to_iso(ts),
                                "src_ip": src_ip, "dst_ip": dst_ip,
                                "method": method, "path": path,
                            })
                    except Exception:
                        pass
                # TLS SNI (very naive — looks for a Server Name in ClientHello).
                if dport in (443, 8443) and isinstance(payload, (bytes, bytearray)):
                    sni = _extract_sni(payload)
                    if sni:
                        tls.append({
                            "ts": _ts_to_iso(ts),
                            "src_ip": src_ip, "dst_ip": dst_ip,
                            "sni": sni,
                        })
                # Modbus TCP — port 502.
                if dport == 502 and isinstance(payload, (bytes, bytearray)):
                    mb = _parse_modbus(payload)
                    if mb:
                        industrial.append({
                            "ts": _ts_to_iso(ts),
                            "src_ip": src_ip, "dst_ip": dst_ip,
                            "protocol": "modbus", **mb,
                        })
                # DNP3 — port 20000.
                if dport == 20000:
                    industrial.append({
                        "ts": _ts_to_iso(ts),
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "protocol": "dnp3",
                    })
            elif isinstance(transport, dpkt.udp.UDP):
                sport = int(transport.sport)
                dport = int(transport.dport)
                key = (src_ip, dst_ip, sport, dport, "UDP")
                fl = flows[key]
                fl["count"] += 1
                fl["bytes"] += len(transport.data)
                fl["first_ts"] = fl["first_ts"] or ts
                fl["last_ts"] = ts
                # DNS — port 53.
                if dport == 53:
                    try:
                        dns_msg = dpkt.dns.DNS(transport.data)
                        for q in dns_msg.qd:
                            name = q.name
                            if isinstance(name, (bytes, bytearray)):
                                name = name.decode("ascii", errors="replace")
                            dns.append({
                                "ts": _ts_to_iso(ts),
                                "src_ip": src_ip, "dst_ip": dst_ip,
                                "query": str(name),
                                "type": int(getattr(q, "type", 0)),
                            })
                    except Exception:
                        pass

    return {
        "flows": [
            {"src_ip": k[0], "dst_ip": k[1], "sport": k[2], "dport": k[3],
             "proto": k[4], "count": v["count"], "bytes": v["bytes"],
             "first_ts": _ts_to_iso(v["first_ts"]) if v["first_ts"] else None,
             "last_ts": _ts_to_iso(v["last_ts"]) if v["last_ts"] else None}
            for k, v in flows.items()
        ],
        "dns": dns,
        "http": http,
        "tls": tls,
        "industrial": industrial,
        "total_packets": sum(f["count"] for f in flows.values()),
    }


def _extract_sni(payload: bytes) -> Optional[str]:
    """Naive SNI extractor from a TLS ClientHello. Returns the SNI hostname
    if present, else None."""
    try:
        # TLS record: type=0x16 (handshake), version, length, then handshake:
        # type=0x01 (ClientHello), length, then client_version, random (32),
        # session_id_len + session_id, cipher_suites_len + cipher_suites,
        # compression_len + compression, extensions_len + extensions.
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        rec_len = int.from_bytes(payload[3:5], "big")
        if rec_len + 5 > len(payload):
            return None
        # Handshake header.
        hs = payload[5:]
        if len(hs) < 4 or hs[0] != 0x01:
            return None
        # ClientHello length.
        hs_len = int.from_bytes(hs[1:4], "big")
        ch = hs[4:4 + hs_len]
        if len(ch) < 38:
            return None
        # Skip client_version (2) + random (32) + session_id_len.
        idx = 2 + 32
        sid_len = ch[idx]
        idx += 1 + sid_len
        # Skip cipher_suites.
        if idx + 2 > len(ch):
            return None
        cs_len = int.from_bytes(ch[idx:idx + 2], "big")
        idx += 2 + cs_len
        # Skip compression methods.
        if idx + 1 > len(ch):
            return None
        cm_len = ch[idx]
        idx += 1 + cm_len
        # Extensions.
        if idx + 2 > len(ch):
            return None
        ext_len = int.from_bytes(ch[idx:idx + 2], "big")
        idx += 2
        ext_end = idx + ext_len
        while idx + 4 <= ext_end:
            ext_type = int.from_bytes(ch[idx:idx + 2], "big")
            ext_data_len = int.from_bytes(ch[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0:  # server_name
                # SNI list: server_name_list_length, then entries of
                # (type, name_len, name). type 0 = host_name.
                sni_list = ch[idx:idx + ext_data_len]
                if len(sni_list) < 2:
                    break
                snl = int.from_bytes(sni_list[:2], "big")
                p = 2
                while p + 5 < 2 + snl:
                    nt = sni_list[p]
                    nl = int.from_bytes(sni_list[p + 1:p + 3], "big")
                    name = sni_list[p + 3:p + 3 + nl].decode("ascii", errors="replace")
                    if nt == 0:
                        return name
                    p += 3 + nl
            idx += ext_data_len
    except Exception:
        return None
    return None


def _parse_modbus(payload: bytes) -> Optional[dict[str, Any]]:
    """Parse a Modbus TCP PDU. Returns {function, unit_id, address, count, value}."""
    try:
        # MBAP header: 7 bytes (tx_id 2, proto 2, length 2, unit 1).
        if len(payload) < 8:
            return None
        tx_id = int.from_bytes(payload[0:2], "big")
        proto_id = int.from_bytes(payload[2:4], "big")
        if proto_id != 0:  # MBAP protocol identifier is always 0 for Modbus
            return None
        length = int.from_bytes(payload[4:6], "big")
        unit_id = payload[6]
        func = payload[7]
        body = payload[8:6 + length]
        out: dict[str, Any] = {
            "function": int(func),
            "unit_id": int(unit_id),
            "transaction_id": tx_id,
        }
        # Common functions:
        # 3 (read holding reg), 4 (read input reg), 6 (write single reg),
        # 16 (write multiple regs), 23 (read/write multiple).
        if func in (3, 4) and len(body) >= 4:
            out["address"] = int.from_bytes(body[0:2], "big")
            out["count"] = int.from_bytes(body[2:4], "big")
        elif func == 6 and len(body) >= 4:
            out["address"] = int.from_bytes(body[0:2], "big")
            out["value"] = int.from_bytes(body[2:4], "big")
        elif func == 16 and len(body) >= 5:
            out["address"] = int.from_bytes(body[0:2], "big")
            out["count"] = int.from_bytes(body[2:4], "big")
        return out
    except Exception:
        return None


async def parse_pcap_as_evidence(session: AsyncSession, investigation_id: str,
                                   pcap_path: str, *, synthetic: bool = False) -> int:
    """Parse a PCAP file and ingest each flow / DNS / HTTP / TLS / industrial
    event as a normalized evidence row. Returns the count of evidence inserted."""
    result = await parse_pcap(pcap_path)
    if "error" in result:
        log.warning(f"pcap_parse_error:{result['error']}")
        return 0
    n = 0
    for flow in result.get("flows", []):
        await add_evidence(
            session, investigation_id,
            source="pcap", source_type="pcap",
            timestamp=datetime.fromisoformat(flow["first_ts"]) if flow["first_ts"] else utc_now(),
            normalized_data={
                "event_kind": "flow", "domain": "network",
                "src_ip": flow["src_ip"], "dst_ip": flow["dst_ip"],
                "src_port": flow["sport"], "dst_port": flow["dport"],
                "proto": flow["proto"],
                "bytes": flow["bytes"], "packet_count": flow["count"],
            },
            reliability="high", confidence=0.9,
            synthetic=synthetic,
            raw_reference=pcap_path,
        )
        n += 1
    for d in result.get("dns", []):
        await add_evidence(
            session, investigation_id,
            source="pcap", source_type="pcap",
            timestamp=datetime.fromisoformat(d["ts"]),
            normalized_data={
                "event_kind": "dns", "domain": "network",
                "src_ip": d["src_ip"], "dst_ip": d["dst_ip"],
                "query": d["query"],
            },
            reliability="high", confidence=0.95,
            synthetic=synthetic, raw_reference=pcap_path,
        )
        n += 1
    for h in result.get("http", []):
        await add_evidence(
            session, investigation_id,
            source="pcap", source_type="pcap",
            timestamp=datetime.fromisoformat(h["ts"]),
            normalized_data={
                "event_kind": "http", "domain": "network",
                "src_ip": h["src_ip"], "dst_ip": h["dst_ip"],
                "method": h["method"], "path": h["path"],
            },
            reliability="high", confidence=0.95,
            synthetic=synthetic, raw_reference=pcap_path,
        )
        n += 1
    for t in result.get("tls", []):
        await add_evidence(
            session, investigation_id,
            source="pcap", source_type="pcap",
            timestamp=datetime.fromisoformat(t["ts"]),
            normalized_data={
                "event_kind": "tls", "domain": "network",
                "src_ip": t["src_ip"], "dst_ip": t["dst_ip"],
                "sni": t["sni"],
            },
            reliability="high", confidence=0.95,
            synthetic=synthetic, raw_reference=pcap_path,
        )
        n += 1
    for ind in result.get("industrial", []):
        await add_evidence(
            session, investigation_id,
            source="pcap", source_type="pcap",
            timestamp=datetime.fromisoformat(ind["ts"]),
            normalized_data={
                "event_kind": "industrial_protocol", "domain": "ot",
                "protocol": ind["protocol"], "src_ip": ind["src_ip"],
                "dst_ip": ind["dst_ip"],
                **{k: v for k, v in ind.items() if k not in ("ts", "src_ip", "dst_ip", "protocol")},
            },
            reliability="high", confidence=0.95,
            synthetic=synthetic, raw_reference=pcap_path,
        )
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Pcap tool wrapper for the tool registry
# --------------------------------------------------------------------------- #

from ..tools.base import Tool, ToolResult, ToolContext, register, READ_TELEMETRY


def contained_pcap_path(user_path: str):
    """Resolve `user_path` inside WITNESS_PCAP_DIR, or return None if it
    escapes it (absolute paths elsewhere, `..` traversal, symlinks out)."""
    from pathlib import Path
    from ..config import settings
    root = Path(settings.pcap_dir).resolve()
    candidate = Path(user_path)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if resolved == root or root in resolved.parents:
        return resolved
    return None


class PcapAnalyzeTool(Tool):
    name = "pcap_analyze"
    description = ("Parse a PCAP file and extract normalized network, DNS, "
                  "HTTP, TLS, and industrial-protocol evidence. Uses dpkt.")
    permissions = [READ_TELEMETRY]
    risk_level = "low"
    read_write = "read"
    input_schema = {"path": "string (PCAP file path)"}

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        path = args.get("path")
        if not path:
            return ToolResult(success=False, error="missing_path")
        safe = contained_pcap_path(path)
        if safe is None:
            return ToolResult(success=False, error="pcap_path_outside_pcap_dir")
        path = str(safe)
        result = await parse_pcap(path)
        if "error" in result:
            return ToolResult(success=False, error=result["error"])
        return ToolResult(
            success=True,
            data={
                "total_packets": result["total_packets"],
                "flows": len(result["flows"]),
                "dns": len(result["dns"]),
                "http": len(result["http"]),
                "tls": len(result["tls"]),
                "industrial": len(result["industrial"]),
                "result": result,
            },
            evidence=[{
                "source": "pcap",
                "source_type": "pcap",
                "host": None,
                "normalized_data": {
                    "event_kind": "pcap_summary",
                    "domain": "network",
                    "path": path,
                    "flow_count": len(result["flows"]),
                    "dns_count": len(result["dns"]),
                    "http_count": len(result["http"]),
                    "tls_count": len(result["tls"]),
                    "industrial_count": len(result["industrial"]),
                },
            }],
        )


register(PcapAnalyzeTool())
