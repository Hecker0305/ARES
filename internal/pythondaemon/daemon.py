"""
Enterprise-grade Python daemon for Ares Engine.
Long-lived process handling YARA, Capstone, CAPA, and Scapy operations
via JSON-RPC over stdin/stdout. Eliminates subprocess overhead per operation.
"""
import sys, json, base64, os, traceback, logging, threading
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("ares-daemon")

CAPABILITIES = {}

try:
    import yara
    CAPABILITIES["yara"] = yara.__version__
except ImportError:
    CAPABILITIES["yara"] = False

try:
    from capstone import *
    CAPABILITIES["capstone"] = True
except ImportError:
    CAPABILITIES["capstone"] = False

try:
    from scapy.all import IP, TCP, ICMP, UDP, Ether, send, sr1, conf
    conf.verb = 0
    CAPABILITIES["scapy"] = True
except ImportError:
    CAPABILITIES["scapy"] = False

try:
    import capa
    CAPABILITIES["capa"] = True
except ImportError:
    CAPABILITIES["capa"] = False

# Embedded YARA rules
YARA_RULES = """
rule ProcessInjection {
    strings:
        $a1 = "OpenProcess" nocase
        $a2 = "VirtualAllocEx" nocase
        $a3 = "WriteProcessMemory" nocase
        $a4 = "CreateRemoteThread" nocase
        $a5 = "NtCreateThreadEx" nocase
    condition: 2 of ($a*)
}
rule AntiDebug {
    strings:
        $a1 = "IsDebuggerPresent" nocase
        $a2 = "NtQueryInformationProcess" nocase
        $a3 = "ptrace" nocase
    condition: 1 of ($a*)
}
rule NetworkAPI {
    strings:
        $a1 = "socket" nocase
        $a2 = "connect" nocase
        $a3 = "WinHttpOpen" nocase
        $a4 = "InternetOpen" nocase
    condition: 2 of ($a*)
}
rule CryptoAPI {
    strings:
        $a1 = "CryptEncrypt" nocase
        $a2 = "CryptDecrypt" nocase
        $a3 = "BCrypt" nocase
    condition: 1 of ($a*)
}
rule Persistence {
    strings:
        $a1 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $a2 = "CreateService" nocase
        $a3 = "cron" nocase
    condition: 1 of ($a*)
}
"""

_yara_rules_compiled = None


def get_yara_rules():
    global _yara_rules_compiled
    if _yara_rules_compiled is None and CAPABILITIES["yara"]:
        try:
            _yara_rules_compiled = yara.compile(source=YARA_RULES)
        except Exception as e:
            log.error("YARA compile error: %s", e)
    return _yara_rules_compiled


def handle_yara(data_b64):
    if not CAPABILITIES["yara"]:
        return {"error": "yara-python not available", "capability": False}
    rules = get_yara_rules()
    if not rules:
        return {"error": "YARA rules not compiled", "capability": True}
    try:
        data = base64.b64decode(data_b64)
        matches = rules.match(data=data)
        result = []
        for m in matches:
            strings_found = []
            if hasattr(m, "strings"):
                for s in m.strings[:20]:
                    for inst in s.instances[:3]:
                        strings_found.append({
                            "identifier": s.identifier,
                            "offset": inst.offset,
                            "data": inst.data[:32].hex(),
                        })
            result.append({
                "rule": m.rule,
                "meta": m.meta if hasattr(m, "meta") else {},
                "strings": strings_found,
            })
        return {"matches": result}
    except Exception as e:
        return {"error": str(e)}


def handle_capstone(data_b64, fmt, base_addr):
    if not CAPABILITIES["capstone"]:
        return {"error": "capstone not available"}
    try:
        data = base64.b64decode(data_b64)
        if fmt == "pe" and data[:2] == b"MZ":
            import struct
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            machine = struct.unpack_from("<H", data, pe_off + 4)[0]
            arch_map = {
                0x14c: (CS_ARCH_X86, CS_MODE_32),
                0x8664: (CS_ARCH_X86, CS_MODE_64),
            }
            arch_info = arch_map.get(machine)
            if not arch_info:
                return {"error": f"unsupported PE machine 0x{machine:x}"}
            ARCH, MODE = arch_info
            opt_hdr_off = pe_off + 24
            magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
            sec_off = opt_hdr_off + (96 if magic == 0x10b else 112)
            num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
            sections = []
            for i in range(min(num_sec, 50)):
                s_start = sec_off + i * 40
                name = data[s_start:s_start+8].rstrip(b"\x00").decode("ascii", errors="replace")
                vaddr = struct.unpack_from("<I", data, s_start + 12)[0]
                vsize = struct.unpack_from("<I", data, s_start + 8)[0]
                raw_size = struct.unpack_from("<I", data, s_start + 16)[0]
                raw_off = struct.unpack_from("<I", data, s_start + 20)[0]
                if raw_size == 0:
                    continue
                sec_data = data[raw_off:raw_off + raw_size]
                md = Cs(ARCH, MODE)
                insns = []
                for insn in md.disasm(sec_data, base_addr + vaddr):
                    insns.append({
                        "address": hex(insn.address),
                        "size": insn.size,
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                    })
                    if len(insns) >= 5000:
                        break
                sections.append({
                    "section": name,
                    "virtual_address": hex(vaddr),
                    "size": len(sec_data),
                    "instruction_count": len(insns),
                    "instructions": insns,
                })
            return {"sections": sections}

        elif fmt == "elf" and data[:4] == b"\x7fELF":
            import struct
            ei_class = data[4]
            if ei_class == 1:
                e_machine = struct.unpack_from("<H", data, 18)[0]
                e_shoff = struct.unpack_from("<I", data, 32)[0]
                e_shentsize = struct.unpack_from("<H", data, 46)[0]
                e_shnum = struct.unpack_from("<H", data, 48)[0]
                ARCH, MODE = (CS_ARCH_X86, CS_MODE_32) if e_machine == 3 else (CS_ARCH_ARM, CS_MODE_ARM)
                sh_size = 40
            else:
                e_machine = struct.unpack_from("<H", data, 18)[0]
                e_shoff = struct.unpack_from("<Q", data, 40)[0]
                e_shnum = struct.unpack_from("<H", data, 60)[0]
                ARCH, MODE = (CS_ARCH_X86, CS_MODE_64) if e_machine == 0x3e else (CS_ARCH_ARM64, CS_MODE_ARM)
                sh_size = 64
            sections = []
            for i in range(min(e_shnum, 50)):
                off = e_shoff + i * sh_size
                if ei_class == 1:
                    sh_addr, sh_offset, sh_size_val = struct.unpack_from("<I I I", data, off + 12)[1:4]
                    sh_flags_raw = struct.unpack_from("<I", data, off + 8)[0]
                else:
                    sh_addr, sh_offset, sh_size_val = struct.unpack_from("<Q Q Q", data, off + 16)[:3]
                    sh_flags_raw = struct.unpack_from("<Q", data, off + 8)[0]
                if not (sh_flags_raw & 2) or sh_size_val == 0:
                    continue
                sec_data = data[sh_offset:sh_offset + sh_size_val]
                md = Cs(ARCH, MODE)
                insns = []
                for insn in md.disasm(sec_data, base_addr + sh_addr):
                    insns.append({
                        "address": hex(insn.address),
                        "size": insn.size,
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                    })
                    if len(insns) >= 5000:
                        break
                sections.append({
                    "section": f"section_{i}",
                    "virtual_address": hex(sh_addr),
                    "size": sh_size_val,
                    "instruction_count": len(insns),
                    "instructions": insns,
                })
            return {"sections": sections}
        return {"error": "unrecognized format"}
    except Exception as e:
        return {"error": f"capstone: {e}"}


def handle_scapy_send(target, port, proto, count):
    if not CAPABILITIES["scapy"]:
        return {"error": "scapy not available"}
    try:
        pkts_sent = 0
        bytes_sent = 0
        if proto == "tcp":
            for _ in range(min(count, 100)):
                pkt = IP(dst=target) / TCP(dport=port, flags="S")
                send(pkt, verbose=0)
                pkts_sent += 1
                bytes_sent += len(pkt)
        elif proto == "icmp":
            for _ in range(min(count, 100)):
                pkt = IP(dst=target) / ICMP()
                send(pkt, verbose=0)
                pkts_sent += 1
                bytes_sent += len(pkt)
        elif proto == "udp":
            for _ in range(min(count, 100)):
                pkt = IP(dst=target) / UDP(dport=port)
                send(pkt, verbose=0)
                pkts_sent += 1
                bytes_sent += len(pkt)
        return {"packets_sent": pkts_sent, "bytes_sent": bytes_sent}
    except Exception as e:
        return {"error": f"scapy: {e}"}


def handle_capa(file_b64, filename):
    if not CAPABILITIES["capa"]:
        return {"error": "capa not available"}
    import tempfile, subprocess
    data = base64.b64decode(file_b64)
    ext_map = {b"MZ": ".exe", b"\x7fELF": ".elf"}
    ext = ".bin"
    for magic, e in ext_map.items():
        if data[:len(magic)] == magic:
            ext = e
            break
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
            f.write(data)
            f.flush()
            fname = f.name
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--json", fname],
            capture_output=True, text=True, timeout=60,
        )
        os.unlink(fname)
        if r.returncode == 0:
            parsed = json.loads(r.stdout)
            rules = []
            if "rules" in parsed:
                for name, rule in parsed["rules"].items():
                    rules.append(name)
            return {"rules": rules[:50], "raw": parsed}
        elif "No supported" in r.stderr:
            return {"status": "skipped", "reason": r.stderr[:200]}
        else:
            return {"error": r.stderr[:500]}
    except Exception as e:
        return {"error": str(e)}


def handle_capa_from_path(filepath):
    """CAPA analysis from an already-written file path (no b64 transfer)."""
    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--json", filepath],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode == 0:
            parsed = json.loads(r.stdout)
            rules = []
            if "rules" in parsed:
                for name in parsed["rules"]:
                    rules.append(name)
            return {"rules": rules[:100]}
        elif "No supported" in r.stderr:
            return {"status": "skipped", "reason": r.stderr[:200]}
        else:
            return {"error": r.stderr[:500]}
    except subprocess.TimeoutExpired:
        return {"error": "capa timed out after 120s"}
    except Exception as e:
        return {"error": str(e)}


HANDLERS = {
    "ping": lambda req: {"pong": True, "capabilities": {k: bool(v) for k, v in CAPABILITIES.items()}},
    "yara": lambda req: handle_yara(req.get("data", "")),
    "capstone": lambda req: handle_capstone(req.get("data", ""), req.get("format", "pe"), req.get("base_addr", 0)),
    "scapy_send": lambda req: handle_scapy_send(req.get("target", ""), int(req.get("port", 80)), req.get("proto", "tcp"), int(req.get("count", 1))),
    "capa": lambda req: handle_capa_from_path(req.get("filepath", "")),
}


def main():
    log.info("Ares Python daemon started. Capabilities: %s", {k: bool(v) for k, v in CAPABILITIES.items()})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method", "")
            params = req.get("params", {})
            handler = HANDLERS.get(method)
            if handler:
                result = handler(params)
            else:
                result = {"error": f"unknown method: {method}"}
        except json.JSONDecodeError as e:
            result = {"error": f"invalid JSON: {e}"}
        except Exception as e:
            result = {"error": f"unhandled: {e}", "traceback": traceback.format_exc()}

        response = {"jsonrpc": "2.0", "result": result, "id": req_id}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
