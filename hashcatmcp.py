"""
Hashcat MCP Server
==================
Developed by: Anil Parashar (TechChip)
YouTube: https://www.youtube.com/@techchipnet
Website: https://www.techchip.net

A Model Context Protocol (MCP) server that wraps the hashcat suite.
Communicates via JSON-RPC 2.0 over stdio (default) or HTTP (--http flag).

HTTP mode added by Tattooed-Geek fork for remote MCP client access.
"""

import json
import sys
import subprocess
import re
import os
import logging
import tempfile
import time
import signal
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format="[hashcat-mcp] %(levelname)s %(message)s",
)
log = logging.getLogger("hashcat-mcp")

SERVER_NAME = "hashcat-mcp"
SERVER_VERSION = "1.0.5"
SERVER_AUTHOR = "Anil Parashar (TechChip)"
PROTOCOL_VERSION = "2024-11-05"

# --- Common Hash Modes Fallback ---
COMMON_MODES = [
    {"mode": 0, "name": "MD5", "category": "Raw Hash"},
    {"mode": 100, "name": "SHA1", "category": "Raw Hash"},
    {"mode": 1400, "name": "SHA256", "category": "Raw Hash"},
    {"mode": 1700, "name": "SHA512", "category": "Raw Hash"},
    {"mode": 3200, "name": "bcrypt", "category": "OS"},
    {"mode": 1000, "name": "NTLM", "category": "OS"},
    {"mode": 5600, "name": "NetNTLMv2", "category": "Network Protocol"},
    {"mode": 13100, "name": "Kerberoast TGS-REP", "category": "Network Protocol"},
    {"mode": 18200, "name": "Kerberos AS-REP", "category": "Network Protocol"},
    {"mode": 500, "name": "md5crypt", "category": "OS"},
    {"mode": 1800, "name": "sha512crypt", "category": "OS"},
    {"mode": 7400, "name": "sha256crypt", "category": "OS"},
    {"mode": 22000, "name": "WPA-PBKDF2-PMKID+EAPOL", "category": "Network Protocol"},
    {"mode": 11300, "name": "Bitcoin/Litecoin wallet.dat", "category": "Cryptocurrency"},
]

# --- Hash Identification Engine ---
HASH_SIGNATURES = [
    (r"^[a-fA-F0-9]{32}$", 32, "MD5", 0),
    (r"^[a-fA-F0-9]{32}$", 32, "NTLM / NT", 1000),
    (r"^[a-fA-F0-9]{32}$", 32, "MD4", 900),
    (r"^[a-fA-F0-9]{40}$", 40, "SHA1", 100),
    (r"^[a-fA-F0-9]{64}$", 64, "SHA-256", 1400),
    (r"^[a-fA-F0-9]{128}$", 128, "SHA-512", 1700),
    (r"^\$2[aby]?\$\d{2}\$.{53}$", None, "bcrypt", 3200),
    (r"^\$6\$", None, "sha512crypt", 1800),
    (r"^\$5\$", None, "sha256crypt", 7400),
    (r"^\$1\$", None, "md5crypt", 500),
    (r"^\$apr1\$", None, "Apache MD5", 1600),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", None, "MD5 (salted)", 10),
    (r"^\$krb5tgs\$", None, "Kerberoast TGS-REP", 13100),
    (r"^\$krb5asrep\$", None, "AS-REP Roast", 18200),
    (r"^[a-zA-Z0-9+/]+={0,2}$", None, "Base64", None), # General base64
]

# --- Tools Schema ---
TOOLS = [
    {
        "name": "identify_hash",
        "description": "Identify hash type from a hash string.",
        "inputSchema": {
            "type": "object",
            "properties": {"hash_string": {"type": "string", "description": "The hash string to identify"}},
            "required": ["hash_string"],
        },
    },
    {
        "name": "dictionary_attack",
        "description": "Wordlist/dictionary attack against hashes (-a 0). Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string", "description": "Inline hash string(s). Use \\n for multiple."},
                "hash_mode": {"type": "integer"},
                "wordlist": {"type": "string"},
                "session_name": {"type": "string", "description": "Optional custom session name. Auto-generated if omitted."},
                "workload": {"type": "integer"},
                "timeout": {"type": "integer"},
            },
            "required": ["hash_mode", "wordlist"],
        },
    },
    {
        "name": "combination_attack",
        "description": "Combine words from two wordlists (-a 1). Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
                "hash_mode": {"type": "integer"},
                "wordlist1": {"type": "string"},
                "wordlist2": {"type": "string"},
                "session_name": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["hash_mode", "wordlist1", "wordlist2"],
        },
    },
    {
        "name": "bruteforce_attack",
        "description": "Brute-force using mask patterns (-a 3). Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
                "hash_mode": {"type": "integer"},
                "mask": {"type": "string"},
                "session_name": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["hash_mode", "mask"],
        },
    },
    {
        "name": "hybrid_wordlist_mask",
        "description": "Wordlist + mask (-a 6). Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
                "hash_mode": {"type": "integer"},
                "wordlist": {"type": "string"},
                "mask": {"type": "string"},
                "session_name": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["hash_mode", "wordlist", "mask"],
        },
    },
    {
        "name": "hybrid_mask_wordlist",
        "description": "Mask + wordlist (-a 7). Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
                "hash_mode": {"type": "integer"},
                "mask": {"type": "string"},
                "wordlist": {"type": "string"},
                "session_name": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["hash_mode", "mask", "wordlist"],
        },
    },
    {
        "name": "rule_attack",
        "description": "Dictionary + rule file (-a 0 -r). Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
                "hash_mode": {"type": "integer"},
                "wordlist": {"type": "string"},
                "rule_file": {"type": "string"},
                "session_name": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["hash_mode", "wordlist", "rule_file"],
        },
    },
    {
        "name": "list_rules",
        "description": "Scan common directories and return available rule files for use in rule_attack.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "restore_session",
        "description": "Resume a paused/interrupted session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_name": {"type": "string"},
            },
            "required": ["session_name"],
        },
    },
    {
        "name": "show_cracked",
        "description": "Show already-cracked hashes. Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
                "hash_mode": {"type": "integer"},
            },
            "required": ["hash_mode"],
        },
    },
    {
        "name": "show_uncracked",
        "description": "Show remaining uncracked hashes. Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
                "hash_mode": {"type": "integer"},
            },
            "required": ["hash_mode"],
        },
    },
    {
        "name": "benchmark",
        "description": "Benchmark hash speed",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_mode": {"type": "integer"},
            },
            "required": ["hash_mode"],
        },
    },
    {
        "name": "list_devices",
        "description": "List OpenCL/CUDA devices",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "check_hashcat",
        "description": "Verify hashcat is installed",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "verify_hash_file",
        "description": "Validate hash file format & count hashes. Provide either hash_file OR hash_string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "hash_string": {"type": "string"},
            },
        },
    },
    {
        "name": "extract_hashes",
        "description": "Merge Linux passwd and shadow files to create crackable hashes (Python unshadow implementation).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "passwd_file": {"type": "string", "description": "Path to the passwd file"},
                "shadow_file": {"type": "string", "description": "Path to the shadow file"},
                "output_file": {"type": "string", "description": "Where to save the merged hashes"},
            },
            "required": ["passwd_file", "shadow_file", "output_file"],
        },
    },
    {
        "name": "list_hash_modes",
        "description": "Search supported hash modes by keyword. Returns structured JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string"}
            },
            "required": ["keyword"],
        },
    },
    {
        "name": "potfile_lookup",
        "description": "Search potfile for specific hashes",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_string": {"type": "string"}
            },
            "required": ["hash_string"],
        },
    },
    {
        "name": "generate_mask",
        "description": "Generate mask pattern suggestions",
        "inputSchema": {
            "type": "object",
            "properties": {
                "length": {"type": "integer"},
                "charset": {"type": "string", "description": "e.g., lower, upper, digits, special, all"}
            },
            "required": ["length"],
        },
    }
]

# --- Validation & Setup Helpers ---

def mask_paths(text: str) -> str:
    """Masks the user's home directory path to prevent username leaks."""
    if not text:
        return text
    home = os.path.expanduser("~")
    if home and home != "/" and home in text:
        text = text.replace(home.replace('\\', '/'), "~")
        text = text.replace(home.replace('/', '\\'), "~")
        text = text.replace(home, "~")
    return text

def setup_hash_input(args: dict, session_name: str | None = None) -> tuple[str | None, str | None, bool]:
    """Returns (error_msg, file_path, is_temp)."""
    if "hash_string" in args and args["hash_string"].strip():
        # Handle literal \n if JSON parser didn't
        content = args["hash_string"].replace("\\n", "\n")
        
        session_dir = os.path.expanduser("~/.hashcat_mcp_sessions")
        os.makedirs(session_dir, exist_ok=True)
        
        # Save to persistent session directory instead of /tmp so restore_session can find it
        if session_name:
            path = os.path.join(session_dir, f"{session_name}.hash")
        else:
            fd, path = tempfile.mkstemp(prefix="mcp_hash_", suffix=".txt", dir=session_dir)
            os.close(fd)
            
        with open(path, 'w') as f:
            f.write(content)
        return None, path, True
    elif "hash_file" in args and args["hash_file"].strip():
        hf = os.path.abspath(args["hash_file"])
        if not os.path.isfile(hf):
            return f"File not found: '{hf}'", None, False
        return None, hf, False
    else:
        return "Must provide either 'hash_file' or 'hash_string'", None, False

def cleanup_temp_file(path: str, is_temp: bool):
    if is_temp and path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass

def validate_file_exists(path: str) -> str | None:
    if not os.path.isfile(path):
        return f"File not found: '{path}'."
    return None

def validate_mode(mode: int) -> str | None:
    if not (0 <= mode <= 99999):
        return f"Invalid hash mode: {mode}"
    return None

def clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))

def generate_session_name(args: dict) -> str:
    if "session_name" in args and args["session_name"].strip():
        return args["session_name"].strip()
    return f"mcp_session_{int(time.time())}"

# --- Command Runner ---
def run_cmd(cmd: list[str], timeout: int | None = None, session_name: str | None = None) -> dict:
    # Ensure persistent session directory exists
    session_dir = os.path.expanduser("~/.hashcat_mcp_sessions")
    os.makedirs(session_dir, exist_ok=True)

    if session_name and "--restore-file-path" not in cmd:
        cmd.extend(["--restore-file-path", os.path.join(session_dir, f"{session_name}.restore")])

    log.info("Running: %s (timeout=%s)", " ".join(cmd), timeout)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=session_dir # Force hashcat to save sessions/logs here
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return {
                "success": proc.returncode == 0,
                "stdout": mask_paths(stdout),
                "stderr": mask_paths(stderr),
                "returncode": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            # Gracefully terminate so Hashcat saves its .restore checkpoint
            if sys.platform != "win32":
                proc.send_signal(signal.SIGINT) # Better chance of saving checkpoint
            else:
                proc.terminate()
                
            try:
                stdout, stderr = proc.communicate(timeout=3) # Give it 3s to save
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                
            msg = f"(Command timed out after {timeout}s"
            if session_name:
                msg += f". You can resume using restore_session with session_name: '{session_name}')\n"
            else:
                msg += ")\n"
                
            return {
                "success": True, # Timeout handled safely
                "stdout": mask_paths(msg + (stdout or "")),
                "stderr": mask_paths(stderr or ""),
                "returncode": 0,
            }
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": -1}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": mask_paths(str(e)), "returncode": -1}

# --- Tool Handlers ---
def handle_identify_hash(args: dict) -> dict:
    h = args["hash_string"].strip()
    length = len(h)
    matches = []
    for pattern, required_len, name, mode in HASH_SIGNATURES:
        if required_len and length != required_len:
            continue
        if re.match(pattern, h):
            matches.append(f"- {name} (Mode: {mode if mode is not None else 'Unknown'})")
    
    if not matches:
        return {"isError": False, "text": "No matching hash signatures found."}
    return {"isError": False, "text": "Possible hash types:\n" + "\n".join(matches)}

def handle_dictionary_attack(args: dict) -> dict:
    hm = args["hash_mode"]
    wl = os.path.abspath(args["wordlist"])
    t = clamp(args.get("timeout", 300), 10, 3600)
    sess = generate_session_name(args)
    
    err, hf, is_temp = setup_hash_input(args, sess)
    if err: return {"isError": True, "text": err}
    
    if err := validate_file_exists(wl):
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    if err := validate_mode(hm):
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    
    cmd = ["hashcat", "-m", str(hm), "-a", "0", hf, wl, "--session", sess]
    if "workload" in args:
        cmd.extend(["-w", str(clamp(args["workload"], 1, 4))])
        
    res = run_cmd(cmd, timeout=t, session_name=sess)
    
    # Only clean up if it didn't timeout, so restore_session can find the hash file!
    if is_temp and "(Command timed out" not in res.get("stdout", ""):
        cleanup_temp_file(hf, is_temp)
        
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_combination_attack(args: dict) -> dict:
    hm = args["hash_mode"]
    wl1 = os.path.abspath(args["wordlist1"])
    wl2 = os.path.abspath(args["wordlist2"])
    t = clamp(args.get("timeout", 300), 10, 3600)
    sess = generate_session_name(args)
    
    err, hf, is_temp = setup_hash_input(args, sess)
    if err: return {"isError": True, "text": err}
    
    if err := validate_file_exists(wl1): 
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    if err := validate_file_exists(wl2): 
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    
    cmd = ["hashcat", "-m", str(hm), "-a", "1", hf, wl1, wl2, "--session", sess]
    res = run_cmd(cmd, timeout=t, session_name=sess)
    
    if is_temp and "(Command timed out" not in res.get("stdout", ""):
        cleanup_temp_file(hf, is_temp)
        
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_bruteforce_attack(args: dict) -> dict:
    hm, mask = args["hash_mode"], args["mask"]
    t = clamp(args.get("timeout", 300), 10, 3600)
    sess = generate_session_name(args)
    
    err, hf, is_temp = setup_hash_input(args, sess)
    if err: return {"isError": True, "text": err}
    
    cmd = ["hashcat", "-m", str(hm), "-a", "3", hf, mask, "--session", sess]
    res = run_cmd(cmd, timeout=t, session_name=sess)
    
    if is_temp and "(Command timed out" not in res.get("stdout", ""):
        cleanup_temp_file(hf, is_temp)
        
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_hybrid_wordlist_mask(args: dict) -> dict:
    hm, mask = args["hash_mode"], args["mask"]
    wl = os.path.abspath(args["wordlist"])
    t = clamp(args.get("timeout", 300), 10, 3600)
    sess = generate_session_name(args)
    
    err, hf, is_temp = setup_hash_input(args, sess)
    if err: return {"isError": True, "text": err}
    
    if err := validate_file_exists(wl): 
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    
    cmd = ["hashcat", "-m", str(hm), "-a", "6", hf, wl, mask, "--session", sess]
    res = run_cmd(cmd, timeout=t, session_name=sess)
    
    if is_temp and "(Command timed out" not in res.get("stdout", ""):
        cleanup_temp_file(hf, is_temp)
        
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_hybrid_mask_wordlist(args: dict) -> dict:
    hm, mask = args["hash_mode"], args["mask"]
    wl = os.path.abspath(args["wordlist"])
    t = clamp(args.get("timeout", 300), 10, 3600)
    sess = generate_session_name(args)
    
    err, hf, is_temp = setup_hash_input(args, sess)
    if err: return {"isError": True, "text": err}
    
    if err := validate_file_exists(wl): 
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    
    cmd = ["hashcat", "-m", str(hm), "-a", "7", hf, mask, wl, "--session", sess]
    res = run_cmd(cmd, timeout=t, session_name=sess)
    
    if is_temp and "(Command timed out" not in res.get("stdout", ""):
        cleanup_temp_file(hf, is_temp)
        
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_rule_attack(args: dict) -> dict:
    hm = args["hash_mode"]
    wl = os.path.abspath(args["wordlist"])
    rf = os.path.abspath(args["rule_file"])
    t = clamp(args.get("timeout", 300), 10, 3600)
    sess = generate_session_name(args)
    
    err, hf, is_temp = setup_hash_input(args, sess)
    if err: return {"isError": True, "text": err}
    
    if err := validate_file_exists(wl): 
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    if err := validate_file_exists(rf): 
        if is_temp: cleanup_temp_file(hf, is_temp)
        return {"isError": True, "text": err}
    
    cmd = ["hashcat", "-m", str(hm), "-a", "0", hf, wl, "-r", rf, "--session", sess]
    res = run_cmd(cmd, timeout=t, session_name=sess)
    
    if is_temp and "(Command timed out" not in res.get("stdout", ""):
        cleanup_temp_file(hf, is_temp)
        
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_list_rules(args: dict) -> dict:
    search_dirs = [
        "/usr/share/hashcat/rules",
        "/usr/local/share/hashcat/rules",
        "/opt/hashcat/rules",
        os.path.expanduser("~/.hashcat/rules")
    ]
    found = []
    for d in search_dirs:
        if os.path.isdir(d):
            for root, _, files in os.walk(d):
                for f in files:
                    if f.endswith(".rule"):
                        found.append(os.path.join(root, f))
    
    if not found:
        fallback_dir = os.path.expanduser("~/.hashcat_mcp_rules")
        os.makedirs(fallback_dir, exist_ok=True)
        fallback_file = os.path.join(fallback_dir, "mcp_fallback.rule")
        if not os.path.exists(fallback_file):
            with open(fallback_file, "w") as f:
                # Basic useful mutations: nothing, lowercase, uppercase, capitalize, append 0-9, append !?
                f.write(":\nc\nl\nu\nC\nt\nd\n$0\n$1\n$2\n$3\n$4\n$5\n$6\n$7\n$8\n$9\n$!\n$?\n")
        found.append(fallback_file)
        return {"isError": False, "text": "No system rules found. Created fallback rule file:\n" + "\n".join(found)}
        
    return {"isError": False, "text": "Available rule files:\n" + "\n".join(found)}

def handle_restore_session(args: dict) -> dict:
    sess = args["session_name"]
    session_dir = os.path.expanduser("~/.hashcat_mcp_sessions")
    restore_file = os.path.join(session_dir, f"{sess}.restore")
    
    if not os.path.exists(restore_file):
        return {"isError": True, "text": f"Session restore file '{restore_file}' not found. Cannot restore."}

    cmd = ["hashcat", "--session", sess, "--restore", "--restore-file-path", restore_file]
    res = run_cmd(cmd, timeout=300, session_name=sess)
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_show_cracked(args: dict) -> dict:
    err, hf, is_temp = setup_hash_input(args)
    if err: return {"isError": True, "text": err}
    
    hm = args["hash_mode"]
    cmd = ["hashcat", "-m", str(hm), hf, "--show"]
    res = run_cmd(cmd, timeout=10)
    cleanup_temp_file(hf, is_temp)
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_show_uncracked(args: dict) -> dict:
    err, hf, is_temp = setup_hash_input(args)
    if err: return {"isError": True, "text": err}
    
    hm = args["hash_mode"]
    cmd = ["hashcat", "-m", str(hm), hf, "--left"]
    res = run_cmd(cmd, timeout=10)
    cleanup_temp_file(hf, is_temp)
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_benchmark(args: dict) -> dict:
    cmd = ["hashcat", "-b", "-m", str(args["hash_mode"])]
    res = run_cmd(cmd, timeout=60)
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_list_devices(args: dict) -> dict:
    cmd = ["hashcat", "-I"]
    res = run_cmd(cmd)
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_check_hashcat(args: dict) -> dict:
    cmd = ["hashcat", "--version"]
    res = run_cmd(cmd)
    return {"isError": not res["success"], "text": res["stdout"] or res["stderr"]}

def handle_verify_hash_file(args: dict) -> dict:
    err, hf, is_temp = setup_hash_input(args)
    if err: return {"isError": True, "text": err}
    
    with open(hf, 'r', errors='ignore') as f:
        lines = f.readlines()
    cleanup_temp_file(hf, is_temp)
    return {"isError": False, "text": f"Provided input contains {len(lines)} lines/hashes."}

def handle_extract_hashes(args: dict) -> dict:
    passwd_file = os.path.abspath(args["passwd_file"])
    shadow_file = os.path.abspath(args["shadow_file"])
    out_file = os.path.abspath(args["output_file"])
    
    if err := validate_file_exists(passwd_file): return {"isError": True, "text": err}
    if err := validate_file_exists(shadow_file): return {"isError": True, "text": err}
    
    shadow_map = {}
    try:
        with open(shadow_file, 'r', errors='ignore') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    shadow_map[parts[0]] = parts[1]
                    
        merged_count = 0
        with open(passwd_file, 'r', errors='ignore') as f_in, open(out_file, 'w', errors='ignore') as f_out:
            for line in f_in:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    user = parts[0]
                    if user in shadow_map and shadow_map[user] not in ('*', '!', 'x', ''):
                        parts[1] = shadow_map[user]
                        f_out.write(':'.join(parts) + "\n")
                        merged_count += 1
                        
        return {"isError": False, "text": f"Successfully unshadowed {merged_count} hashes to {out_file}."}
    except Exception as e:
        return {"isError": True, "text": f"Error extracting hashes: {e}"}

def handle_list_hash_modes(args: dict) -> dict:
    keyword = args["keyword"].lower()
    results = []
    
    # Try parsing hashcat --help output using relaxed regex
    res = run_cmd(["hashcat", "--help"], timeout=10)
    if res["success"]:
        pattern = re.compile(r"^\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)$")
        for line in res["stdout"].splitlines():
            match = pattern.match(line)
            if match:
                mode_num = int(match.group(1).strip())
                name = match.group(2).strip()
                category = match.group(3).strip()
                
                if keyword in name.lower() or keyword in category.lower() or keyword == str(mode_num):
                    results.append({
                        "mode": mode_num,
                        "name": name,
                        "category": category,
                        "example_command": f"hashcat -m {mode_num} hash.txt wordlist.txt"
                    })
                    
    # If standard parsing fails (empty list), check fallback COMMON_MODES
    if not results:
        for m in COMMON_MODES:
            if keyword in m["name"].lower() or keyword in m["category"].lower() or keyword == str(m["mode"]):
                m_copy = m.copy()
                m_copy["example_command"] = f"hashcat -m {m['mode']} hash.txt wordlist.txt"
                results.append(m_copy)

    if not results:
        return {"isError": False, "text": json.dumps({"status": "no_results_found", "data": []})}
        
    return {"isError": False, "text": json.dumps({"status": "success", "data": results}, indent=2)}

def handle_potfile_lookup(args: dict) -> dict:
    potfile = os.path.expanduser("~/.local/share/hashcat/hashcat.potfile")
    if not os.path.exists(potfile): potfile = "hashcat.potfile"
    if not os.path.exists(potfile): return {"isError": True, "text": "Potfile not found."}
    
    out = []
    h = args["hash_string"]
    with open(potfile, "r", errors="ignore") as f:
        for line in f:
            if h in line: out.append(line.strip())
    return {"isError": False, "text": "\n".join(out) if out else "Hash not found in potfile."}

def handle_generate_mask(args: dict) -> dict:
    l = clamp(args["length"], 1, 15)
    c = args.get("charset", "all").lower()
    mapping = {"lower": "?l", "upper": "?u", "digits": "?d", "special": "?s", "all": "?a"}
    char = mapping.get(c, "?a")
    return {"isError": False, "text": "Suggested mask: " + (char * l)}

TOOL_HANDLERS = {
    "identify_hash": handle_identify_hash,
    "dictionary_attack": handle_dictionary_attack,
    "combination_attack": handle_combination_attack,
    "bruteforce_attack": handle_bruteforce_attack,
    "hybrid_wordlist_mask": handle_hybrid_wordlist_mask,
    "hybrid_mask_wordlist": handle_hybrid_mask_wordlist,
    "rule_attack": handle_rule_attack,
    "list_rules": handle_list_rules,
    "restore_session": handle_restore_session,
    "show_cracked": handle_show_cracked,
    "show_uncracked": handle_show_uncracked,
    "benchmark": handle_benchmark,
    "list_devices": handle_list_devices,
    "check_hashcat": handle_check_hashcat,
    "verify_hash_file": handle_verify_hash_file,
    "extract_hashes": handle_extract_hashes,
    "list_hash_modes": handle_list_hash_modes,
    "potfile_lookup": handle_potfile_lookup,
    "generate_mask": handle_generate_mask,
}

# --- HTTP Server (StreamableHTTP mode) ---

class MCPHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for MCP StreamableHTTP transport."""

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._send_error(-32700, "Parse error")
            return

        if not isinstance(req, dict) or "method" not in req:
            self._send_error(-32600, "Invalid Request")
            return

        res = handle_request(req)
        if res is not None:
            self._send_json(res)
        else:
            self.send_response(202)
            self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "server": SERVER_NAME, "version": SERVER_VERSION}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_error(self, code: int, message: str):
        self._send_json({"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}})

    def log_message(self, format, *args):
        log.info("HTTP %s", format % args)


def run_http_server(host: str = "0.0.0.0", port: int = 9090):
    """Run the MCP server in HTTP mode."""
    server = HTTPServer((host, port), MCPHTTPHandler)
    log.info("Hashcat MCP HTTP server listening on http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down HTTP server")
        server.shutdown()


# --- JSON-RPC 2.0 Loop ---
def make_response(req_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}

def make_error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

def handle_request(req: dict) -> dict:
    req_id = req.get("id")
    method = req.get("method")
    
    if method == "initialize":
        return make_response(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
    elif method == "notifications/initialized":
        return None
    elif method == "ping":
        return make_response(req_id, {})
    elif method == "tools/list":
        return make_response(req_id, {"tools": TOOLS})
    elif method == "tools/call":
        tool_name = req.get("params", {}).get("name")
        args = req.get("params", {}).get("arguments", {})
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return make_error(req_id, -32602, f"Unknown tool: '{tool_name}'")
        try:
            res = handler(args)
            # Mask paths in final output text
            text = mask_paths(res["text"])
            return make_response(req_id, {"content": [{"type": "text", "text": text}], "isError": res.get("isError", False)})
        except KeyError as e:
            return make_error(req_id, -32602, f"Missing required parameter: {e}")
        except Exception as e:
            return make_error(req_id, -32603, str(e))
    return make_error(req_id, -32601, f"Unknown method: '{method}'")

def main():
    parser = argparse.ArgumentParser(description="Hashcat MCP Server")
    parser.add_argument("--http", action="store_true", help="Run in HTTP mode instead of stdio")
    parser.add_argument("--host", default="0.0.0.0", help="HTTP bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9090, help="HTTP port (default: 9090)")
    args = parser.parse_args()

    if args.http:
        run_http_server(host=args.host, port=args.port)
        return

    log.info("Hashcat MCP server started (stdio mode)")
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(make_error(None, -32700, "Parse error")) + "\n")
            sys.stdout.flush()
            continue

        if not isinstance(req, dict) or "method" not in req:
            sys.stdout.write(json.dumps(make_error(req.get("id"), -32600, "Invalid Request")) + "\n")
            sys.stdout.flush()
            continue

        res = handle_request(req)
        if res is not None:
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
