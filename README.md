# Hashcat MCP Server

**Developed By: Anil Parashar (TechChip)**  
**YouTube:** [@techchipnet](https://www.youtube.com/@techchipnet) | **Website:** [techchip.net](https://www.techchip.net)

Hashcat-MCP is a server implementation of the Model Context Protocol (MCP) designed to bridge large language models with the powerful capabilities of Hashcat, a widely used password recovery and hash-cracking tool. By exposing Hashcat’s functionality through a structured, machine-readable interface, Hashcat-MCP allows AI systems to securely invoke, control, and automate complex cracking workflows.

With Hashcat-MCP, language models can perform tasks such as identifying hash types, configuring attack modes (dictionary, brute-force, hybrid, and rule-based attacks), managing wordlists and masks, and monitoring cracking progress in real time. This integration enables more efficient, context-aware automation of security auditing, penetration testing, and forensic analysis processes.

The system is particularly useful for cybersecurity professionals, researchers, and developers who want to incorporate intelligent automation into password recovery tasks, while maintaining fine-grained control over execution parameters. By combining the reasoning capabilities of large language models with Hashcat’s high-performance computation, Hashcat-MCP streamlines workflows that would otherwise require significant manual setup and expertise.

## Prerequisites

| Requirement | Details |
|---|---|
| Python | 3.10+ |
| hashcat | Must be installed and in `$PATH` |
| OS | Linux/Windows/macOS |

## Available Tools

| Tool | Description |
|---|---|
| `identify_hash` | Built-in tool to identify hash types and suggest hashcat `-m` mode |
| `dictionary_attack` | Wordlist/dictionary attack against hashes (`-a 0`) |
| `combination_attack` | Combine words from two wordlists (`-a 1`) |
| `bruteforce_attack` | Brute-force using mask patterns (`-a 3`) |
| `hybrid_wordlist_mask` | Wordlist + mask (`-a 6`) |
| `hybrid_mask_wordlist` | Mask + wordlist (`-a 7`) |
| `rule_attack` | Dictionary + rule file for word mutations (`-a 0 -r`) |
| `restore_session` | Resume a paused/interrupted session (`--restore`) |
| `show_cracked` | Show already-cracked hashes (`--show`) |
| `show_uncracked` | Show remaining uncracked hashes (`--left`) |
| `benchmark` | Benchmark hash speed (`-b`) |
| `list_devices` | List OpenCL/CUDA devices (`-I`) |
| `check_hashcat` | Verify hashcat version |
| `verify_hash_file` | Validate hash file format & count hashes |
| `extract_hashes` | Extract hashes from common file formats |
| `list_hash_modes` | Search supported hash modes |
| `potfile_lookup` | Search potfile for specific hashes |
| `generate_mask` | Generate mask pattern suggestions |

## Usage

### Run the server directly
```bash
python3 hashcatmcp.py
```
The server reads JSON-RPC 2.0 messages from **stdin** and writes responses to **stdout**.

### MCP Client Configuration

Add this to your MCP client config (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "hashcat": {
      "command": "python3",
      "args": [
        "/absolute/path/to/hashcat-mcp/hashcatmcp.py"
      ]
    }
  }
}
```

## Security

- **No External Dependency for Hash ID**: Built-in regex engine.
- **File Validation**: File paths are checked for existence before use.
- **Timeouts**: Long-running attacks have configurable timeouts.
- **No Shell Execution**: Commands use list-based `subprocess.run()` (no shell injection).
---

> ⚠️ **Legal Disclaimer**: This tool is for **authorized penetration testing and security research only**. Unauthorized access to computer networks is illegal. Always obtain written permission before testing.

---
**Developed with ❤️ by [Anil Parashar (TechChip)](https://www.youtube.com/@techchipnet)**
