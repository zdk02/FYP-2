#!/usr/bin/env python3
"""
AEGIS Seeder: Client-Side Vulnerability Scanner
================================================

Integrates the client vulnerability scanner into your AEGIS framework.
Handles:
  1. Creates "Client-Side" category + "Vulnerability Scanning" subcategory (if missing)
  2. Copies cve_database.yaml to AEGIS backend data directory
  3. Patches the scanner script to find the YAML in AEGIS paths
  4. Inserts the attack into the SQLite database

Usage:
  # Step 1: See what's in your database
  python seed_client_scanner.py --db /path/to/aegis.db --list

  # Step 2: Seed with auto-created subcategory
  python seed_client_scanner.py --db /path/to/aegis.db --auto

  # Step 3: Or specify an existing subcategory
  python seed_client_scanner.py --db /path/to/aegis.db --subcategory YOUR_ID

  # The script auto-detects common AEGIS DB paths if --db is omitted
"""

import os
import sys
import json
import uuid
import sqlite3
import shutil
from datetime import datetime


# ═══════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Scanner files (should be in same directory as this seed script)
SCANNER_PY = os.path.join(SCRIPT_DIR, "client_vuln_scanner.py")
CVE_DB_YAML = os.path.join(SCRIPT_DIR, "cve_database.yaml")
TEST_HARNESS = os.path.join(SCRIPT_DIR, "test_harness.py")

# Common AEGIS DB locations
DB_CANDIDATES = [
    "backend/instance/aegis.db",
    "instance/aegis.db",
    "../backend/instance/aegis.db",
    "../../backend/instance/aegis.db",
    "../instance/aegis.db",
    "aegis.db",
]

# Where to put cve_database.yaml inside AEGIS
# The scanner will look here at runtime
AEGIS_DATA_DIRS = [
    "backend/data/client_scanner",
    "data/client_scanner",
    "../backend/data/client_scanner",
]


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK DEFINITION
# ═══════════════════════════════════════════════════════════════════════════

ATTACK_METADATA = {
    "name": "MCP Client Vulnerability Scanner",
    "description": (
        "Enterprise-grade MCP client vulnerability scanner with three-layer "
        "verification: (1) version correlation, (2) environment/config analysis, "
        "(3) active non-destructive verification probes. Scans 12 MCP clients "
        "(Claude Code, Cursor, Copilot, Windsurf, etc.) against 28+ verified CVEs. "
        "Each finding includes a confidence score (confirmed/high/medium/low). "
        "Fully YAML-driven — update cve_database.yaml to add new clients and CVEs."
    ),
    "severity": "high",
    "attack_type": "scanner",
    "script_language": "python",
    "config_schema": {
        "timeout": {"type": "integer", "default": 30, "description": "Request timeout in seconds"},
        "scan_depth": {
            "type": "string", "default": "full",
            "enum": ["quick", "standard", "full"],
            "description": "quick=fingerprint | standard=+environment | full=+active verification"
        },
        "client_hint": {
            "type": "string", "default": "auto",
            "description": "Which client to scan. 'auto' scans all. Comma-separated keys for specific clients."
        },
        "check_local": {"type": "boolean", "default": True, "description": "Scan local system"},
        "check_remote": {"type": "boolean", "default": True, "description": "Probe remote endpoints"},
        "min_severity": {
            "type": "string", "default": "low",
            "enum": ["critical", "high", "medium", "low"],
            "description": "Minimum CVE severity to report"
        },
        "min_confidence": {
            "type": "string", "default": "low",
            "enum": ["confirmed", "high", "medium", "low"],
            "description": "Minimum confidence to report"
        },
    },
    "default_config": {
        "timeout": 30, "scan_depth": "full", "client_hint": "auto",
        "check_local": True, "check_remote": True,
        "min_severity": "low", "min_confidence": "low",
    },
    "prerequisites": (
        "cve_database.yaml must be in the AEGIS data directory "
        "(backend/data/client_scanner/). PyYAML and requests required."
    ),
    "remediation": (
        "Update all identified MCP clients to their latest patched versions. "
        "Review each CVE finding for specific remediation guidance. "
        "Remove dangerous MCP config patterns (enableAllProjectMcpServers, "
        "ANTHROPIC_BASE_URL overrides, autoApprove settings)."
    ),
    "tags": [
        "mcp", "client", "cve", "fingerprint", "version-detection",
        "active-verification", "vulnerability-scanner", "reconnaissance",
        "client-side", "pillar-3"
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# DATABASE HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def find_db(custom_path=None):
    """Auto-detect AEGIS database path."""
    if custom_path and os.path.exists(custom_path):
        return os.path.abspath(custom_path)
    for c in DB_CANDIDATES:
        if os.path.exists(c):
            return os.path.abspath(c)
    return None


def get_tables(db_path):
    """List all tables in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cursor.fetchall()]
    conn.close()
    return tables


def find_subcat_table(db_path):
    """Find the subcategories table name."""
    tables = get_tables(db_path)
    for name in ["sub_categories", "subcategories", "sub_category", "subcategory"]:
        if name in tables:
            return name
    return None


def find_cat_table(db_path):
    """Find the categories table name."""
    tables = get_tables(db_path)
    for name in ["categories", "category"]:
        if name in tables:
            return name
    return None


def list_all(db_path):
    """List categories, subcategories, and existing attacks."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Categories
    cat_table = find_cat_table(db_path)
    if cat_table:
        print(f"\n  Categories (table: {cat_table}):")
        try:
            cursor.execute(f"SELECT id, name FROM {cat_table} ORDER BY name")
            for row in cursor.fetchall():
                print(f"    {row[0]:<40} {row[1]}")
        except Exception as e:
            print(f"    Error: {e}")

    # Subcategories
    subcat_table = find_subcat_table(db_path)
    if subcat_table:
        print(f"\n  Subcategories (table: {subcat_table}):")
        try:
            cursor.execute(f"SELECT id, name FROM {subcat_table} ORDER BY name")
            for row in cursor.fetchall():
                print(f"    {row[0]:<40} {row[1]}")
        except Exception as e:
            print(f"    Error: {e}")

    # Existing attacks
    print(f"\n  Existing attacks:")
    try:
        cursor.execute("SELECT id, name, severity, attack_type FROM attacks ORDER BY name")
        for row in cursor.fetchall():
            print(f"    [{row[2]:>8}] [{row[3]:>10}] {row[1]}")
    except Exception as e:
        print(f"    Error: {e}")

    # Check if scanner already exists
    try:
        cursor.execute("SELECT id FROM attacks WHERE name = ?", (ATTACK_METADATA["name"],))
        if cursor.fetchone():
            print(f"\n  ⚠  Scanner already exists in database!")
    except:
        pass

    conn.close()
    print(f"\n  All tables: {get_tables(db_path)}")


def create_client_subcategory(db_path):
    """Create Client-Side category and Vulnerability Scanning subcategory if they don't exist."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cat_table = find_cat_table(db_path)
    subcat_table = find_subcat_table(db_path)
    now = datetime.utcnow().isoformat()

    if not cat_table or not subcat_table:
        print(f"  [!] Could not find category/subcategory tables. Create manually.")
        conn.close()
        return None

    # Check if "Client-Side" category exists
    cursor.execute(f"SELECT id FROM {cat_table} WHERE name LIKE '%client%'")
    cat_row = cursor.fetchone()

    if cat_row:
        cat_id = cat_row[0]
        print(f"  [*] Found existing Client-Side category: {cat_id}")
    else:
        cat_id = str(uuid.uuid4())
        try:
            cursor.execute(f"""
                INSERT INTO {cat_table} (id, name, description, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                cat_id,
                "Client-Side",
                "Attacks and scanners targeting MCP client applications (IDEs, CLI tools, desktop apps)",
                1, now, now
            ))
            print(f"  [+] Created category: Client-Side ({cat_id})")
        except Exception as e:
            print(f"  [!] Failed to create category: {e}")
            print(f"      You may need to create it manually in the AEGIS admin UI.")
            conn.close()
            return None

    # Check if "Vulnerability Scanning" subcategory exists under this category
    cursor.execute(
        f"SELECT id FROM {subcat_table} WHERE name LIKE '%vuln%scan%' OR name LIKE '%reconnaissance%'"
    )
    subcat_row = cursor.fetchone()

    if subcat_row:
        subcat_id = subcat_row[0]
        print(f"  [*] Found existing subcategory: {subcat_id}")
    else:
        subcat_id = str(uuid.uuid4())
        try:
            cursor.execute(f"""
                INSERT INTO {subcat_table} (id, name, description, category_id, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                subcat_id,
                "Vulnerability Scanning",
                "Client-side fingerprinting, version detection, and CVE correlation for MCP clients",
                cat_id,
                1, now, now
            ))
            print(f"  [+] Created subcategory: Vulnerability Scanning ({subcat_id})")
        except Exception as e:
            print(f"  [!] Failed to create subcategory: {e}")
            print(f"      Create manually, then run: python seed_client_scanner.py --subcategory YOUR_ID")
            conn.close()
            return None

    conn.commit()
    conn.close()
    return subcat_id


# ═══════════════════════════════════════════════════════════════════════════
# FILE DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════

def deploy_yaml(db_path):
    """Copy cve_database.yaml to AEGIS data directory."""
    if not os.path.exists(CVE_DB_YAML):
        print(f"  [!] cve_database.yaml not found at {CVE_DB_YAML}")
        return None

    # Find AEGIS root relative to database
    db_dir = os.path.dirname(os.path.abspath(db_path))
    backend_dir = db_dir

    # Walk up to find "backend" directory
    for _ in range(4):
        if os.path.basename(backend_dir) == "backend":
            break
        if os.path.exists(os.path.join(backend_dir, "backend")):
            backend_dir = os.path.join(backend_dir, "backend")
            break
        parent = os.path.dirname(backend_dir)
        if parent == backend_dir:
            break
        backend_dir = parent

    # Create data directory
    data_dir = os.path.join(backend_dir, "data", "client_scanner")
    os.makedirs(data_dir, exist_ok=True)

    # Copy YAML
    dest = os.path.join(data_dir, "cve_database.yaml")
    shutil.copy2(CVE_DB_YAML, dest)
    print(f"  [+] Deployed cve_database.yaml → {dest}")

    # Also copy test harness if present
    if os.path.exists(TEST_HARNESS):
        shutil.copy2(TEST_HARNESS, os.path.join(data_dir, "test_harness.py"))
        print(f"  [+] Deployed test_harness.py → {data_dir}/")

    return data_dir


def load_scanner_script(data_dir):
    """Load scanner script and patch it to find cve_database.yaml in AEGIS paths."""
    if not os.path.exists(SCANNER_PY):
        print(f"  [!] client_vuln_scanner.py not found at {SCANNER_PY}")
        return None

    with open(SCANNER_PY, "r") as f:
        script = f.read()

    # Add AEGIS-specific search paths to the _find_db function
    # This patch adds the AEGIS data directory to the search candidates
    aegis_paths_code = '''
    # AEGIS framework paths (added by seed script)
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "client_scanner", "cve_database.yaml"))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "client_scanner", "cve_database.yaml"))
    candidates.append("/home/kali/Desktop/minerva/backend/data/client_scanner/cve_database.yaml")
'''

    # Find the insertion point in _find_db function
    marker = '    candidates.append(os.path.join(os.getcwd(), "cve_database.yaml"))'
    if marker in script:
        script = script.replace(
            marker,
            marker + "\n" + aegis_paths_code
        )
        print(f"  [+] Patched scanner with AEGIS data paths")
    else:
        print(f"  [*] Scanner already patched or marker not found — adding paths at import")
        # Fallback: add paths after the imports
        script = script.replace(
            "import requests",
            "import requests\n\n# AEGIS data paths\n"
            "_AEGIS_DATA_PATHS = [\n"
            '    "/home/kali/Desktop/minerva/backend/data/client_scanner/cve_database.yaml",\n'
            "]\n"
        )

    return script


# ═══════════════════════════════════════════════════════════════════════════
# DATABASE INSERT
# ═══════════════════════════════════════════════════════════════════════════

def seed_attack(db_path, subcategory_id, script_content):
    """Insert the scanner attack into the AEGIS database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()

    # Check if already exists
    cursor.execute("SELECT id FROM attacks WHERE name = ?", (ATTACK_METADATA["name"],))
    existing = cursor.fetchone()
    if existing:
        print(f"\n  [!] Attack already exists (ID: {existing[0]})")
        response = input("  [?] Update it? (y/n): ").strip().lower()
        if response == "y":
            cursor.execute("""
                UPDATE attacks SET
                    description = ?, script_content = ?, config_schema = ?,
                    default_config = ?, prerequisites = ?, remediation = ?,
                    tags = ?, updated_at = ?
                WHERE id = ?
            """, (
                ATTACK_METADATA["description"],
                script_content,
                json.dumps(ATTACK_METADATA["config_schema"]),
                json.dumps(ATTACK_METADATA["default_config"]),
                ATTACK_METADATA["prerequisites"],
                ATTACK_METADATA["remediation"],
                json.dumps(ATTACK_METADATA["tags"]),
                now,
                existing[0],
            ))
            conn.commit()
            conn.close()
            print(f"  [+] Updated attack: {existing[0]}")
            return existing[0]
        else:
            conn.close()
            print("  [*] Skipped.")
            return None

    attack_id = str(uuid.uuid4())

    cursor.execute("""
        INSERT INTO attacks (
            id, name, description, subcategory_id, severity, attack_type,
            script_language, script_content, config_schema, default_config,
            prerequisites, remediation, tags, is_verified, is_active,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        attack_id,
        ATTACK_METADATA["name"],
        ATTACK_METADATA["description"],
        subcategory_id,
        ATTACK_METADATA["severity"],
        ATTACK_METADATA["attack_type"],
        ATTACK_METADATA["script_language"],
        script_content,
        json.dumps(ATTACK_METADATA["config_schema"]),
        json.dumps(ATTACK_METADATA["default_config"]),
        ATTACK_METADATA["prerequisites"],
        ATTACK_METADATA["remediation"],
        json.dumps(ATTACK_METADATA["tags"]),
        1,  # is_verified
        1,  # is_active
        now,
        now,
    ))

    conn.commit()
    conn.close()

    print(f"  [+] Attack inserted into database!")
    print(f"      ID:   {attack_id}")
    print(f"      Name: {ATTACK_METADATA['name']}")
    return attack_id


# ═══════════════════════════════════════════════════════════════════════════
# EXECUTION ENGINE PATCH REMINDER
# ═══════════════════════════════════════════════════════════════════════════

def print_engine_patch_reminder():
    """Remind about the exec_globals patch needed for the scanner to work."""
    print("""
  ┌────────────────────────────────────────────────────────────────┐
  │ IMPORTANT: Execution Engine Patch                              │
  │                                                                │
  │ The scanner needs these modules available at runtime.          │
  │ Make sure your AEGIS execution engine's exec_globals includes: │
  │                                                                │
  │   exec_globals = {                                             │
  │       "requests": requests,                                    │
  │       "yaml": yaml,          # pip install pyyaml              │
  │       "subprocess": subprocess,                                │
  │       "platform": platform,                                    │
  │       "socket": socket,                                        │
  │       "hashlib": hashlib,                                      │
  │       "datetime": datetime,                                    │
  │       "re": re,                                                │
  │       "json": json,                                            │
  │       "os": os,                                                │
  │   }                                                            │
  │                                                                │
  │ If your engine already allows these imports (most do), you're  │
  │ fine. If attacks fail silently, this is usually why.           │
  └────────────────────────────────────────────────────────────────┘
""")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Seed MCP Client Vulnerability Scanner into AEGIS"
    )
    parser.add_argument("--db", help="Path to aegis.db")
    parser.add_argument("--list", action="store_true", help="List categories and existing attacks")
    parser.add_argument("--auto", action="store_true", help="Auto-create Client-Side category + subcategory")
    parser.add_argument("--subcategory", help="Existing subcategory ID to use")

    args = parser.parse_args()

    # Find database
    db_path = find_db(args.db)
    if not db_path:
        print("\n  [!] AEGIS database not found.")
        print("      Use --db /path/to/aegis.db")
        print("      Common locations:")
        for c in DB_CANDIDATES:
            print(f"        {c}")
        sys.exit(1)

    print(f"\n  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║  AEGIS Seeder: Client Vulnerability Scanner         ║")
    print(f"  ╚══════════════════════════════════════════════════════╝")
    print(f"  Database: {db_path}")

    # Check source files exist
    for f, desc in [(SCANNER_PY, "Scanner script"), (CVE_DB_YAML, "CVE database")]:
        if not os.path.exists(f):
            print(f"\n  [!] {desc} not found: {f}")
            print(f"      Make sure this seed script is in the same directory as the scanner files.")
            sys.exit(1)

    if args.list:
        list_all(db_path)
        print(f"\n  Next steps:")
        print(f"    python seed_client_scanner.py --db {db_path} --auto")
        print(f"    python seed_client_scanner.py --db {db_path} --subcategory ID")
        sys.exit(0)

    # Determine subcategory
    subcat_id = args.subcategory
    if args.auto:
        subcat_id = create_client_subcategory(db_path)
        if not subcat_id:
            sys.exit(1)
    elif not subcat_id:
        print("\n  [!] Need a subcategory. Options:")
        print(f"      --auto                  (creates Client-Side → Vulnerability Scanning)")
        print(f"      --subcategory ID        (use existing subcategory)")
        print(f"      --list                  (see what's available)")
        sys.exit(1)

    # Deploy YAML to AEGIS data directory
    data_dir = deploy_yaml(db_path)

    # Load and patch scanner script
    script_content = load_scanner_script(data_dir)
    if not script_content:
        sys.exit(1)

    # Insert into database
    attack_id = seed_attack(db_path, subcat_id, script_content)

    if attack_id:
        print_engine_patch_reminder()
        print(f"  ╔══════════════════════════════════════════════════════╗")
        print(f"  ║  Done! Restart your Flask backend.                  ║")
        print(f"  ║                                                     ║")
        print(f"  ║  To test:                                           ║")
        print(f"  ║  1. Start AEGIS (Flask + React)                     ║")
        print(f"  ║  2. Go to Attacks → Client-Side → Vuln Scanning     ║")
        print(f"  ║  3. Select 'MCP Client Vulnerability Scanner'       ║")
        print(f"  ║  4. Set target to localhost:8080 and run             ║")
        print(f"  ║                                                     ║")
        print(f"  ║  For a full demo with test harness:                 ║")
        print(f"  ║  cd {data_dir or 'backend/data/client_scanner'}")
        print(f"  ║  python test_harness.py demo                        ║")
        print(f"  ╚══════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
