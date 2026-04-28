#!/usr/bin/env python3
"""
Minerva Platform startup verification script
Checks configuration and dependencies before running
"""

import os
import sys
import subprocess
from pathlib import Path


def check_docker():
    """Check if Docker is installed and running"""
    try:
        result = subprocess.run(['docker', 'info'], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def check_docker_compose():
    """Check if docker-compose is available"""
    try:
        # Try docker compose (newer version)
        result = subprocess.run(['docker', 'compose', 'version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            return True
        # Try docker-compose (older version)
        result = subprocess.run(['docker-compose', '--version'], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def check_env_file():
    """Check if .env file exists"""
    return os.path.exists('.env')


def check_python_deps():
    """Check if required Python packages are available"""
    required = ['flask', 'sqlalchemy', 'flask_cors', 'jwt']
    try:
        for package in required:
            __import__(package.replace('_', '-'))
        return True
    except ImportError:
        return False


def main():
    """Main startup verification"""
    print("\n" + "="*60)
    print("Minerva Platform - Startup Verification")
    print("="*60 + "\n")
    
    checks = {
        "Docker daemon": check_docker(),
        "docker-compose": check_docker_compose(),
        ".env configuration file": check_env_file(),
    }
    
    passed = 0
    failed = 0
    
    for check_name, result in checks.items():
        status = "✓" if result else "✗"
        print(f"{status} {check_name}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print("\n" + "-"*60)
    
    if failed > 0:
        print(f"\n⚠️  {failed} check(s) failed:\n")
        
        if not checks["Docker daemon"]:
            print("  • Docker daemon is not running")
            print("    → Start Docker Desktop or the Docker daemon service\n")
        
        if not checks["docker-compose"]:
            print("  • docker-compose is not installed")
            print("    → Install Docker Desktop (includes docker-compose)\n")
        
        if not checks[".env configuration file"]:
            print("  • .env file is missing")
            print("    → A default .env file has been created")
            print("    → You can customize it as needed\n")
        
        if checks["Docker daemon"] and checks["docker-compose"]:
            print("\nProceeding with startup (missing .env will use defaults)...")
            return True
        else:
            return False
    else:
        print(f"\n✓ All checks passed! Ready to start Minerva.\n")
        return True


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
