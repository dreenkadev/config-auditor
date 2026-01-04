#!/usr/bin/env python3
"""
Config Auditor - Security audit for configuration files

Features:
- Secret detection
- Permission checking
- Insecure settings
- Hardcoded credentials
- Multiple config formats
"""

import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# Secret patterns
SECRET_PATTERNS = [
    (r'password\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', 'Password'),
    (r'secret\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', 'Secret'),
    (r'api[_-]?key\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', 'API Key'),
    (r'token\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', 'Token'),
    (r'private[_-]?key\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', 'Private Key'),
    (r'aws[_-]?access[_-]?key\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', 'AWS Key'),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private Key Block'),
    (r'mysql://[^:]+:([^@]+)@', 'MySQL Password'),
    (r'postgres://[^:]+:([^@]+)@', 'PostgreSQL Password'),
    (r'mongodb://[^:]+:([^@]+)@', 'MongoDB Password'),
]

# Insecure settings
INSECURE_SETTINGS = [
    (r'debug\s*[=:]\s*["\']?(true|1|yes|on)["\']?', 'Debug mode enabled'),
    (r'ssl[_-]?verify\s*[=:]\s*["\']?(false|0|no|off)["\']?', 'SSL verification disabled'),
    (r'allow[_-]?origin\s*[=:]\s*["\']?\*["\']?', 'CORS allows all origins'),
    (r'root[_-]?password\s*[=:]\s*["\']?["\']?', 'Empty root password'),
    (r'bind[_-]?address\s*[=:]\s*["\']?0\.0\.0\.0["\']?', 'Binding to all interfaces'),
    (r'secure\s*[=:]\s*["\']?(false|0|no|off)["\']?', 'Secure mode disabled'),
    (r'auth[_-]?disabled\s*[=:]\s*["\']?(true|1|yes|on)["\']?', 'Auth disabled'),
]

# Common config files
CONFIG_PATTERNS = [
    '*.conf', '*.cfg', '*.ini', '*.env', '*.yaml', '*.yml',
    '*.json', '*.toml', '*.properties', '.env*',
    'config.*', 'settings.*', 'application.*'
]


@dataclass
class Finding:
    severity: str
    category: str
    file: str
    line: int
    title: str
    value: str


class ConfigAuditor:
    def __init__(self):
        self.findings: List[Finding] = []
        
    def audit_file(self, filepath: str) -> List[Finding]:
        """Audit a single file"""
        findings = []
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            # Check permissions
            file_perms = self.check_permissions(filepath)
            if file_perms:
                findings.append(file_perms)
            
            for i, line in enumerate(lines, 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue
                
                # Check for secrets
                for pattern, secret_type in SECRET_PATTERNS:
                    match = re.search(pattern, line, re.I)
                    if match:
                        value = match.group(1) if match.lastindex else 'detected'
                        # Skip obvious placeholders
                        if value.lower() in ['password', 'secret', 'key', 'token', 
                                             'xxx', 'changeme', 'example']:
                            continue
                        findings.append(Finding(
                            severity='critical',
                            category='secret',
                            file=filepath,
                            line=i,
                            title=f'Hardcoded {secret_type}',
                            value=self.mask_value(value)
                        ))
                
                # Check for insecure settings
                for pattern, description in INSECURE_SETTINGS:
                    if re.search(pattern, line, re.I):
                        findings.append(Finding(
                            severity='high',
                            category='insecure',
                            file=filepath,
                            line=i,
                            title=description,
                            value=stripped[:80]
                        ))
            
        except Exception as e:
            pass
        
        self.findings.extend(findings)
        return findings
    
    def check_permissions(self, filepath: str) -> Optional[Finding]:
        """Check file permissions"""
        try:
            stat = os.stat(filepath)
            mode = stat.st_mode
            
            # Check if world-readable
            if mode & 0o004:
                perms = oct(mode)[-3:]
                if any(keyword in filepath.lower() for keyword in 
                       ['password', 'secret', 'key', 'credential', '.env']):
                    return Finding(
                        severity='high',
                        category='permission',
                        file=filepath,
                        line=0,
                        title='Sensitive file is world-readable',
                        value=f'Permissions: {perms}'
                    )
        except:
            pass
        return None
    
    def mask_value(self, value: str) -> str:
        """Mask sensitive values"""
        if len(value) < 4:
            return '***'
        return value[:2] + '*' * (len(value) - 4) + value[-2:]
    
    def audit_directory(self, directory: str, recursive: bool = True):
        """Audit all config files in directory"""
        path = Path(directory)
        
        for pattern in CONFIG_PATTERNS:
            if recursive:
                files = path.rglob(pattern)
            else:
                files = path.glob(pattern)
            
            for filepath in files:
                if filepath.is_file():
                    self.audit_file(str(filepath))
    
    def get_summary(self) -> Dict:
        """Get audit summary"""
        by_severity = {}
        by_category = {}
        
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
        
        return {
            'total': len(self.findings),
            'by_severity': by_severity,
            'by_category': by_category
        }


def print_banner():
    print(f"""{Colors.CYAN}
   ____             __ _          _             _ _ _             
  / ___|___  _ __  / _(_) __ _   / \\  _   _  __| (_) |_ ___  _ __ 
 | |   / _ \\| '_ \\| |_| |/ _` | / _ \\| | | |/ _` | | __/ _ \\| '__|
 | |__| (_) | | | |  _| | (_| |/ ___ \\ |_| | (_| | | || (_) | |   
  \\____\\___/|_| |_|_| |_|\\__, /_/   \\_\\__,_|\\__,_|_|\\__\\___/|_|   
                         |___/                                    
{Colors.RESET}                                                v{VERSION}
""")


def print_findings(findings: List[Finding]):
    """Print findings"""
    if not findings:
        print(f"\n{Colors.GREEN}[OK] No issues found!{Colors.RESET}")
        return
    
    print(f"\n{Colors.BOLD}Findings ({len(findings)}):{Colors.RESET}\n")
    
    for f in findings:
        color = Colors.RED if f.severity in ['critical', 'high'] else Colors.YELLOW
        
        print(f"  {color}[{f.severity.upper()}]{Colors.RESET} {f.title}")
        print(f"    File: {f.file}:{f.line}")
        print(f"    {Colors.DIM}{f.value}{Colors.RESET}\n")


def demo_mode():
    """Run demo"""
    print(f"{Colors.CYAN}Running demo...{Colors.RESET}\n")
    
    demo_findings = [
        Finding('critical', 'secret', '/app/config.yml', 15, 
                'Hardcoded Password', 'db**********ss'),
        Finding('critical', 'secret', '/app/.env', 3,
                'Hardcoded API Key', 'sk**********e4'),
        Finding('high', 'insecure', '/app/config.yml', 22,
                'Debug mode enabled', 'debug: true'),
        Finding('high', 'insecure', '/app/nginx.conf', 45,
                'SSL verification disabled', 'ssl_verify: false'),
        Finding('high', 'permission', '/app/.env', 0,
                'Sensitive file is world-readable', 'Permissions: 644'),
    ]
    
    print_findings(demo_findings)
    
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Total: 5")
    print(f"  Critical: 2")
    print(f"  High: 3")


def main():
    parser = argparse.ArgumentParser(description="Config Auditor")
    parser.add_argument("path", nargs="?", help="File or directory to audit")
    parser.add_argument("-r", "--recursive", action="store_true", default=True,
                        help="Recursive search")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if not args.path:
        print(f"{Colors.YELLOW}No path specified. Use --demo for demonstration.{Colors.RESET}")
        return
    
    auditor = ConfigAuditor()
    
    if os.path.isfile(args.path):
        auditor.audit_file(args.path)
    else:
        auditor.audit_directory(args.path, recursive=args.recursive)
    
    print_findings(auditor.findings)
    
    summary = auditor.get_summary()
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Total: {summary['total']}")
    for sev, count in summary['by_severity'].items():
        print(f"  {sev.capitalize()}: {count}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'findings': [asdict(f) for f in auditor.findings],
                'summary': summary
            }, f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
