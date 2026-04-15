#!/usr/bin/env python3
"""
AS2Org Parser Module

Parses CAIDA AS Organizations Dataset files to extract AS names based on ASN.

The as-org2info.txt file contains two types of entries:
1. Organization entries: org_id|changed|org_name|country|source
2. AS entries: aut|changed|aut_name|org_id|opaque_id|source

Usage:
    parser = AS2OrgParser(as_org_file='data/as-org2info.txt')
    as_name = parser.get_as_name(13335)  # -> "CLOUDFLARENET"
    org_info = parser.get_org_info('CLOUD-ARIN')  # -> {'name': 'Cloudflare, Inc.', ...}
"""

from pathlib import Path
from typing import Dict, Optional, Tuple


class AS2OrgParser:
    """Parser for CAIDA AS Organizations Dataset."""

    # Format markers in the file
    ORG_FORMAT_MARKER = "# format:org_id|changed|org_name|country|source"
    AS_FORMAT_MARKER = "# format:aut|changed|aut_name|org_id|opaque_id|source"

    def __init__(self, as_org_file: str = None):
        """
        Initialize AS2Org parser.

        Args:
            as_org_file: Path to as-org2info.txt file
        """
        self.as_org_file = Path(as_org_file) if as_org_file else None

        # Data storage
        self._as_to_name: Dict[int, str] = {}  # ASN -> AS name
        self._as_to_org_id: Dict[int, str] = {}  # ASN -> org_id
        self._org_info: Dict[str, Dict] = {}  # org_id -> org info

        # Parsing state
        self._parsed = False

        # Auto-load if file is provided
        if self.as_org_file and self.as_org_file.exists():
            self._parse_file()

    def _parse_file(self) -> None:
        """Parse the as-org2info.txt file."""
        if self._parsed:
            return

        if not self.as_org_file or not self.as_org_file.exists():
            raise FileNotFoundError(f"AS2Org file not found: {self.as_org_file}")

        current_section = None  # 'org' or 'as'

        with open(self.as_org_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines and comments (except format markers)
                if not line or (line.startswith('#') and not line.startswith('# format:')):
                    continue

                # Detect section by format marker
                if line == self.ORG_FORMAT_MARKER:
                    current_section = 'org'
                    continue
                elif line == self.AS_FORMAT_MARKER:
                    current_section = 'as'
                    continue

                # Skip if section not determined yet
                if current_section is None:
                    continue

                # Parse based on current section
                parts = line.split('|')
                if current_section == 'org':
                    self._parse_org_entry(parts)
                elif current_section == 'as':
                    self._parse_as_entry(parts)

        self._parsed = True

    def _parse_org_entry(self, parts: list) -> None:
        """
        Parse an organization entry.

        Format: org_id|changed|org_name|country|source
        """
        if len(parts) < 5:
            return

        org_id = parts[0]
        changed = parts[1]
        org_name = parts[2]
        country = parts[3]
        source = parts[4]

        self._org_info[org_id] = {
            'org_id': org_id,
            'changed': changed,
            'name': org_name,
            'country': country,
            'source': source
        }

    def _parse_as_entry(self, parts: list) -> None:
        """
        Parse an AS entry.

        Format: aut|changed|aut_name|org_id|opaque_id|source
        """
        if len(parts) < 6:
            return

        try:
            asn = int(parts[0])
        except ValueError:
            return

        changed = parts[1]
        as_name = parts[2]
        org_id = parts[3]
        opaque_id = parts[4]
        source = parts[5]

        self._as_to_name[asn] = as_name
        self._as_to_org_id[asn] = org_id

    def get_as_name(self, asn: int) -> Optional[str]:
        """
        Get AS name for a given ASN.

        Args:
            asn: Autonomous System Number

        Returns:
            AS name string or None if not found
        """
        if not self._parsed:
            self._parse_file()

        return self._as_to_name.get(asn)

    def get_org_info(self, org_id: str) -> Optional[Dict]:
        """
        Get organization information by org_id.

        Args:
            org_id: Organization ID

        Returns:
            Dict with organization info or None if not found
        """
        if not self._parsed:
            self._parse_file()

        return self._org_info.get(org_id)

    def get_org_id(self, asn: int) -> Optional[str]:
        """
        Get organization ID for a given ASN.

        Args:
            asn: Autonomous System Number

        Returns:
            Organization ID string or None if not found
        """
        if not self._parsed:
            self._parse_file()

        return self._as_to_org_id.get(asn)

    def get_as_info(self, asn: int) -> Optional[Dict]:
        """
        Get complete AS information including organization details.

        Args:
            asn: Autonomous System Number

        Returns:
            Dict with AS and organization info or None if not found
        """
        if not self._parsed:
            self._parse_file()

        if asn not in self._as_to_name:
            return None

        org_id = self._as_to_org_id.get(asn)
        org_info = self._org_info.get(org_id) if org_id else None

        return {
            'asn': asn,
            'as_name': self._as_to_name[asn],
            'org_id': org_id,
            'org_info': org_info
        }

    def get_all_asns(self) -> list:
        """
        Get all ASNs in the dataset.

        Returns:
            List of ASN integers
        """
        if not self._parsed:
            self._parse_file()

        return list(self._as_to_name.keys())

    def get_stats(self) -> Dict:
        """
        Get dataset statistics.

        Returns:
            Dict with statistics
        """
        if not self._parsed:
            self._parse_file()

        return {
            'total_asns': len(self._as_to_name),
            'total_orgs': len(self._org_info)
        }


# Convenience function for quick AS name lookup
def get_as_name(asn: int, as_org_file: str = 'data/as-org2info.txt') -> Optional[str]:
    """
    Quick AS name lookup function.

    Args:
        asn: Autonomous System Number
        as_org_file: Path to as-org2info.txt file

    Returns:
        AS name string or None if not found
    """
    parser = AS2OrgParser(as_org_file)
    return parser.get_as_name(asn)


# Convenience function for complete AS information lookup
def get_as_info(asn: int, as_org_file: str = 'data/as-org2info.txt') -> Optional[Dict]:
    """
    Quick AS information lookup function.

    Args:
        asn: Autonomous System Number
        as_org_file: Path to as-org2info.txt file

    Returns:
        Dict with AS and organization info or None if not found
    """
    parser = AS2OrgParser(as_org_file)
    return parser.get_as_info(asn)
