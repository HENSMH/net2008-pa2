# python pa2.py DEVICES.xml POLICY.yaml

# Name: Jenn Wu
# Algonquin Student Number: 041268011
# Carleton Student Number: 101382060

# check first:

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import yaml

# first audit error exception, means for 
class AuditError(Exception):
    """Custom exception expected audit input or configuration error"""
    pass


def version_parts(ver_str: str) -> List[int]:
    """parses version string into list integers"""
    if not ver_str:
        # retunr nothing then continue
        return []
    return [int(p) for p in str(ver_str).split(".")]


def compare_versions(ver1, ver2):
    """Compares two version strings part by part by raw number
        1 fr ver1 > ver2
       -1 for  ver1 < ver2
        0 for ver1 == ver2
    """
    a, b = version_parts(ver1), version_parts(ver2)
    size = max(len(a), len(b))
    # t he . becomes .0 OOO
    a += [0] * (size - len(a))   
    b += [0] * (size - len(b))
    return (a > b) - (a < b)


# step 1: XML device
# device class
class Device:
    """Network Devices belong here after to be put in the xml file"""
    def __init__ (
            self, 
                  device_id: str, 
                  role: str,
                  os_version: str,
                  owner: Optional[str] = None,
                  interfaces: Optional[List[Dict[str, str]]] = None
                  ):
        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        # MAYBE insert owner
        self.owner = owner = owner.strip() if owner and owner.strip() else None
        self.interfaces = interfaces if interfaces is not None else []

    def int_counting (self) -> Tuple [int, int, int]:
        """Counts ints interfaces and return int staus up, dowm, other"""
        up_int = 0
        down_int = 0
        other_int = 0
        for interface in self.interfaces:
            # this finds the current int status, without space and then storew value
            status = interface.get("status", "").lower() 
            if status == "up":
                up_int += 1
            elif status == "down":
                down_int += 1
            else: 
                other_int += 1
            # i can return multiple values when called to the function
        return up_int, down_int, other_int


    #Checking for violations, any type of variable can be used.
    def violation_check (self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Checking for violations"""

        violations = []

        # rule 1 unknown roles
        # find miniumium os version first
        os_min = policy.get("min_os")
        if os_min is not None:
            if self.role not in os_min:
                # this appends adds to dict list to the violations long dict list
                violations.append (
                    {
                        "device": self.device_id,
                        "type": "unknown_role",
                        "role": self.role
                    }
                )
            else:
                    # rule 2: punish outdated oses, for known roles
                    required_os = os_min[self.role]
                    if compare_versions(self.os_version, required_os) < 0:
                        violations.append(
                            {
                                "device": self.device_id,
                                "type": "os_outdated",
                                "found": self.os_version,
                                "required": required_os
                            }
                    )    
                        
        # rule 3: missing owner
        if policy.get("require_owner") is True and not self.owner:
            violations.append (
                {
                "device": self.device_id,
                "type": "missing_owner"
            }
                )

        # rule 4: too much down interface s
        max_down = policy.get("max_down_interfaces")
        if max_down is not None:
            _, down_count, _ = self.int_counting()
            if down_count > max_down:
                violations.append (
                    {
                        "device": self.device_id,
                        "type": "too_many_down",
                        "down": down_count
                    }
                )

        return violations



# step 1 final finally load into xml file
def load_inventory(filepath: Path) -> Tuple[Optional[str], List[Device], int]:
    """Loads xml inventory file"""

    if not filepath.exists() or not filepath.is_file():
        # audit error for step 3
        raise AuditError(f"Inventory file not found: {filepath}")

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

    except Exception as err:
        raise AuditError(f"Invalid XML in inventory file '{filepath}': {err}")

    if root.tag != "inventory":
        raise AuditError(f"Root element must be 'inventory' in file '{filepath}'")

    site = root.attrib.get("site")
    kept_devices: List[Device] = []
    skipped_count = 0

    for elem in root.findall("device"):
        dev_id = elem.attrib.get("id")
        if not dev_id or not dev_id.strip():
            skipped_count += 1
            continue

        role = elem.attrib.get("role", "")
        os_ver = elem.attrib.get("os", "")

        owner_elem = elem.find("owner")
        owner_text = owner_elem.text if owner_elem is not None else None

        interfaces = []
        for iface_elem in elem.findall("interface"):
            interfaces.append({
                "name": iface_elem.attrib.get("name", ""),
                "status": iface_elem.attrib.get("status", "")
            })

        device = Device(
            device_id=dev_id.strip(),
            role=role.strip(),
            os_version=os_ver.strip(),
            owner=owner_text,
            interfaces=interfaces
        )
        kept_devices.append(device)

    return site, kept_devices, skipped_count


def load_policy(filepath: Path) -> Dict[str, Any]:
    """Load then parse the yaml using safe load"""
    if not filepath.exists() or not filepath.is_file():
        raise AuditError(f"Policy file not found: {filepath}")

    try:
        with filepath.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as err:
        raise AuditError(f"Invalid YAML in policy file '{filepath}': {err}")

    if data is None:
        return {}
    
    if not isinstance(data, dict):
        raise AuditError(f"Policy file '{filepath}' must contain a YAML mapping/object.")

    return data


def run_audit(xml_path: Path, yaml_path: Path) -> Dict[str, Any]:
    """Execute full audit and dict of audiot"""
    site, devices, skipped_devices = load_inventory(xml_path)
    policy = load_policy(yaml_path)

    roles_summary: Dict[str, int] = {}
    total_up = 0
    total_down = 0
    total_other = 0

    all_violations: List[Dict[str, Any]] = []
    compliant_ids: List[str] = []

    for dev in devices:
        # counting roles
        roles_summary[dev.role] = roles_summary.get(dev.role, 0) + 1

        # coutning interfaces ints
        up, down, other = dev.int_counting()
        total_up += up
        total_down += down
        total_other += other

        # violations checking 
        dev_violations = dev.violation_check(policy)

        if dev_violations:
            all_violations.extend(dev_violations)

        else:
            compliant_ids.append(dev.device_id)

    
    compliant_ids.sort()

    audit_report = {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped_devices,
        "roles": roles_summary,
        "interfaces": {
            "up": total_up,
            "down": total_down,
            "other": total_other
        },
        "violations": all_violations,
        "compliant": compliant_ids
    }

    return audit_report



# main method :

def main() -> None:
    "Main method "
    if len(sys.argv) != 3:
        print("usage: python pa2.py <DEVICES.xml> <POLICY.yaml>", file=sys.stderr)
        sys.exit(2)

    xml_path = Path(sys.argv[1])
    yaml_path = Path(sys.argv[2])

    try:
        report_data = run_audit(xml_path, yaml_path)
        output_file = Path("audit.json")
        with output_file.open("w", encoding="utf-8") as f:

            # finally dump the .json 
            # indent 2 writes 2 line by 2 line
            json.dump(report_data, f, indent=2)

        print("Audit complete.")
        print(f"Total Devices: {report_data['total_devices']} | "
              f"Compliant: {len(report_data['compliant'])} | "
              f"Violations: {len(report_data['violations'])}")

        # assuming everything is correct and works
        sys.exit(0)

# audit fails, then causes to exit error
    except AuditError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()