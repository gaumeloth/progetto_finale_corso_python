import xml.etree.ElementTree as ET
from typing import List, Dict


def parse_nmap_xml(xml_text: str) -> List[Dict[str, str]]:
    """
    Converte l'XML di output Nmap in una lista di host:
      [{'addr': '1.2.3.4', 'hostname': 'foo', 'state': 'up', 'ports': '22/tcp open ssh; ...'}, ...]
    """
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host in root.findall("host"):
        addr = host.find("address").get("addr") if host.find(
            "address") is not None else ""
        status = host.find("status").get("state") if host.find(
            "status") is not None else "unknown"
        hostname = host.find("./hostnames/hostname").get("name",
                                                         "") if host.find("./hostnames/hostname") is not None else ""

        ports_s = []
        for p in host.findall("./ports/port"):
            portid = p.get("portid")
            proto = p.get("protocol")
            state = p.find("state").get("state") if p.find(
                "state") is not None else ""
            service = p.find("service")
            sname = service.get("name") if service is not None else ""
            sversion = service.get("version") if (
                service is not None and service.get("version")) else ""
            ports_s.append(
                f"{portid}/{proto} {state} {sname} {sversion}".strip())

        hosts.append({
            "addr": addr,
            "hostname": hostname,
            "state": status,
            "ports": "; ".join(ports_s) if ports_s else ""
        })

    return hosts
