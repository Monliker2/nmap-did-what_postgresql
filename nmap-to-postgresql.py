import xml.etree.ElementTree as ET
import psycopg2
from psycopg2 import sql
from datetime import datetime, timezone
import argparse

def parse_nmap_xml(xml_file):
    import xml.etree.ElementTree as ET
    from datetime import datetime, timezone

    tree = ET.parse(xml_file)
    root = tree.getroot()

    nmap_version = root.get('version', '')
    command_line = root.get('args', '')

    # scan-level timestamp as datetime in UTC
    scan_start = root.get('start')
    if scan_start:
        scan_start_dt = datetime.fromtimestamp(int(scan_start), tz=timezone.utc)
    else:
        scan_start_dt = None

    elapsed_time = ''
    elapsed_elem = root.find('runstats/finished')
    if elapsed_elem is not None:
        elapsed_time = elapsed_elem.get('elapsed')

    total_hosts = 0
    total_open_ports = 0
    hosts = []

    for host in root.findall('host'):
        total_hosts += 1
        ip = host.find('address').get('addr', '')
        hostname = host.find('hostnames/hostname').get('name', '') if host.findall('hostnames/hostname') else ''

        os = 'Unknown'
        os_el = host.find('os/osmatch')
        if os_el is not None:
            os = os_el.get('name', 'Unknown')

        # initialize counts
        ports_open = 0
        ports_closed = 0
        ports_filtered = 0
        ports = []

        ports_section = host.find('ports')
        if ports_section is not None:
            # summary counts from <extraports>
            for extra in ports_section.findall('extraports'):
                state = extra.get('state')
                count = int(extra.get('count', '0'))
                if state == 'closed':
                    ports_closed = count
                elif state == 'filtered':
                    ports_filtered = count

            # explicit port entries (usually open, sometimes filtered)
            for p in ports_section.findall('port'):
                state = p.find('state').get('state')
                if state == 'open':
                    ports_open += 1
                    total_open_ports += 1
                elif state == 'filtered':
                    ports_filtered += 1

                service = p.find('service')
                svc_name = service.get('name') if service is not None else None
                prod = service.get('product') or ''
                ver = service.get('version') or ''
                svc_info = f"{prod} {ver}".strip()

                http_title = ssl_cn = ssl_issuer = None
                for script in p.findall('script'):
                    sid = script.get('id')
                    if sid == 'http-title':
                        http_title = script.get('output')
                    elif sid == 'ssl-cert':
                        for tbl in script.findall('table'):
                            if tbl.get('key') == 'subject':
                                cn = tbl.find("elem[@key='commonName']")
                                ssl_cn = cn.text if cn is not None else None
                            elif tbl.get('key') == 'issuer':
                                elems = {e.get('key'): e.text for e in tbl.findall('elem')}
                                ssl_issuer = f"{elems.get('commonName','')} {elems.get('organizationName','')}".strip()

                # fallback OS from service ostype
                if service is not None and os == 'Unknown':
                    os = service.get('ostype', os)

                ports.append({
                    'port': p.get('portid'),
                    'protocol': p.get('protocol'),
                    'state': state,
                    'service_name': svc_name,
                    'service_info': svc_info,
                    'http_title': http_title,
                    'ssl_common_name': ssl_cn,
                    'ssl_issuer': ssl_issuer
                })

        # total tested = open + closed(summary) + filtered(summary + explicit)
        ports_tested = ports_open + ports_closed + ports_filtered

        hosts.append({
            'ip':             ip,
            'hostname':       hostname,
            'os':             os,
            'ports_tested':   ports_tested,
            'ports_open':     ports_open,
            'ports_closed':   ports_closed,
            'ports_filtered': ports_filtered,
            'time':           scan_start_dt,
            'ports':          ports
        })

    scan = {
        'nmap_version':    nmap_version,
        'command_line':    command_line,
        'start_time':      scan_start_dt,
        'elapsed_time':    elapsed_time,
        'total_hosts':     total_hosts,
        'total_open_ports': total_open_ports
    }

    return scan, hosts


def create_database(conn):
    with conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                nmap_version TEXT,
                command_line TEXT,
                start_time TIMESTAMPTZ,
                elapsed_time TEXT,
                total_hosts INTEGER,
                total_open_ports INTEGER
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                ip TEXT,
                hostname TEXT,
                os TEXT,
                ports_tested INTEGER,
                ports_open INTEGER,
                ports_closed INTEGER,
                ports_filtered INTEGER,
                time TIMESTAMPTZ
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                host_id INTEGER REFERENCES hosts(id),
                port TEXT,
                protocol TEXT,
                state TEXT,
                service_name TEXT,
                service_info TEXT,
                http_title TEXT,
                ssl_common_name TEXT,
                ssl_issuer TEXT
            );
        ''')
        conn.commit()


def insert_data(conn, scan, hosts):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scans (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_open_ports)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """,
            (
                scan['nmap_version'],
                scan['command_line'],
                scan['start_time'],
                scan['elapsed_time'],
                scan['total_hosts'],
                scan['total_open_ports']
            )
        )
        scan_id = cur.fetchone()[0]

        for h in hosts:
            cur.execute(
                """
                INSERT INTO hosts (scan_id, ip, hostname, os, ports_tested, ports_open, ports_closed, ports_filtered, time)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
                """,
                (
                    scan_id,
                    h['ip'],
                    h['hostname'],
                    h['os'],
                    h['ports_tested'],
                    h['ports_open'],
                    h['ports_closed'],
                    h['ports_filtered'],
                    h['time']
                )
            )
            host_id = cur.fetchone()[0]

            for p in h['ports']:
                cur.execute(
                    """
                    INSERT INTO ports (scan_id, host_id, port, protocol, state, service_name, service_info, http_title, ssl_common_name, ssl_issuer)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_id,
                        host_id,
                        p['port'],
                        p['protocol'],
                        p['state'],
                        p['service_name'],
                        p['service_info'],
                        p['http_title'],
                        p['ssl_common_name'],
                        p['ssl_issuer']
                    )
                )
        conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Process nmap scan results.")
    parser.add_argument("xml_file", help="Path to the nmap output XML file")
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-port", default=5432, type=int)
    parser.add_argument("--db-name", default="nmapdb")
    parser.add_argument("--db-user", default="postgres")
    parser.add_argument("--db-password", default="")
    args = parser.parse_args()

    conn = psycopg2.connect(
        host=args.db_host,
        port=args.db_port,
        dbname=args.db_name,
        user=args.db_user,
        password=args.db_password
    )
    create_database(conn)
    scan, hosts = parse_nmap_xml(args.xml_file)
    insert_data(conn, scan, hosts)
    conn.close()

if __name__ == '__main__':
    main()
