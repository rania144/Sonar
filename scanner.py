import nmap
import psycopg2

# -----------------------------
# CONFIG POSTGRESQL
# -----------------------------
conn = psycopg2.connect(
    host="localhost",
    database="cyberwatch",
    user="cyberuser",
    password="cyberpass",
    port=5432
)

cur = conn.cursor()

# -----------------------------
# INIT NMAP SCANNER
# -----------------------------
nm = nmap.PortScanner()

target = "192.168.10.0/24"

print("[*] Starting Nmap scan...")

nm.scan(hosts=target, arguments="-sV")

# -----------------------------
# PARSE RESULTS
# -----------------------------
for host in nm.all_hosts():

    print("\nHOST:", host)

    for proto in nm[host].all_protocols():

        for port in nm[host][proto]:

            service = nm[host][proto][port]

            ip = host
            port_num = port
            state = service.get("state")
            service_name = service.get("name")
            product = service.get("product")
            version = service.get("version")

            print(f"[+] {ip}:{port_num} {service_name} {product} {version}")

            # -----------------------------
            # INSERT INTO POSTGRESQL
            # -----------------------------
            cur.execute("""
                INSERT INTO assets (ip, port, service, product, version, state)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                ip,
                port_num,
                service_name,
                product,
                version,
                state
            ))

# -----------------------------
# SAVE & CLOSE
# -----------------------------
conn.commit()
cur.close()
conn.close()

print("\n[✓] Scan terminé + données stockées dans PostgreSQL")
