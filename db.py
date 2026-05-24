import psycopg2

def get_connection():
    return psycopg2.connect(
        dbname="cyberwatch",
        user="cyberuser",
        password="cyberpass",
        host="localhost",
        port="5432"
    )

def insert_vuln(cve_id, description, score, level):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO vulnerabilities (cve_id, description, score, level)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (cve_id) DO NOTHING
    """, (cve_id, description, score, level))

    conn.commit()
    cur.close()
    conn.close()
