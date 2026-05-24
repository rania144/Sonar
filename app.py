from flask import Flask, jsonify
import psycopg2

app = Flask(__name__)


# 🔗 Connexion PostgreSQL
conn = psycopg2.connect(
    host="localhost",
    database="cyberwatch",
    user="cyberuser",
    password="cyberpass"
)


# 🏠 Route accueil
@app.route('/')
def home():
    return jsonify({
        "message": "Cyber Watch API running"
    })


# 📊 Toutes les vulnérabilités
@app.route('/vulnerabilities')
def vulnerabilities():

    cur = conn.cursor()

    cur.execute("""
        SELECT cve_id, score, level, description
        FROM vulnerabilities
        ORDER BY created_at DESC
        LIMIT 50
    """)

    rows = cur.fetchall()

    results = []

    for row in rows:
        results.append({
            "cve": row[0],
            "score": row[1],
            "level": row[2],
            "description": row[3]
        })

    cur.close()

    return jsonify(results)


# 🚨 Vulnérabilités critiques
@app.route('/critical')
def critical():

    cur = conn.cursor()

    cur.execute("""
        SELECT cve_id, score, description
        FROM vulnerabilities
        WHERE level='CRITICAL'
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()

    results = []

    for row in rows:
        results.append({
            "cve": row[0],
            "score": row[1],
            "description": row[2]
        })

    cur.close()

    return jsonify(results)


# ▶ lancement serveur
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
