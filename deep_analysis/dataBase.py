import sqlite3
import sys, os
BASE_DIR = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__))
INSTALL_ROOT = os.path.normpath(os.path.join(BASE_DIR, '..', '..'))
DB_PATH = os.path.join(INSTALL_ROOT, 'deep_analysis', 'c2_threats.db')
print(DB_PATH)


def setup_database():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # 1. This deletes the old table and ALL its data
    cursor.execute('DROP TABLE IF EXISTS scan_results')

    # 2. This creates the fresh table with the correct columns
    cursor.execute('''
        CREATE TABLE scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            confidence INTEGER,
            pathname TEXT,
            date TEXT,
            findings TEXT
        )
    ''')

    connection.commit()
    connection.close()
    print("✅ Table overwritten and recreated successfully.")

def display_all_threats():
    # וודא שזה השם המדויק של הקובץ שבו ראית את המידע
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # אנחנו פונים לטבלה שראינו ב-Dump שלך
        cursor.execute('SELECT id, confidence, pathname, date, findings FROM scan_results')
        rows = cursor.fetchall()

        if not rows:
            print("Target table 'scan_results' is EMPTY.")
            return

        print(f"\n--- FOUND {len(rows)} ENTRIES IN SCAN_RESULTS ---")
        for row in rows:
            print(f"ID: {row[0]} | Conf: {row[1]}% | Path: {row[2]}")
            print(f"   Date: {row[3]}")
            print(f"   Findings: {row[4]}")
            print("-" * 50)

    except sqlite3.Error as e:
        print(f"SQL Error: {e}")
    finally:
        conn.close()


def insert_threat(confidence, pathname, findings, date):
    """
    מקבלת נתונים ומכניסה אותם לטבלה.
    כולל בדיקה שהקובץ והטבלה קיימים לפני הכתיבה.
    """
    # 1. בדיקה האם הקובץ בכלל קיים בנתיב שהגדרנו
    if not os.path.exists(DB_PATH):
        setup_database()

    connection = None
    try:
        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()



        # 3. ביצוע ההכנסה
        query = '''INSERT INTO scan_results (confidence, pathname, date, findings) 
                   VALUES (?, ?, ?, ?)'''

        cursor.execute(query, (confidence, pathname, date, findings))

        connection.commit()
        print(f"✅ Threat successfully inserted into DB.")
        return True

    except sqlite3.Error as e:
        print(f"❌ Database error during insert: {e}")
        return False

    finally:
        if connection:
            connection.close()

# שים לב לסדר הפרמטרים: confidence, pathname, findings, date


# 3. עכשיו מדפיסים - וזה יראה 2 שורות

