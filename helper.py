import os

# הגדרות - אילו תיקיות להזניח (כדי שלא תקבל זבל)
IGNORE_DIRS = {'venv', '.git', '__pycache__', '.vs', 'x64', 'Debug'}
# אילו סיומות קבצים לחפש (כדי שלא יסרוק קבצי EXE או DLL)
ALLOWED_EXTENSIONS = {'.py', '.cpp', '.h', '.txt', '.bat', '.c'}

def search_in_files():
    search_term = input("[?] Enter string to search: ").strip()
    if not search_term:
        return

    print(f"[*] Searching for '{search_term}'...")
    print("-" * 50)

    found_count = 0
    # מעבר על כל התיקיות מהמיקום הנוכחי
    for root, dirs, files in os.walk('.'):
        # סינון תיקיות לא רלוונטיות
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            if any(file.endswith(ext) for ext in ALLOWED_EXTENSIONS):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        if search_term in f.read():
                            print(f"[+] Found in: {file_path}")
                            found_count += 1
                except Exception:
                    continue

    print("-" * 50)
    print(f"[*] Finished. Found in {found_count} files.")
    input("\nPress Enter to exit...") # השהיה בסוף

if __name__ == "__main__":
    search_in_files()
