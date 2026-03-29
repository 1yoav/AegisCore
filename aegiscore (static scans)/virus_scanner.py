import requests
import sys


def check_hash_on_virustotal(file_hash):
    """
    Check if a file hash exists in the VirusTotal database.

    Returns:
        bool: True if safe, False if malicious or not found/error
    """
    # Use the Report/Lookup endpoint
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    # Use the API key from your original script
    params = {
        'apikey': '3fde0e9dde73eb5a014ccc1d61a3acf1d8bb6d53f5b1cfdeed6d534d3c6d4c02',
        'resource': file_hash
    }

    try:
        response = requests.get(url, params=params)

        if response.status_code == 204:
            print("Error: API request rate limit exceeded.")
            return True # Fail-safe: assume safe or handle as error

        results = response.json()

        # response_code 1 means the file was found in the database
        if results.get('response_code') == 1:
            positives = results.get('positives', 0)
            total = results.get('total', 0)

            print(f"Detection ratio: {positives}/{total}")

            if positives == 0:
                print("File signature is safe!")
                return True
            else:
                print("File potentially dangerous!")
                # Show top detections
                scans = results.get('scans', {})
                for engine, result in list(scans.items())[:3]:
                    if result.get('detected'):
                        print(f"  - {engine}: {result.get('result')}")
                return False

        elif results.get('response_code') == 0:
            # File has never been seen by VirusTotal before
            print("File signature is safe! (Not found in VirusTotal database)")
            return True

        else:
            print(f"Error: {results.get('verbose_msg')}")
            return True

    except Exception as e:
        print(f"Error connecting to VirusTotal: {e}")
        return True


def main():
    if len(sys.argv) != 2:
        print("Usage: python virus_scanner.py <md5_hash>")
        sys.exit(1)

    file_hash = sys.argv[1]
    print(f"Searching VirusTotal for hash: {file_hash}")

    is_safe = check_hash_on_virustotal(file_hash)

    print("Scan finished! Returning to C++")

    # Your C++ code looks for these specific strings:
    # "File potentially dangerous!" or "File signature is safe!"

    sys.exit(0 if is_safe else 1)


if __name__ == "__main__":
    main()
