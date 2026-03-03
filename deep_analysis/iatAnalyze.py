import pefile
from pathlib import Path


def analyze(path):
    if Path(path).is_file():
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print()
            print(entry.dll)
            for func in entry.imports:
                print(func)
                # make any search
    else:
        print("iat reporting " + path + " not exsist in the system")
    return 0 # to do: cimmunicate with isolationForest

