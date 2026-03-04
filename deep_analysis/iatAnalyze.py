import pefile
from pathlib import Path


def analyze(path):
    if Path(path).is_file():

        # check if its executable
        with open(path, 'rb') as f:
            magic = f.read(2)
            if magic != b'MZ':
                return 0

        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        # for entry in pe.DIRECTORY_ENTRY_IMPORT:
        #     for func in entry.imports:
                # make any search
    else:
        print("iat reporting " + path + " not exsist in the system")
    return 0 # to do: cimmunicate with isolationForest

