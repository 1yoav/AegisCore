import pefile


def analyze(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print()
        print(entry.dll)
        for func in entry.imports:
            print(func.name)

    # to do:
#     start an analyze about the imported functions

analyze("C:\\Users\\Cyber_User\\Downloads\\PEiD.exe")
