import pefile
import sys
from pathlib import Path
data_list = []

def extract():
    signatures_path = ""
    if getattr(sys, 'frozen', False):
        signatures_path = Path(sys.executable).parent.parent / "userdb.txt"
    else:
        signatures_path = Path(__file__).resolve().parent / "userdb.txt"
    with open(signatures_path , "r" , encoding="utf-8") as file:
        i = 0
        upxName = ""
        signture = ""
        entryPoint = True

        for line in file:
            if(i % 4 == 0):
                upxName = line.strip()
            elif i % 4 == 1:
                signature1 = line.strip()
                signature = signature1.replace("signature = " , '')
                signature1 = signature.split(" ")
            elif i % 4 == 2:
                if("false" in line):
                    entryPoint = False
                data_list.append((upxName , signature1 , entryPoint))
                entryPoint = True
            i += 1

def find_entry_point_section(pe, eop_rva):
    for section in pe.sections:
        if section.contains_rva(eop_rva):
            return section

    return None

def calc_Entry_Point(file):
    pe = pefile.PE(file, fast_load=True)
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return pe.get_offset_from_rva(entrypoint)




def scan(file_path):
    signature_list = []
    entrypoint = calc_Entry_Point(file_path)
    with open (file_path , "rb") as scanFile:
        scanFile.seek(entrypoint)
        output = scanFile.read(100)

         #create the the list of the signature
        for item in output:
            signature_list.append( hex(item)[2:])
        #this is the part of the comparing signatures
        for instance in data_list:
            if(instance[2] == False):
                continue
            else:
                is_equal = True
                for num in range(len(instance[1])):
                    if instance[1][num] == "??":
                        continue
                    else:
                        if instance[1][num] != signature_list[num]:
                            is_equal = False
                            break
                if is_equal == True:
                    return 25 ,["the program packed by " + instance[0] + "\n"]


    return 50 , [""]



def createSignature(filePath):
    with open(filePath , "r+b") as file:
        file.seek(calc_Entry_Point(filePath))
        payload = bytes.fromhex("83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14")
        print(payload)
        file.write(payload)


# run one time for keeping all the packers signature
extract()

