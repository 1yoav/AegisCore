import pefile
import mmap
import ctypes
data_list = []

def extract():
    with open("C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\userdb.txt" , "r" , encoding="utf-8") as file:
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
        print(signature_list)
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
                    return 25


    return 50



def createSignature(filePath):
    with open(filePath , "r+b") as file:
        file.seek(calc_Entry_Point(filePath))
        payload = bytes.fromhex("83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14")
        print(payload)
        file.write(payload)




def main():
    file_path = "C:\\Users\\Cyber_User\\Desktop\\magshimim\\Software.c1\\week.8\\q2.exe"
    extract()
    scan(file_path)

    return 0

if __name__ == '__main__':
    main()
