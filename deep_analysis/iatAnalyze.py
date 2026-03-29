import pefile
from pathlib import Path

cleaned_funcs = []

def analyzeIat():
    risk_score = 0
    findings = ""
    if len(cleaned_funcs) < 5: # check for functions amount
        if "loadlibrarya" in cleaned_funcs or "getprocaddress" in cleaned_funcs:
            findings += "too few functions in iat"
            risk_score += 30

    # checks for injector program
    injection_apis = {"virtualallocex", "writeprocessmemory", "createremotethread", "openprocess"}
    found_injection = injection_apis.intersection(cleaned_funcs)
    if len(found_injection) >= 2:
        findings += "THE programs suspect in injecting!\n"
        risk_score += 20

    # checks for logger program
    spy_apis = {"setwindowshookex", "getasynckeystate", "getkeyboardstate"}
    found_spy = spy_apis.intersection(cleaned_funcs)
    if found_spy:
        findings += "program trying to hook keyboards\n"
        risk_score += 20

    #check for debugger progrqm
    evasion_apis = {"isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstringa"}
    found_evasion = evasion_apis.intersection(cleaned_funcs)
    if found_evasion:
        findings += "program behave like debugger!\n"
        risk_score += 20

    # checks for internet prgram
    network_apis = {"internetopenurl", "httpsendrequest", "wsastartup", "urldownloadtofilea", "internetconnecta"}
    found_network = network_apis.intersection(cleaned_funcs)
    if found_network:
        findings += "program trying to listen for the ethernet\n"
        risk_score += 10

    return risk_score , findings

def analyze(path):
    if Path(path).is_file():

        # check if its executable
        with open(path, 'rb') as f:
            magic = f.read(2)
            if magic != b'MZ':
                return 0 , ""

        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for func in entry.imports:
                    if func.name:
                        name = func.name.decode('utf-8', errors='ignore').lower()
                        cleaned_funcs.append(name)

            return analyzeIat()
        else:
            return 0 , ""

    else:
        print("iat reporting " + path + " not exsist in the system")
        return 0 # to do: cimmunicate with isolationForest

