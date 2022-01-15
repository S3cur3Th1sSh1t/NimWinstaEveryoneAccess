import Desktop
import winim/lean
import winim/com, segfaults, terminal

type
    status* = enum
        error, success, loading, warning
proc print*(STATUS: status, text: string) =
    case STATUS
    of error:
        stdout.styledWrite(fgRed, "[-] ")
    of success:
        stdout.styledWrite(fgGreen, "[+] ")
    of loading:
        stdout.styledWrite(fgBlue, "[*] ")
    of warning:
        stdout.styledWrite(fgYellow, "[!] ")
    stdout.write(text & "\n"); flushFile(stdout)

### WINSTA -> Not fully working yet. Need hints/help
# https://github.com/antonioCoco/RoguePotato/blob/master/RoguePotato/Desktop.cpp

proc BuildEveryoneSid *(): PSID =
    var auth: SID_IDENTIFIER_AUTHORITY = cast[SID_IDENTIFIER_AUTHORITY](SECURITY_WORLD_SID_AUTHORITY)
    var pSID: PSID = nil
    var fSuccess: BOOL = AllocateAndInitializeSid(addr auth, 1,SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, addr pSID)
    if (fSuccess):
        return pSID
    else:
        return nil

converter toLPCWSTR*(s: string): LPCWSTR = 
  ## Converts a Nim string to Sciter-expected ptr wchar_t (LPCWSTR)
  var widestr = newWideCString(s)
  result = cast[LPCWSTR](addr widestr[0])

proc SetWinDesktopPerms * () =
    var WinStationName: LPCWSTR
    var hwinstaold: HANDLE = cast[HANDLE](GetProcessWindowStation())
    var lengthNeeded: DWORD
    var pInfo: PVOID
    var test: string = "WinSta0"
    zeroMem(addr WinStationName, 257)
    
    # memset doesn't exist in nim, system.zeroMem() should do the same
    # c_memset(addr WinStationName, 0, sizeof(WinStationName))
    if (GetUserObjectInformationW(hwinstaold, UOI_NAME, addr pInfo, 257, addr lengthNeeded) == 0):
        print(error, "Error GetUserObjectInformationW: " & $GetLastError())
    print(error, "Length needed: " & $lengthNeeded)
    #copyMem(addr test, addr pInfo, lengthNeeded)

    # The following works, but it cuts the "0" from WinSta0 - I think, that this is interpreted as the end of the LPCWSTR, need to add 0 again or find an alternative to use it as LPCWSTR
    #WinStationName = cast[LPCWSTR](addr pInfo)
    #if "WinSta" in cast[string](WinStationName):
    #    echo "Found"
    
    # This is the workaround, but it will only work for WinSta0, so it won't for special cases e.g. in ring zero.
    WinStationName = toLPCWSTR(test)
    echo "WINSTATIONNAME:"
    echo $WinStationName
    var hwinsta: HANDLE = OpenWindowStationW(WinStationName, FALSE, READ_CONTROL or WRITE_DAC);
    if (hwinsta == nil):
        echo "HWINSTA still nil"
    echo "ERROR:"
    echo $GetLastError()
    if (SetProcessWindowStation(hwinsta) == 0):
        print(error, "Error SetProcessWindowStation: " & $GetLastError())
    
    var hdesk: HDESK = OpenDesktop(
        L"default",
        0,
        FALSE,
        READ_CONTROL or WRITE_DAC or
        DESKTOP_WRITEOBJECTS or DESKTOP_READOBJECTS)
    
    if (hdesk == nil):
        print(error, "Error open Desktop: " & $GetLastError())
    
    if (hwinstaold == nil):
        print(error, "Could not open ProcessWindowStation: " & $GetLastError())
    
    if (SetProcessWindowStation(hwinstaold) == 0):
        print(error, "Error SetProcessWindowStation hwinstaold: " & $GetLastError())
    
    var psid: PSID = BuildEveryoneSid()
    if(AddTheAceWindowStation(hwinstaold, psid, true) == 0):
        print(error, "Error add Ace Station: " & $GetLastError())
    if(AddTheAceDesktop(cast[HANDLE](hdesk), psid, true) == 0):
        print(error, "Error add Ace desktop: " & $GetLastError())

    CloseWindowStation(hwinsta)
    CloseDesktop(hDesk)

when defined(windows):
    when isMainModule:
        SetWinDesktopPerms()
