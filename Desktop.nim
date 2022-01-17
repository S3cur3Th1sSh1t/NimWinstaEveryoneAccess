import winim/lean
import terminal, strutils
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

#proc GetAclInformation * (pAcl: PACL, pAclInformation: LPVOID, nAclInformationLength: DWORD, dwAclInformationClass: typedesc[ACL_SIZE_INFORMATION]): WINBOOL {.winapi, stdcall, dynlib: "advapi32", importc.}


proc AddTheAceDesktop * (hdesk: HANDLE, psid: PSID, debug : bool = false): BOOL =
    var
        aclSizeInfo: ACL_SIZE_INFORMATION
        AclSizeInformationClass: int32 = cast[int32](2)
        DESKTOP_ALL: DWORD = (DESKTOP_CREATEMENU or DESKTOP_CREATEWINDOW  or DESKTOP_ENUMERATE or DESKTOP_HOOKCONTROL or DESKTOP_JOURNALPLAYBACK or DESKTOP_JOURNALRECORD or DESKTOP_READOBJECTS or DESKTOP_SWITCHDESKTOP or  DESKTOP_WRITEOBJECTS or DELETE or READ_CONTROL or WRITE_DAC or WRITE_OWNER)
        bDaclExist: BOOL
        bDaclPresent: BOOL
        bSuccess: BOOL = 0
        dwNewAclSize: DWORD
        dwSidSize: DWORD = 0
        dwSdSizeNeeded: DWORD
        pacl: PACL
        pNewACL: PACL = nil
        psd: PSECURITY_DESCRIPTOR = nil
        psdNew: PSECURITY_DESCRIPTOR = nil
        pTempAce: PVOID
        si: SECURITY_INFORMATION = DACL_SECURITY_INFORMATION
        functionreturn: BOOL = 0
    if debug:
        print(success, "AddTheAceDesktop to hdesk start!")

    # obtain the security descriptor for the desktop object
    functionreturn = GetUserObjectSecurity(hdesk, addr si, psd, dwSidSize, addr dwSdSizeNeeded)
    if (functionreturn == 0):
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER):
            psd = cast[PSECURITY_DESCRIPTOR](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSdSizeNeeded))
            if (psd == nil):
                echo "Psd is null"
                return bSuccess
            psdNew = cast[PSECURITY_DESCRIPTOR](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSdSizeNeeded))
            if (psdNew == nil):
                echo "PsdNew is null"
                return bSuccess
            dwSidSize = dwSdSizeNeeded
            functionreturn = GetUserObjectSecurity(hdesk, addr si, psd, dwSidSize, addr dwSdSizeNeeded)
            if (functionreturn == 0):
                echo "2ccond GetUserObjectSecurity fail"
                return bSuccess
    if debug:
        print(success, "GetUserObjectSecurity fine!")
    # create a new security descriptor
    functionreturn = InitializeSecurityDescriptor(psdNew,SECURITY_DESCRIPTOR_REVISION)
    if (functionreturn == 0):
        echo "InitializeSecurityDescriptor failed"
        return bSuccess
    if debug:
        print(success, "InitializeSecurityDescriptor fine!")
    # obtain the dacl from the security descriptor
    functionreturn = GetSecurityDescriptorDacl(psd,addr bDaclPresent,addr pacl,addr bDaclExist)
    if (functionreturn == 0):
        echo "GetSecurityDescriptorDacl failed"
        return bSuccess
    if debug:
        print(success, "GetSecurityDescriptorDacl fine!")
    # initialize
    ZeroMemory(addr aclSizeInfo, sizeof(ACL_SIZE_INFORMATION))
    aclSizeInfo.AclBytesInUse = cast[DWORD](sizeof(ACL))
    # call only if NULL dacl
    if (pacl != nil):
        # determine the size of the ACL info
        functionreturn = GetAclInformation(pacl,cast[LPVOID](addr aclSizeInfo),cast[DWORD](sizeof(ACL_SIZE_INFORMATION)),AclSizeInformationClass)
        if (functionreturn == 0):
            print(error,"GetAclInformation failed!" & $GetLastError())
            return bSuccess
        else:
            if(debug):
                print(success,"GetAclInformation fine!" & $GetLastError())
    # compute the size of the new acl
    dwNewAclSize = cast[DWORD](aclSizeInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD))
    # allocate buffer for the new acl
    pNewAcl = cast[PACL](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwNewAclSize))
    if (pNewAcl == nil):
         echo "pNewACL is null"
         return bSuccess
    if debug:
        print(success, "pNewAcl fine!")
     # initialize the new acl
    functionreturn = InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION)
    if (functionreturn == 0):
        echo "InitializeAcl failed"
        return bSuccess
    if debug:
        print(success, "InitializeAcl fine!")
    # if DACL is present, copy it to a new DACL
    if (bDaclPresent): # only copy if DACL was present
        # copy the ACEs to our new ACL
        if (aclSizeInfo.AceCount):
            if debug:
                print(success, "aclSizeInfo.AceCount: " & $aclSizeInfo.AceCount)
            var low = 0
            for low in 0 ..< aclSizeInfo.AceCount:
                # get an ACE
                functionreturn = GetAce(pacl, cast[DWORD](low), addr pTempAce)
                if (functionreturn == 0):
                    print(error,"GetACE failed!" & $GetLastError())
                    #return bSuccess
                else:
                    if debug:
                        print(success, "GetAce fine!")
                var asd: PACE_HEADER = cast[PACE_HEADER](addr pTempAce)
                echo $cast[DWORD](asd.AceSize)
                functionreturn = AddAce(pNewAcl,ACL_REVISION,MAXDWORD,cast[LPVOID](addr pTempAce),cast[DWORD](asd.AceSize))
                if (functionreturn == 0):
                    print(error,"AddAce failed!" & $GetLastError())
                    #return bSuccess
                else:
                    if debug:
                        print(success, "AddAce fine!")
                # leave
    #if (functionreturn == 0):
    #    return bSuccess
    # add ace to the dacl
    functionreturn = AddAccessAllowedAce(pNewAcl,ACL_REVISION,DESKTOP_ALL,psid)
    if (functionreturn == 0):
        echo "AddAccessAllowedAce failed"
        return bSuccess
    if debug:
        print(success, "AddAccessAllowedAce fine!")
    # set new dacl to the new security descriptor
    functionreturn = SetSecurityDescriptorDacl(psdNew,true,pNewAcl,false)
    if (functionreturn == 0):
        echo "SetSecurityDescriptorDacl failed"
        return bSuccess
    if debug:
        print(success, "SetSecurityDescriptorDacl fine!")
    # set the new security descriptor for the desktop object
    functionreturn = SetUserObjectSecurity(hdesk, addr si, psdNew)
    if (functionreturn == 0):
        echo "SetUserObjectSecurity failed"
        return bSuccess
    if debug:
        print(success, "SetUserObjectSecurity fine!")
    bSuccess = true
    echo "Everything went fine"
    # free buffers
    if (pNewACL != nil):
        HeapFree(GetProcessHeap(), 0, cast[LPVOID](pNewAcl))
    if (psd != nil):
        HeapFree(GetProcessHeap(), 0, cast[LPVOID](psd))
    if (psdNew != nil):
        HeapFree(GetProcessHeap(), 0, cast[LPVOID](psdNew))
    return bSuccess

proc AddTheAceWindowStation * (hwinsta: HANDLE, psid: PSID, debug : bool = false): BOOL =
    var
        pace: PVOID
        WINSTA_ALL: DWORD =  (WINSTA_ACCESSCLIPBOARD  or WINSTA_ACCESSGLOBALATOMS or WINSTA_CREATEDESKTOP or WINSTA_ENUMDESKTOPS or WINSTA_ENUMERATE or WINSTA_EXITWINDOWS or WINSTA_READATTRIBUTES or WINSTA_READSCREEN or WINSTA_WRITEATTRIBUTES or DELETE or READ_CONTROL or WRITE_DAC or WRITE_OWNER)
        aclSizeInfo: ACL_SIZE_INFORMATION
        GENERIC_ACCESS: DWORD = (GENERIC_READ or GENERIC_WRITE or GENERIC_EXECUTE or GENERIC_ALL)
        AclSizeInformationClass: int32 = 2
        bDaclExist: BOOL
        bDaclPresent: BOOL
        bSuccess: BOOL = 0
        dwNewAclSize: DWORD
        dwSidSize: DWORD = 0
        dwSdSizeNeeded: DWORD
        pacl: PACL
        pNewACL: PACL = nil
        psd: PSECURITY_DESCRIPTOR = nil
        psdNew: PSECURITY_DESCRIPTOR = nil
        pTempAce: PVOID
        si: SECURITY_INFORMATION = DACL_SECURITY_INFORMATION
        i: int
        functionreturn: BOOL = 0
    if debug:
        print(success, "AddTheAceWindowStation to WINSTA start!")
    # obtain the security descriptor for the desktop object
    functionreturn = GetUserObjectSecurity(hwinsta, addr si, psd, dwSidSize, addr dwSdSizeNeeded)
    if (functionreturn == 0):
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER):
            psd = cast[PSECURITY_DESCRIPTOR](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSdSizeNeeded))
            if (psd == nil):
                echo "Psd is null"
                return bSuccess
            psdNew = cast[PSECURITY_DESCRIPTOR](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSdSizeNeeded))
            if (psdNew == nil):
                echo "PsdNew is null"
                return bSuccess
            dwSidSize = dwSdSizeNeeded
            functionreturn = GetUserObjectSecurity(hwinsta, addr si, psd, dwSidSize, addr dwSdSizeNeeded)
            if (functionreturn == 0):
                echo "2ccond GetUserObjectSecurity fail"
                return bSuccess
    if debug:
        print(success, "GetUserObjectSecurity fine!")
    # create a new security descriptor
    functionreturn = InitializeSecurityDescriptor(psdNew,SECURITY_DESCRIPTOR_REVISION)
    if (functionreturn == 0):
        print(error,"InitializeSecurityDescriptor failed!" & $GetLastError())
        return bSuccess
    else:
        if (debug):
            print(success, "InitializeSecurityDescriptor fine!")
    # obtain the dacl from the security descriptor
    functionreturn = GetSecurityDescriptorDacl(psd,addr bDaclPresent,addr pacl,addr bDaclExist)
    if (functionreturn == 0):
        print(error,"GetSecurityDescriptorDacl failed!" & $GetLastError())
        return bSuccess
    else:
            print(success, "GetSecurityDescriptorDacl fine!")
    # initialize
    ZeroMemory(addr aclSizeInfo, sizeof(ACL_SIZE_INFORMATION))
    aclSizeInfo.AclBytesInUse = cast[DWORD](sizeof(ACL))
    # call only if NULL dacl
    if (pacl != nil):
        # determine the size of the ACL info
        functionreturn = GetAclInformation(pacl,cast[LPVOID](addr aclSizeInfo),cast[DWORD](sizeof(ACL_SIZE_INFORMATION)),AclSizeInformationClass)
        if (functionreturn == 0):
            print(error,"GetAclInformation failed!" & $GetLastError())
            return bSuccess
        else:
            if (debug):
                print(success, "GetAclInformation fine!")
    # compute the size of the new acl
    dwNewAclSize = cast[DWORD](aclSizeInfo.AclBytesInUse + (2 * sizeof(ACCESS_ALLOWED_ACE)) + (2 * GetLengthSid(psid)) - (2 * sizeof(DWORD)))
    # allocate buffer for the new acl
    pNewAcl = cast[PACL](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwNewAclSize))
    if (pNewAcl == nil):
         echo "pNewACL is null"
         return bSuccess
    if debug:
        print(success, "pNewACL fine!")
     # initialize the new acl
    functionreturn = InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION)
    if (functionreturn == 0):
        echo "InitializeAcl failed"
        return bSuccess
    if debug:
        print(success, "InitializeAcl fine!")
    # if DACL is present, copy it to a new DACL
    if debug:
        print(success, "aclSizeInfo.AceCount: " & $aclSizeInfo.AceCount)
    if (bDaclPresent): # only copy if DACL was present
        # copy the ACEs to our new ACL
        if (aclSizeInfo.AceCount):
            #var counter = 0
            if debug:
                print(success, "aclSizeInfo.AceCount: " & $aclSizeInfo.AceCount)
            for i in 0 ..< aclSizeInfo.AceCount:
                # get an ACE
                functionreturn = GetAce(pacl, cast[DWORD](i), addr pTempAce)
                if (functionreturn == 0):
                    print(error,"GetACE failed!" & $GetLastError() )
                    #return bSuccess
                else:
                    if debug:
                        print(success, "GetAce fine!")
                var asd: PACE_HEADER = cast[PACE_HEADER](addr pTempAce)
                echo $cast[DWORD](asd.AceSize)
                functionreturn = AddAce(pNewAcl,ACL_REVISION,MAXDWORD,cast[LPVOID](addr pTempAce),cast[DWORD](asd.AceSize))
                #pNewAcl = cast[PACL](addr pNewAcl)
                if (functionreturn == 0):
                    print(error,"AddACE failed!" & $GetLastError())
                    #return bSuccess
                else:
                    if debug:
                        print(success, "AddAce fine!")
                # leave
    #if (functionreturn == 0):
    #    return bSuccess
    # add the first ace to the windowstation
    pace = cast[PVOID](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD)))
    if (pace == nil):
        echo "PACE is null"
        return bSuccess
    if debug:
        print(success, "PACE fine!")
    var paceACE: ACCESS_ALLOWED_ACE = cast[ACCESS_ALLOWED_ACE](pace) 
    paceACE.Header.AceType = ACCESS_ALLOWED_ACE_TYPE
    paceACE.Header.AceFlags = CONTAINER_INHERIT_ACE or INHERIT_ONLY_ACE or OBJECT_INHERIT_ACE
    paceACE.Header.AceSize =  cast[uint16](sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD))
    paceACE.Mask = GENERIC_ACCESS
    functionreturn = CopySid(GetLengthSid(psid), addr paceACE.SidStart, psid)
    if (functionreturn == 0):
        echo "CopySid failed"
        return bSuccess
    if debug:
        print(success, "CopySid fine!")
        echo $cast[DWORD](paceACE.Header.AceSize)
    functionreturn = AddAce(pNewAcl,ACL_REVISION,MAXDWORD,cast[LPVOID](addr pace),cast[DWORD](paceACE.Header.AceSize))
    #pNewAcl = cast[PACL](addr pNewAcl)
    if (functionreturn == 0):
        print(error,"AddAce failed!" & $GetLastError())
        return bSuccess
    else:
        echo "AddACE fine"
    if debug:
        print(success, "AddAce fine!")
    # add the second ACE to the windowstation
    paceACE.Header.AceFlags = NO_PROPAGATE_INHERIT_ACE
    paceACE.Mask = WINSTA_ALL
    functionreturn = AddAce(pNewAcl,ACL_REVISION,MAXDWORD,addr pace,cast[DWORD](paceACE.Header.AceSize))
    if (functionreturn == 0):
        print(error,"AddAce failed!" & $GetLastError())
        return bSuccess
    else:
        echo "AddACE 2 fine"

    if debug:
        print(success, "AddAce2 fine!")
    # set new dacl for the security descriptor
    functionreturn = SetSecurityDescriptorDacl(cast[PSECURITY_DESCRIPTOR](addr psdNew),true,cast[PACL](addr pNewAcl),false)
    if (functionreturn == 0):
        echo "SetSecurityDescriptorDacl failed"
    if debug:
        print(success, "SetSecurityDescriptorDacl fine!")
    # set the new security descriptor for the windowstation
    functionreturn = SetUserObjectSecurity(hwinsta, addr si, addr psdNew) 
    if (functionreturn == 0):
        echo "SetUserObjectSecurity failed"
    if debug:
        print(success, "SetUserObjectSecurity fine!")

    bSuccess = true

    # free buffers
    if (pNewACL != nil):
        HeapFree(GetProcessHeap(), 0, cast[LPVOID](pNewAcl))
    if (pace != nil):
        HeapFree(GetProcessHeap(), 0, cast[LPVOID](pace))
    if (psd != nil):
        HeapFree(GetProcessHeap(), 0, cast[LPVOID](psd))
    if (psdNew != nil):
        HeapFree(GetProcessHeap(), 0, cast[LPVOID](psdNew))
    return bSuccess
