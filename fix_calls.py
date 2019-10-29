import os
import sys


import idc
import idautils
import idaapi
import ida_bytes
import ida_idaapi


import logging


logger = logging.getLogger(__name__)


def __create_load_data_segment(data, seg_addr, seg_name):
    # This function creates a data segment located in a pre-specified address
    # and fills this new segment with data

    seglen = len(data)
    if seglen % 0x1000 != 0:
        seglen = seglen + (0x1000 - (seglen % 0x1000))

    if not idc.AddSeg(seg_addr, seg_addr + seglen, 0, 1, 0, idaapi.scPub):
        logger.error('failed to add segment: 0x%x', seg_addr)
        return False

    if not idc.set_segm_name(seg_addr, seg_name):
        logger.warning('failed to rename segment: %s', seg_name)
        return False

    if not idc.set_segm_class(seg_addr, 'DATA'):
        logger.warning('failed to set segment class DATA: %s', seg_name)
        return False

    if not idc.set_segm_attr(seg_addr, idc.SEGATTR_ALIGN, idc.saRelPara):
        logger.warning('failed to align segment: %s', seg_name)
        return False

    if data:
        idaapi.patch_bytes(seg_addr, data)

    return True


def __import_names(start_address, names):

    for addr in range(start_address, start_address + (len(names) * 4), 4):
        print('0x{:08x}'.format(addr))
        ida_bytes.create_data(addr, idc.FF_DWORD, 4, ida_idaapi.BADADDR)
        name = names.pop(0)
        idc.set_name(addr, name, idc.SN_NOWARN)

    return True


def __patch_indirect_call_instructions():
    for seg in idautils.Segments():
        for func in idautils.Functions(seg):
            function_name = idc.get_func_name(func)
            print('[+] Checking function "{}"'.format(function_name))
            for (startea, endea) in idautils.Chunks(func):
                for head in idautils.Heads(startea, endea):
                    m = idc.print_insn_mnem(head)
                    if m == 'call':
                        op = idc.get_operand_type(head, 0)
                        if op == idc.o_displ:
                            print('{}: 0x{:08x}: {}'.format(function_name, head, idc.generate_disasm_line(head, 0)))
                            ida_bytes.patch_word(head, 0x15ff)
                            print('{}: 0x{:08x}: {}'.format(function_name, head, idc.generate_disasm_line(head, 0)))

SL_CALL_TABLE_LABELS = [ 
    "kernel32.LoadLibraryA", "kernel32.GetProcAddress", "ntdll.RtlExitUserThread", "kernel32.VirtualAlloc", 
    "kernel32.VirtualFree", "kernel32.lstrcatA", "kernel32.lstrlen", "kernel32.GetComputerNameA", 
    "kernel32.CloseHandle", "kernel32.CreateProcessInternalA", "kernel32.Sleep", "kernel32.GetFileSize", 
    "kernel32.ReadFile", "kernel32.WriteFile", "kernel32.GetSystemDirectoryA", "kernel32.SetFileTime", 
    "kernel32.GetFileAttributesExA", "kernel32.CreateMutexA", "kernel32.CreateThread", 
    "kernel32.GetProcessHeap", "kernel32.GetVolumeInformationA", "kernel32.MultiByteToWideChar", 
    "kernel32.LoadLibraryW", "kernel32.GetModuleFileNameW", "kernel32.CopyFileW", 
    "kernel32.CreateProcessInternalW", "kernel32.GetTempPathW", "kernel32.GetTempFileNameW", 
    "kernel32.CreateFileW", "kernel32.DeleteFileW", "kernel32.SetFileAttributesW", "kernel32.lstrcmpW", 
    "kernel32.lstrlenW", "kernel32.lstrcatW", "kernel32.ExpandEnvironmentStringsW", "kernel32.CreateDirectoryW", 
    "kernel32.CreateToolhelp32Snapshot", "kernel32.Process32First", "kernel32.Process32Next", 
    "kernel32.GetCurrentProcessId", "kernel32.OpenProcess", "kernel32.ResumeThread", 
    "kernel32.CreateFileMappingA", "kernel32.MapViewOfFile", "kernel32.WriteProcessMemory", 
    "kernel32.VirtualQuery", "kernel32.ReadProcessMemory", "kernel32.TerminateProcess", 
    "kernel32.GetTickCount", "kernel32.GetSystemWow64DirectoryA", "kernel32.GetWindowsDirectoryA", 
    "ntdll.RtlGetLastWin32Error", "ntdll.RtlAllocateHeap", "ntdll.RtlReAllocateHeap", "ntdll.RtlFreeHeap", 
    "ntdll.ZwCreateSection", "ntdll.NtMapViewOfSection", "ntdll.NtUnmapViewOfSection", 
    "ntdll.RtlComputeCrc32", "ntdll.RtlMoveMemory", "ntdll.RtlZeroMemory", "ntdll.atoi", 
    "ntdll.LdrGetDllHandle", "ntdll.RtlGetVersion", "ntdll.NtQueryInformationProcess", 
    "ntdll.LdrProcessRelocationBlock", "ntdll.RtlRandomEx", "advapi32.RegCloseKey", 
    "advapi32.RegOpenKeyExA", "advapi32.RegQueryValueExA", "advapi32.OpenProcessToken", 
    "advapi32.GetTokenInformation", "advapi32.CryptAcquireContextA", "advapi32.CryptReleaseContext", 
    "advapi32.CryptCreateHash", "advapi32.CryptHashData", "advapi32.CryptGetHashParam", 
    "advapi32.CryptDestroyHash", "advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorA", 
    "advapi32.GetSidSubAuthority", "advapi32.GetSidSubAuthorityCount", "advapi32.GetUserNameW", 
    "user32.wsprintfA", "user32.wsprintfW", "user32.GetClassNameA", "user32.GetWindowThreadProcessId", 
    "user32.EnumWindows", "ole32.CoInitializeEx", "ole32.CoInitializeSecurity", "ole32.CoCreateInstance", 
    "ole32.CoUninitialize", "winhttp.WinHttpOpen", "winhttp.WinHttpConnect", "winhttp.WinHttpOpenRequest", 
    "winhttp.WinHttpCloseHandle", "winhttp.WinHttpSendRequest", "winhttp.WinHttpReceiveResponse", 
    "winhttp.WinHttpReadData", "winhttp.WinHttpSetOption", "winhttp.WinHttpCrackUrl", 
    "winhttp.WinHttpGetIEProxyConfigForCurrentUser", "winhttp.WinHttpGetProxyForUrl", 
    "winhttp.WinHttpAddRequestHeaders", "dnsapi.DnsQuery_W", "dnsapi.DnsRecordListFree", 
    "urlmon.ObtainUserAgentString", "ws2_32.inet_ntoa", "shell32.ShellExecuteW"
]


_file = "C:\\Users\\test\\Desktop\\tinype_002E0000.bin"

fd = open(_file, 'rb')
data = fd.read()
if not __create_load_data_segment(data, 0x0, '.data'):
    logger.warning('[!] Could not create and load data into new segment.')
else:
    logger.info('[+] Segment was created successfully!')

__import_names(0xE86, SL_CALL_TABLE_LABELS)

__patch_indirect_call_instructions()