import ctypes
import locale
import typing

_NULL = type('NULL', (), {})
INVALID_HANDLE_VALUE = 0xffffffffffffffff
DEFAULT_CODING = locale.getpreferredencoding()

if typing.TYPE_CHECKING:
    from .process import Process


def def_win_api(func, res_type: typing.Any = ctypes.c_void_p, arg_types=(), error_zero=False, error_nonzero=False, error_val: typing.Any = _NULL):
    func.argtypes = arg_types
    func.restype = res_type
    if error_zero and error_nonzero:  # pragma: no cover
        raise ValueError("Cannot raise on both zero and non-zero")

    if error_zero:
        def wrapper(*args, **kwargs):

            res = func(*args, **kwargs)
            if not res:
                raise ctypes.WinError()
            return res

        return wrapper
    if error_nonzero:
        def wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            if res: raise ctypes.WinError()
            return res

        return wrapper

    if error_val is not _NULL:
        def wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            if res == error_val: raise ctypes.WinError()
            return res

        return wrapper
    return func


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong)
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong), ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("count", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class LIST_ENTRY(ctypes.Structure):
    _fields_ = [("Flink", ctypes.c_void_p), ("Blink", ctypes.c_void_p), ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [('Length', ctypes.c_ushort), ('MaximumLength', ctypes.c_ushort), ('Buffer', ctypes.c_size_t), ]

    @classmethod
    def from_str(cls, s: str):
        length = len(s) * 2
        _s = cls(length, length + 2, ctypes.addressof(_buf := ctypes.create_unicode_buffer(s)))
        setattr(_s, '_buf', _buf)
        return _s

    @property
    def value(self):
        return ctypes.cast(self.Buffer, ctypes.c_wchar_p).value

    def remote_value(self, process: 'Process'):
        return process.read(self.Buffer, self.Length).decode('utf-16-le')


class LDR_DATA_TABLE_ENTRY(LIST_ENTRY):
    _fields_ = [
        ("InLoadOrderLinks", LIST_ENTRY),
        ("InMemoryOrderLinks", LIST_ENTRY),
        ("InInitializationOrderLinks", LIST_ENTRY),
        ("DllBase", ctypes.c_void_p),
        ("EntryPoint", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_uint32),
        ("FullDllName", UNICODE_STRING),
        ("BaseDllName", UNICODE_STRING),
        ("Flags", ctypes.c_uint32),
        ("LoadCount", ctypes.c_uint16),
        ("TlsIndex", ctypes.c_uint16),
        ("HashLinks", LIST_ENTRY),
        ("SectionPointer", ctypes.c_void_p),
        ("CheckSum", ctypes.c_uint32),
        ("TimeDateStamp", ctypes.c_uint32),
        ("LoadedImports", ctypes.c_void_p),
        ("EntryPointActivationContext", ctypes.c_void_p),
        ("PatchInformation", ctypes.c_void_p),
    ]


class PEB_LDR_DATA(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("Initialized", ctypes.c_uint8),
        ("SsHandle", ctypes.c_void_p),
        ("InLoadOrderModuleList", LIST_ENTRY),
        ("InMemoryOrderModuleList", LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
        ("EntryInProgress", ctypes.c_void_p),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_ulong),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_void_p),
        ("BasePriority", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p)
    ]


class PEB(ctypes.Structure):
    _fields_ = [
        ("InheritedAddressSpace", ctypes.c_uint8),
        ("ReadImageFileExecOptions", ctypes.c_uint8),
        ("BeingDebugged", ctypes.c_uint8),
        ("SpareBool", ctypes.c_uint8),
        ("Mutant", ctypes.c_void_p),
        ("ImageBaseAddress", ctypes.c_void_p),
        ("Ldr", ctypes.c_void_p),
        # ...
    ]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", ctypes.c_ulong),
        ("OffsetHigh", ctypes.c_ulong),
        ("hEvent", ctypes.c_void_p)
    ]


class kernel32:
    dll = ctypes.WinDLL('kernel32.dll')
    GetCurrentProcess = def_win_api(dll.GetCurrentProcess, ctypes.c_void_p, (), error_zero=True)
    CreateToolhelp32Snapshot = def_win_api(dll.CreateToolhelp32Snapshot, ctypes.c_void_p, (ctypes.c_ulong, ctypes.c_ulong), error_val=INVALID_HANDLE_VALUE)
    Process32First = def_win_api(dll.Process32First, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    Process32Next = def_win_api(dll.Process32Next, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    CloseHandle = def_win_api(dll.CloseHandle, ctypes.c_bool, (ctypes.c_void_p,), error_zero=True)
    OpenProcess = def_win_api(dll.OpenProcess, ctypes.c_void_p, (ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong), error_zero=True)
    CreateRemoteThread = def_win_api(dll.CreateRemoteThread, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p), error_zero=True)
    ReadProcessMemory = def_win_api(dll.ReadProcessMemory, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p), error_zero=True)
    WriteProcessMemory = def_win_api(dll.WriteProcessMemory, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p), error_zero=True)
    VirtualAllocEx = def_win_api(dll.VirtualAllocEx, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong), error_val=0)
    VirtualFreeEx = def_win_api(dll.VirtualFreeEx, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong), error_zero=True)
    VirtualProtectEx = def_win_api(dll.VirtualProtectEx, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p), error_zero=True)
    VirtualQueryEx = def_win_api(dll.VirtualQueryEx, ctypes.c_size_t, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t), error_zero=True)
    GetProcAddress = def_win_api(dll.GetProcAddress, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_char_p), error_zero=True)
    GetModuleHandle = def_win_api(dll.GetModuleHandleW, ctypes.c_size_t, (ctypes.c_wchar_p,), error_val=0)
    GetCurrentProcessId = def_win_api(dll.GetCurrentProcessId, ctypes.c_ulong, (), error_zero=True)
    WaitForSingleObject = def_win_api(dll.WaitForSingleObject, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_ulong), error_val=0xFFFFFFFF)
    CreateEvent = def_win_api(dll.CreateEventW, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_bool, ctypes.c_bool, ctypes.c_wchar_p), error_val=INVALID_HANDLE_VALUE)
    WriteFile = def_win_api(dll.WriteFile, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    ReadFile = def_win_api(dll.ReadFile, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    GetOverlappedResult = def_win_api(dll.GetOverlappedResult, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool), error_zero=True)
    CreateNamedPipe = def_win_api(dll.CreateNamedPipeW, ctypes.c_void_p, (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p), error_val=INVALID_HANDLE_VALUE)
    ConnectNamedPipe = def_win_api(dll.ConnectNamedPipe, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    CreateFile = def_win_api(dll.CreateFileW, ctypes.c_void_p, (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p), error_val=INVALID_HANDLE_VALUE)
    SetNamedPipeHandleState = def_win_api(dll.SetNamedPipeHandleState, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)


class advapi32:
    dll = ctypes.WinDLL('advapi32.dll')
    OpenProcessToken = def_win_api(dll.OpenProcessToken, ctypes.c_long, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p), error_zero=True)
    LookupPrivilegeName = def_win_api(dll.LookupPrivilegeNameW, ctypes.c_long, (ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p), error_zero=True)
    LookupPrivilegeValue = def_win_api(dll.LookupPrivilegeValueW, ctypes.c_long, (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p), error_zero=True)
    AdjustTokenPrivileges = def_win_api(dll.AdjustTokenPrivileges, ctypes.c_long, (ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)


class ntdll:
    dll = ctypes.WinDLL('ntdll.dll')
    NtQueryInformationProcess = def_win_api(dll.NtQueryInformationProcess, ctypes.c_long, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p), error_nonzero=True)
