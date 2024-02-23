import ctypes
import ctypes.wintypes
import ctypes.util
import functools
import io
import locale
import logging
import os
import tempfile

import msvcrt
import pathlib
import pickle
import re
import struct
import threading
import traceback
import types

import time

import sys
import typing

_NULL = type('NULL', (), {})
_T = typing.TypeVar('_T')


def _win_api(func, res_type: typing.Any = ctypes.c_void_p, arg_types=(), error_zero=False, error_nonzero=False, error_val: typing.Any = _NULL):
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


PYTHON_DLL = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
INVALID_HANDLE_VALUE = 0xffffffffffffffff
DEFAULT_CODING = locale.getpreferredencoding()


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
    GetCurrentProcess = _win_api(dll.GetCurrentProcess, ctypes.c_void_p, (), error_zero=True)
    CreateToolhelp32Snapshot = _win_api(dll.CreateToolhelp32Snapshot, ctypes.c_void_p, (ctypes.c_ulong, ctypes.c_ulong), error_val=INVALID_HANDLE_VALUE)
    Process32First = _win_api(dll.Process32First, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    Process32Next = _win_api(dll.Process32Next, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    CloseHandle = _win_api(dll.CloseHandle, ctypes.c_bool, (ctypes.c_void_p,), error_zero=True)
    OpenProcess = _win_api(dll.OpenProcess, ctypes.c_void_p, (ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong), error_zero=True)
    CreateRemoteThread = _win_api(dll.CreateRemoteThread, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p), error_zero=True)
    ReadProcessMemory = _win_api(dll.ReadProcessMemory, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p), error_zero=True)
    WriteProcessMemory = _win_api(dll.WriteProcessMemory, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p), error_zero=True)
    VirtualAllocEx = _win_api(dll.VirtualAllocEx, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong), error_val=0)
    VirtualFreeEx = _win_api(dll.VirtualFreeEx, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong), error_zero=True)
    VirtualProtectEx = _win_api(dll.VirtualProtectEx, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p), error_zero=True)
    VirtualQueryEx = _win_api(dll.VirtualQueryEx, ctypes.c_size_t, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t), error_zero=True)
    GetProcAddress = _win_api(dll.GetProcAddress, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_char_p), error_zero=True)
    GetModuleHandle = _win_api(dll.GetModuleHandleW, ctypes.c_size_t, (ctypes.c_wchar_p,), error_val=0)
    GetCurrentProcessId = _win_api(dll.GetCurrentProcessId, ctypes.c_ulong, (), error_zero=True)
    WaitForSingleObject = _win_api(dll.WaitForSingleObject, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_ulong), error_val=0xFFFFFFFF)
    CreateEvent = _win_api(dll.CreateEventW, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_bool, ctypes.c_bool, ctypes.c_wchar_p), error_val=INVALID_HANDLE_VALUE)
    WriteFile = _win_api(dll.WriteFile, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    ReadFile = _win_api(dll.ReadFile, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    GetOverlappedResult = _win_api(dll.GetOverlappedResult, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool), error_zero=True)
    CreateNamedPipe = _win_api(dll.CreateNamedPipeW, ctypes.c_void_p, (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p), error_val=INVALID_HANDLE_VALUE)
    ConnectNamedPipe = _win_api(dll.ConnectNamedPipe, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    CreateFile = _win_api(dll.CreateFileW, ctypes.c_void_p, (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p), error_val=INVALID_HANDLE_VALUE)
    SetNamedPipeHandleState = _win_api(dll.SetNamedPipeHandleState, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)


class advapi32:
    dll = ctypes.WinDLL('advapi32.dll')
    OpenProcessToken = _win_api(dll.OpenProcessToken, ctypes.c_long, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p), error_zero=True)
    LookupPrivilegeName = _win_api(dll.LookupPrivilegeNameW, ctypes.c_long, (ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p), error_zero=True)
    LookupPrivilegeValue = _win_api(dll.LookupPrivilegeValueW, ctypes.c_long, (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p), error_zero=True)
    AdjustTokenPrivileges = _win_api(dll.AdjustTokenPrivileges, ctypes.c_long, (ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)


class ntdll:
    dll = ctypes.WinDLL('ntdll.dll')
    NtQueryInformationProcess = _win_api(dll.NtQueryInformationProcess, ctypes.c_long, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p), error_nonzero=True)


def pid_by_executable(executable_name: bytes | str):
    if isinstance(executable_name, str):
        executable_name = executable_name.encode(DEFAULT_CODING)

    def _iter_processes():
        class ProcessEntry32(ctypes.Structure):
            _fields_ = [
                ('dwSize', ctypes.c_ulong),
                ('cntUsage', ctypes.c_ulong),
                ('th32ProcessID', ctypes.c_ulong),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                ('th32ModuleID', ctypes.c_ulong),
                ('cntThreads', ctypes.c_ulong),
                ('th32ParentProcessID', ctypes.c_ulong),
                ('pcPriClassBase', ctypes.c_ulong),
                ('dwFlags', ctypes.c_ulong),
                ('szExeFile', ctypes.c_char * ctypes.wintypes.MAX_PATH)
            ]

        hSnap = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # SNAPPROCESS
        process_entry = ProcessEntry32()
        process_entry.dwSize = ctypes.sizeof(process_entry)
        kernel32.Process32First(hSnap, ctypes.byref(process_entry))
        try:
            yield process_entry
            while 1:
                yield process_entry
                kernel32.Process32Next(hSnap, ctypes.byref(process_entry))
        except WindowsError as e:
            if e.winerror != 18:
                raise
        finally:
            kernel32.CloseHandle(hSnap)

    for process in _iter_processes():
        if process.szExeFile == executable_name:
            yield process.th32ProcessID


def enable_privilege():
    hProcess = ctypes.c_void_p(kernel32.GetCurrentProcess())
    if advapi32.OpenProcessToken(hProcess, 32, ctypes.byref(hProcess)):
        tkp = TOKEN_PRIVILEGES()
        advapi32.LookupPrivilegeValue(None, "SeDebugPrivilege", ctypes.byref(tkp.Privileges[0].Luid))
        tkp.count = 1
        tkp.Privileges[0].Attributes = 2
        advapi32.AdjustTokenPrivileges(hProcess, 0, ctypes.byref(tkp), 0, None, None)


_aligned4 = lambda v: (v + 0x3) & (~0x3)
_aligned16 = lambda v: (v + 0xf) & (~0xf)


class _Pattern:
    fl_is_ref = 1 << 0
    fl_is_byes = 1 << 1
    fl_store = 1 << 2

    hex_chars = set(b'0123456789abcdefABCDEF')
    dec_chars = set(b'0123456789')

    special_chars_map = {i for i in b'()[]{}?*+-|^$\\.&~# \t\n\r\v\f'}

    @classmethod
    def take_dec_number(cls, pattern: str, i: int):
        assert i < len(pattern) and ord(pattern[i]) in cls.dec_chars
        j = i + 1
        while j < len(pattern) and ord(pattern[j]) in cls.dec_chars:
            j += 1
        return int(pattern[i:j]), j

    @classmethod
    def take_cnt(cls, pattern: str, i: int, regex_pattern: bytearray):
        if i < len(pattern) and pattern[i] == '{':
            regex_pattern.append(123)  # {
            n1, i = cls.take_dec_number(pattern, i + 1)
            regex_pattern.extend(str(n1).encode())
            if pattern[i] == ':':
                n2, i = cls.take_dec_number(pattern, i + 1)
                assert n1 <= n2
                regex_pattern.append(44)  # ,
                regex_pattern.extend(str(n2).encode())
            assert pattern[i] == '}'
            regex_pattern.append(125)  # }
            i += 1
        return i

    @classmethod
    def take_byte(cls, pattern: str, i: int, regex_pattern: bytearray):
        assert i + 2 <= len(pattern)
        next_byte = int(pattern[i:i + 2], 16)
        if next_byte in cls.special_chars_map:
            regex_pattern.append(92)  # \
        regex_pattern.append(next_byte)
        return i + 2

    @classmethod
    def _take_unk(cls, pattern: str, i: int):
        start_chr = pattern[i]
        assert start_chr in ('?', '*', '^')
        if i + 1 < len(pattern) and pattern[i + 1] == start_chr:
            i += 1
        return start_chr, i + 1

    @classmethod
    def take_unk(cls, pattern: str, i: int, regex_pattern: bytearray):
        start_unk, i = cls._take_unk(pattern, i)
        regex_pattern.append(46)
        i = cls.take_cnt(pattern, i, regex_pattern)
        while i < len(pattern):
            match pattern[i]:
                case ' ':
                    i += 1
                case c if c == start_unk:
                    start_unk, i = cls._take_unk(pattern, i)
                    regex_pattern.append(46)
                    i = cls.take_cnt(pattern, i, regex_pattern)
                case _:
                    break
        return start_unk, i

    @classmethod
    def _compile_pattern(cls, pattern: str, i=0, ret_at=None):
        _i = i
        regex_pattern = bytearray()
        sub_matches = []
        group_flags = []
        while i < len(pattern):
            match pattern[i]:
                case ' ':
                    i += 1
                case '[':
                    regex_pattern.append(91)  # [
                    i += 1
                    i = cls.take_byte(pattern, i, regex_pattern)
                    while True:
                        match pattern[i]:
                            case ' ':
                                i += 1
                            case ']':
                                regex_pattern.append(93)  # ]
                                i += 1
                                break
                            case '|':
                                i = cls.take_byte(pattern, i + 1, regex_pattern)
                            case ':':
                                regex_pattern.append(45)  # -
                                i = cls.take_byte(pattern, i + 1, regex_pattern)
                            case c:
                                raise ValueError(f'Invalid character {c} in pattern {pattern!r} at {i}')

                case '(':
                    base_flag = 0  # not fl_store
                    regex_pattern.append(40)  # (
                    unk_type, i = cls.take_unk(pattern, i + 1, regex_pattern)
                    if unk_type == '*':
                        base_flag |= cls.fl_is_ref
                    elif unk_type == '^':
                        base_flag |= cls.fl_is_byes
                    sub_pattern = None
                    while True:
                        match pattern[i]:
                            case ' ':
                                i += 1
                            case ')':
                                regex_pattern.append(41)  # )
                                i += 1
                                break
                            case ':':
                                sub_pattern, i = cls._compile_pattern(pattern, i + 1, ret_at=')')
                                assert pattern[i] == ')', f'Expected ) get {pattern[i]} at {i} in pattern {pattern!r}'
                                regex_pattern.append(41)
                                i += 1
                                break
                            case c:
                                raise ValueError(f'Invalid character {c} in pattern {pattern!r} at {i}')
                    group_flags.append(base_flag)
                    sub_matches.append(sub_pattern)
                case '<':
                    base_flag = cls.fl_store
                    regex_pattern.append(40)
                    unk_type, i = cls.take_unk(pattern, i + 1, regex_pattern)
                    if unk_type == '*':
                        base_flag |= cls.fl_is_ref
                    elif unk_type == '^':
                        base_flag |= cls.fl_is_byes
                    sub_pattern = None
                    while True:
                        match pattern[i]:
                            case ' ':
                                i += 1
                            case '>':
                                regex_pattern.append(41)
                                i += 1
                                break
                            case ':':
                                sub_pattern, i = cls._compile_pattern(pattern, i + 1, ret_at='>')
                                assert pattern[i] == '>', f'Expected > get {pattern[i]} at {i} in pattern {pattern!r}'
                                regex_pattern.append(41)
                                i += 1
                                break
                            case c:
                                raise ValueError(f'Invalid character {c} in pattern {pattern!r} at {i}')
                    group_flags.append(base_flag)
                    sub_matches.append(sub_pattern)
                case '?' | '*' | '^' as c:
                    regex_pattern.append(40)
                    unk_type, i = cls.take_unk(pattern, i, regex_pattern)
                    regex_pattern.append(41)
                    if c == '?':
                        group_flags.append(0)
                    elif c == '*':
                        group_flags.append(cls.fl_is_ref | cls.fl_store)
                    elif c == '^':
                        group_flags.append(cls.fl_is_byes | cls.fl_store)
                    else:
                        raise ValueError(f'Invalid character {c} in pattern {pattern!r} at {i}')
                    sub_matches.append(None)
                case c if ord(c) in cls.hex_chars:
                    i = cls.take_byte(pattern, i, regex_pattern)
                    i = cls.take_cnt(pattern, i, regex_pattern)
                case c if c == ret_at:
                    break
                case c:
                    fmt_pattern = pattern[:i] + '_' + pattern[i] + '_' + pattern[i + 1:]
                    raise ValueError(f'Invalid character {c} in pattern {fmt_pattern!r} at {i} (ret_at={ret_at})')
        try:
            regex = re.compile(bytes(regex_pattern), re.DOTALL)
        except re.error as e:
            raise ValueError(f'{e}: ({pattern!r}, {_i}, {ret_at!r}) -> {bytes(regex_pattern)}')
        return Pattern(regex, sub_matches, group_flags, pattern), i

    @classmethod
    def compile_pattern(cls, pattern: str):
        return cls._compile_pattern(pattern)[0]

    @classmethod
    def fmt_bytes_regex_pattern(cls, pat: bytes):
        s = ''
        is_escape = False
        is_in_bracket = 0
        for b in pat:
            if is_escape:
                is_escape = False
                s += f'\\x{b:02x}'
            elif b == 92:  # \
                is_escape = True
            elif b in cls.special_chars_map:
                if b == 123:  # {
                    is_in_bracket += 1
                elif b == 125:  # }
                    is_in_bracket -= 1
                s += chr(b)
            elif is_in_bracket:
                s += chr(b)
            else:
                s += f'\\x{b:02x}'
        return s


class Pattern:
    def __init__(self, regex: re.Pattern, sub_matches: 'typing.List[None | Pattern]', group_flags, pattern: str):
        self.regex = regex
        self.sub_matches = sub_matches
        self.group_flags = group_flags
        self.pattern = pattern
        self.res_is_ref = []
        for i, (sub, flag) in enumerate(zip(sub_matches, group_flags)):
            if flag & _Pattern.fl_store:
                self.res_is_ref.append(flag & _Pattern.fl_is_ref)
            if sub is not None:
                self.res_is_ref.extend(sub.res_is_ref)

    def finditer(self, _data: bytes | bytearray | memoryview, ref_base=0):
        data = _data if isinstance(_data, memoryview) else memoryview(_data)
        for match in self.regex.finditer(data):
            res = []
            if self._parse_match(data, match, res, ref_base):
                yield match.start(0), res

    def _parse_match(self, data: memoryview, match: re.Match, res: list, ref_base=0):
        for i, (sub_match, flag) in enumerate(zip(self.sub_matches, self.group_flags)):
            if flag & _Pattern.fl_is_byes:
                res.append(match.group(i + 1))
            else:
                val = int.from_bytes(match.group(i + 1), 'little', signed=True)
                if flag & _Pattern.fl_is_ref:
                    val += match.end(i + 1)
                if flag & _Pattern.fl_store:
                    res.append(val)
                if sub_match is not None:
                    start = val if flag & _Pattern.fl_is_ref else val - ref_base
                    if start < 0 or start >= len(data):
                        return False
                    if not sub_match._match(data, start, res, ref_base):
                        return False
        return True

    def _match(self, _data: memoryview, start_at: int, res: list, ref_base=0):
        if not (match := self.regex.match(_data, start_at)): return False
        return self._parse_match(_data, match, res, ref_base)

    def fmt(self, ind: str | int = ' ', _ind=0):
        if isinstance(ind, int): ind = ' ' * ind
        s = io.StringIO()
        s.write(ind * _ind)
        s.write(_Pattern.fmt_bytes_regex_pattern(self.regex.pattern))
        s.write('\n')
        s.write(ind * _ind)
        s.write('res is ref:')
        for flag in self.res_is_ref:
            s.write(' ref' if flag else ' val')
        s.write('\n')
        for i, (sub, flag) in enumerate(zip(self.sub_matches, self.group_flags)):
            s.write(ind * _ind)
            s.write(f'{i}:{"ref" if flag & _Pattern.fl_is_ref else "val"}{" store" if flag & _Pattern.fl_store else ""}\n')
            if sub is not None:
                s.write(sub.fmt(ind, _ind + 1))
                s.write('\n')
        return s.getvalue().rstrip()


class IPatternScanner:
    def search(self, pattern: str | Pattern) -> typing.Generator[tuple[int, list[int]], None, None]:
        raise NotImplementedError

    def search_unique(self, pattern: str | Pattern) -> tuple[int, list[int]]:
        s = self.search(pattern)
        try:
            res = next(s)
        except StopIteration:
            raise KeyError('pattern not found')
        try:
            next(s)
        except StopIteration:
            return res
        raise KeyError('pattern is not unique, at least 2 is found')

    def find_addresses(self, pattern: str | Pattern):
        for address, _ in self.search(pattern):
            yield address

    def find_vals(self, pattern: str | Pattern):
        for address, args in self.search(pattern):
            yield args

    def find_address(self, pattern: str | Pattern):
        return self.search_unique(pattern)[0]

    def find_val(self, pattern: str | Pattern):
        return self.search_unique(pattern)[1]


try:
    import win32file, win32pipe, win32event
except ImportError:
    has_win32 = False
else:
    has_win32 = True


class PipeHandlerBase:
    active_pipe_handler = {}
    buf_size = 64 * 1024
    handle = None
    period = .001

    def __init__(self):
        self.serve_thread = threading.Thread(target=self.serve, daemon=True)
        self.work = False
        self.is_connected = threading.Event()

    if has_win32:
        def send(self, s: bytes):
            win32file.WriteFile(self.handle, s, win32file.OVERLAPPED())

        def _serve(self):
            tid = threading.get_ident()
            PipeHandlerBase.active_pipe_handler[tid] = self
            try:
                self.is_connected.set()
                self.work = True
                overlapped = win32file.OVERLAPPED()
                overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
                while self.work:
                    err, buf = win32file.ReadFile(self.handle, self.buf_size, overlapped)
                    num_read = win32file.GetOverlappedResult(self.handle, overlapped, True)
                    self.on_data_received(bytes(buf[:num_read]))
            finally:
                if PipeHandlerBase.active_pipe_handler[tid] is self:
                    PipeHandlerBase.active_pipe_handler.pop(tid, None)
    else:
        def send(self, s: bytes):
            kernel32.WriteFile(self.handle, s, len(s), None, ctypes.byref(OVERLAPPED()))

        def _serve(self):
            tid = threading.get_ident()
            PipeHandlerBase.active_pipe_handler[tid] = self
            try:
                self.is_connected.set()
                self.work = True
                buf = ctypes.create_string_buffer(self.buf_size + 0x10)
                size = ctypes.c_ulong()
                overlapped = OVERLAPPED()
                overlapped.hEvent = kernel32.CreateEvent(None, True, False, None)
                while self.work:
                    try:
                        kernel32.ReadFile(self.handle, buf, self.buf_size, 0, ctypes.byref(overlapped))
                    except WindowsError as e:
                        if e.winerror != 997: raise
                        kernel32.WaitForSingleObject(overlapped.hEvent, -1)
                    kernel32.GetOverlappedResult(self.handle, ctypes.byref(overlapped), ctypes.byref(size), True)
                    self.on_data_received(bytes(buf[:size.value]))
            finally:
                if PipeHandlerBase.active_pipe_handler[tid] is self:
                    PipeHandlerBase.active_pipe_handler.pop(tid, None)

    def serve(self):
        try:
            self.on_connect()
            self._serve()
        except Exception as e:
            self.on_close(e)
        else:
            self.on_close(None)
        finally:
            try:
                kernel32.CloseHandle(self.handle)
            except Exception:
                pass

    def close(self, block=True):
        self.work = False
        kernel32.CloseHandle(self.handle)
        if block: self.serve_thread.join()

    def on_connect(self):
        pass

    def on_close(self, e: Exception | None):
        pass

    def on_data_received(self, data: bytes):
        pass


class PipeServerHandler(PipeHandlerBase):
    def __init__(self, server: 'PipeServer', handle, client_id):
        self.server = server
        self.handle = handle
        self.client_id = client_id
        self.buf_size = server.buf_size
        super().__init__()

    def serve(self):
        self.server.handlers[self.client_id] = self
        super().serve()
        self.server.handlers.pop(self.client_id, None)


class PipeServer(typing.Generic[_T]):
    handlers: typing.Dict[int, _T]

    def __init__(self, name, buf_size=64 * 1024, handler_class=PipeServerHandler):
        self.name = name
        self.buf_size = buf_size
        self.handler_class = handler_class
        self.serve_thread = threading.Thread(target=self.serve)
        self.client_counter = 0
        self.handlers = {}
        self.work = False

    def serve(self):
        self.work = True
        while self.work:
            handle = kernel32.CreateNamedPipe(
                self.name,
                0x3 | 0x40000000,  # PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
                0x4 | 0x2 | 0x0,  # PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
                255,  # PIPE_UNLIMITED_INSTANCES
                self.buf_size, self.buf_size, 0, None
            )
            kernel32.ConnectNamedPipe(handle, None)
            c = self.handler_class(self, handle, self.client_counter)
            c.buf_size = self.buf_size
            c.serve_thread.start()
            self.client_counter += 1

    def close(self):
        self.work = False

        while self.handlers:
            next_key = next(iter(self.handlers.keys()))
            self.handlers.pop(next_key).close(False)
        try:
            _FlushClient(self.name, timeout=1).serve()
        except TimeoutError:
            pass

    def send_all(self, s):
        for c in self.handlers.values():
            c.send(s)


class PipeClient(PipeHandlerBase):
    def __init__(self, name: str, buf_size=64 * 1024, timeout=0):
        self.name = name
        self.buf_size = buf_size
        self.timeout = timeout
        super().__init__()

    def _connect(self):
        start = time.perf_counter()
        while True:
            if self.timeout and time.perf_counter() - start > self.timeout:
                raise TimeoutError()
            try:
                self.handle = kernel32.CreateFile(
                    self.name,
                    0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                    0,  # 0x1 | 0x2,  # FILE_SHARE_READ | FILE_SHARE_WRITE
                    None,
                    0x3,  # OPEN_EXISTING
                    0x40000000,  # FILE_FLAG_OVERLAPPED
                    None
                )
            except WindowsError as e:
                if e.winerror == 0xe7:  # ERROR_PIPE_BUSY
                    time.sleep(1)
                    continue
                if e.winerror == 0x2:  # ERROR_FILE_NOT_FOUND
                    time.sleep(1)
                    continue
                raise
            else:
                break
        mode = ctypes.c_ulong(0x2)  # PIPE_READMODE_MESSAGE
        kernel32.SetNamedPipeHandleState(self.handle, ctypes.byref(mode), None, None)

    def serve(self):
        self._connect()
        super().serve()

    def connect(self):
        self.serve_thread.start()
        self.is_connected.wait()

    def __enter__(self):
        if not self.is_connected.is_set():
            self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class _FlushClient(PipeClient):
    def on_connect(self):
        self.close()


class _Rpc:
    CLIENT_CALL = 0
    CLIENT_SUBSCRIBE = 1
    CLIENT_UNSUBSCRIBE = 2

    SERVER_RETURN = 0
    SERVER_EVENT = 1

    RETURN_NORMAL = 0
    RETURN_EXCEPTION = 1
    RETURN_GENERATOR = 2
    RETURN_GENERATOR_END = 3

    REMOTE_TRACE_KEY = '_remote_trace'

    @classmethod
    def format_exc(cls, e):
        return getattr(e, cls.REMOTE_TRACE_KEY, None) or traceback.format_exc()

    @classmethod
    def set_exc(cls, e, tb):
        setattr(e, cls.REMOTE_TRACE_KEY, tb)
        return e


class RpcHandler(PipeServerHandler):
    server: 'RpcServer'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribed = set()

    def on_data_received(self, data: bytes):
        cmd, *arg = pickle.loads(data)
        if cmd == _Rpc.CLIENT_CALL:  # call
            threading.Thread(target=self.handle_call, args=arg).start()
        elif cmd == _Rpc.CLIENT_SUBSCRIBE:  # subscribe
            key, = arg
            if key not in self.subscribed:
                self.subscribed.add(key)
                self.server.add_subscribe(key, self.client_id)
        elif cmd == _Rpc.CLIENT_UNSUBSCRIBE:  # unsubscribe
            key, = arg
            if key in self.subscribed:
                self.subscribed.remove(key)
                self.server.remove_subscribe(key, self.client_id)

    def on_close(self, e: Exception | None):
        for k in self.subscribed:
            self.server.remove_subscribe(k, self.client_id)

    def handle_call(self, reply_id, key, arg, kwargs):
        try:
            res = self.server.call_map[key](*arg, *kwargs)
        except Exception as e:
            self.reply_call_exc(reply_id, e)
        else:
            if isinstance(res, types.GeneratorType):
                self.reply_call_gen(reply_id, res)
            else:
                self.reply_call_normal(reply_id, res)

    def reply_call_normal(self, reply_id, res):
        self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_NORMAL, res)))

    def reply_call_exc(self, reply_id, exc):
        self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_EXCEPTION, (exc, traceback.format_exc()))))

    def reply_call_gen(self, reply_id, gen):
        try:
            for res in gen:
                self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_GENERATOR, res)))
            self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_GENERATOR_END, None)))
        except Exception as e:
            self.reply_call_exc(reply_id, e)

    def send_event(self, event_id, event):
        self.send(pickle.dumps((_Rpc.SERVER_EVENT, event_id, event)))


class RpcServer(PipeServer[RpcHandler]):

    def __init__(self, name, call_map, *args, **kwargs):
        super().__init__(name, *args, handler_class=RpcHandler, **kwargs)
        self.subscribe_map = {}
        if isinstance(call_map, (tuple, list,)):
            call_map = {i.__name__: i for i in call_map}
        self.call_map = call_map

    def push_event(self, event_id, data):
        cids = self.subscribe_map.get(event_id, set())
        for cid in list(cids):
            if client := self.handlers.get(cid):
                client.send_event(event_id, data)
            else:
                try:
                    cids.remove(cid)
                except KeyError:
                    pass

    def add_subscribe(self, key, cid):
        if not (s := self.subscribe_map.get(key)):
            self.subscribe_map[key] = s = set()
        s.add(cid)

    def remove_subscribe(self, key, cid):
        if s := self.subscribe_map.get(key):
            try:
                s.remove(cid)
            except KeyError:
                pass
            if not s:
                self.subscribe_map.pop(key, None)


class Counter:
    def __init__(self, start=0):
        self.value = start
        self.lock = threading.Lock()

    def get(self):
        with self.lock:
            self.value += 1
            return self.value


class RpcClient(PipeClient):
    class ResEventList(typing.Generic[_T]):
        class ResEvent(threading.Event, typing.Generic[_T]):
            def __init__(self):
                super().__init__()
                self.res = None
                self.is_exc = False
                self.is_waiting = False

            def set(self, data: _T = None) -> None:
                assert not self.is_set()
                self.res = data
                self.is_exc = False
                super().set()

            def set_exception(self, exc) -> None:
                assert not self.is_set()
                self.res = exc
                self.is_exc = True
                super().set()

            def wait(self, timeout: float | None = None) -> _T:
                self.is_waiting = True
                try:
                    if super().wait(timeout):
                        if self.is_exc:
                            raise self.res
                        else:
                            return self.res
                    else:
                        raise TimeoutError()
                finally:
                    self.is_waiting = False

        queue: typing.List[ResEvent[_T]]

        def __init__(self):
            self.queue = [self.ResEvent()]
            self.lock = threading.Lock()

        def put(self, data: _T):
            with self.lock:
                if not self.queue or self.queue[-1].is_set():
                    self.queue.append(self.ResEvent())
                self.queue[-1].set(data)

        def get(self) -> _T:
            with self.lock:
                if not self.queue:
                    self.queue.append(self.ResEvent())
                evt = self.queue[0]
            res = evt.wait()
            with self.lock:
                if self.queue and self.queue[0] is evt:
                    self.queue.pop(0)
            return res

    reply_map: typing.Dict[int, ResEventList]
    logger = logging.getLogger('RpcClient')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reply_map = {}
        self.subscribe_map = {}
        self.counter = Counter()

        class Rpc:
            def __getattr__(_self, item):
                def func(*_args, **_kwargs):
                    return self.remote_call(item, _args, _kwargs)

                func.__name__ = item
                return func

        self.rpc = Rpc()

    def on_data_received(self, data: bytes):
        cmd, *args = pickle.loads(data)
        if cmd == _Rpc.SERVER_RETURN:
            reply_id, reply_type, res = args
            if l := self.reply_map.get(reply_id):
                l.put((reply_type, res))
        elif cmd == _Rpc.SERVER_EVENT:
            key, data = args
            s = self.subscribe_map.get(key, set())
            if s:
                for c in s:
                    try:
                        c(key, data)
                    except Exception as e:
                        self.logger.error(f'error in rpc client [{self.name}] event', exc_info=e)
            else:
                self.send(pickle.dumps((_Rpc.CLIENT_UNSUBSCRIBE, key)))

    def subscribe(self, key, call):
        if key not in self.subscribe_map:
            self.subscribe_map[key] = set()
            self.send(pickle.dumps((_Rpc.CLIENT_SUBSCRIBE, key)))
        self.subscribe_map[key].add(call)

    def unsubscribe(self, key, call):
        s = self.subscribe_map.get(key, set())
        try:
            s.remove(call)
        except KeyError:
            pass
        if not s:
            self.subscribe_map.pop(key, None)
            self.send(pickle.dumps((_Rpc.CLIENT_UNSUBSCRIBE, key)))

    def res_iterator(self, reply_id, evt_list, first_res):
        try:
            yield first_res
            while True:
                reply_type, res = evt_list.get()
                if reply_type == _Rpc.RETURN_EXCEPTION: raise _Rpc.set_exc(*res)
                if reply_type == _Rpc.RETURN_GENERATOR_END: break
                yield res
        finally:
            self.reply_map.pop(reply_id, None)

    def remote_call(self, key, args, kwargs):
        if not self.is_connected.is_set():
            self.connect()
        reply_id = self.counter.get()
        self.reply_map[reply_id] = evt_list = self.ResEventList()
        self.send(pickle.dumps((_Rpc.CLIENT_CALL, reply_id, key, args, kwargs)))
        reply_type, res = evt_list.get()
        if reply_type == _Rpc.RETURN_NORMAL:  # normal
            self.reply_map.pop(reply_id, None)
            return res
        if reply_type == _Rpc.RETURN_EXCEPTION:  # exc
            self.reply_map.pop(reply_id, None)
            raise _Rpc.set_exc(*res)
        if reply_type == _Rpc.RETURN_GENERATOR:  # generator
            return self.res_iterator(reply_id, evt_list, res)
        if reply_type == _Rpc.RETURN_GENERATOR_END:  # end of generator
            self.reply_map.pop(reply_id, None)

            def empty_iterator(): yield from ()

            return empty_iterator()


class Mutex:
    fp = None

    def __init__(self, name):
        self.name = pathlib.Path(name).absolute()

    def is_lock(self):
        if not self.name.exists(): return False
        with open(self.name, 'wb') as tmp:
            tmp.seek(0)
            try:
                msvcrt.locking(tmp.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                return True
            else:
                msvcrt.locking(tmp.fileno(), msvcrt.LK_UNLCK, 1)
                return False

    def acquire(self):
        self.fp = open(self.name, 'wb')
        self.fp.seek(0)
        msvcrt.locking(self.fp.fileno(), msvcrt.LK_LOCK, 1)

    def release(self):
        self.fp.seek(0)
        msvcrt.locking(self.fp.fileno(), msvcrt.LK_UNLCK, 1)
        self.fp.close()
        self.name.unlink()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, _type, value, tb):
        self.release()


def wait_until(func, timeout=-1, interval=0.1, *args, **kwargs):
    start = time.perf_counter()
    while not func(*args, **kwargs):
        if 0 < timeout < time.perf_counter() - start:
            raise TimeoutError
        time.sleep(interval)


class Process:
    class Namespace:
        chunk_size = 0x10000

        def __init__(self, process: 'Process'):
            self.process = process
            self.res = []
            self.ptr = 0
            self.remain = 0
            self._protection = 0x40  # PAGE_EXECUTE_READWRITE

        @property
        def protection(self):
            return self._protection

        @protection.setter
        def protection(self, v):
            self._protection = v
            for alloc_addr, alloc_size in self.res:
                self.process.virtual_protect(alloc_addr, alloc_size, v)

        def store(self, data: bytes):
            self.process.write(p_buf := self.take(len(data)), data)
            return p_buf

        def take(self, size):
            size = _aligned16(size)
            if self.remain < size:
                alloc_size = max(self.chunk_size, size)
                alloc_addr = self.process.alloc(alloc_size)
                self.res.append((alloc_addr, alloc_size))
                self.process.virtual_protect(alloc_addr, alloc_size, self.protection)
                self.remain = alloc_size - size
                self.ptr = alloc_addr + size
                return alloc_addr
            else:
                self.remain -= size
                res = self.ptr
                self.ptr += size
                return res

        def free(self):
            while self.res:
                self.process.free(*self.res.pop())

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.free()

    class MemoryPatternScanner(IPatternScanner):
        def __init__(self, process: 'Process', region_address, region_size):
            self.process = process
            self.region_address = region_address
            self.region_size = region_size

        def get_raw(self):
            return self.process.read(self.region_address, self.region_size)

        def search(self, pattern: str | Pattern) -> typing.Generator[tuple[int, list[int]], None, None]:
            if isinstance(pattern, str):  pattern = _Pattern.compile_pattern(pattern)
            for offset, args in pattern.finditer(self.get_raw()):
                yield self.region_address + offset, [a + self.region_address if r else a for a, r in zip(args, pattern.res_is_ref)]

    class CachedRawMemoryPatternScanner(MemoryPatternScanner):
        def __init__(self, *a):
            super().__init__(*a)
            self._cached_raw = None

        def get_raw(self):
            if self._cached_raw is None:
                self._cached_raw = super().get_raw()
            return self._cached_raw

    class Injector:
        logger = logging.getLogger('Injector')

        def __init__(self, process: 'Process'):
            self.process = process
            self.pipe_name = rf'\\.\\pipe\\NyLibInjectPipe-pid-{self.process.process_id}'
            tmp_dir = pathlib.Path(os.environ['TEMP'])
            self.exc_file = tmp_dir / f'NyLibInjectErr{self.process.process_id}-{time.time()}.txt'
            self.lock_file = Mutex(tmp_dir / f'NyLibInjectLock-{self.process.process_id}.lck')
            self.client = RpcClient(self.pipe_name)
            self.is_starting_server = False
            self.paths = []

        def reg_std_out(self, func):
            self.client.subscribe('__std_out__', func)

        def unreg_std_out(self, func):
            self.client.unsubscribe('__std_out__', func)

        def reg_std_err(self, func):
            self.client.subscribe('__std_err__', func)

        def unreg_std_err(self, func):
            self.client.unsubscribe('__std_err__', func)

        def is_active(self):
            return self.lock_file.is_lock()

        def is_python_load(self):
            try:
                self.process.get_python_base()
            except KeyError:
                return False
            return True

        def start_server(self):
            assert not self.is_active()
            self.is_starting_server = True
            shell_code = f'''
def run_rpc_server_main():
    import threading
    import injector

    res_id_counter = injector.Counter()
    pipe_name = {repr(self.pipe_name)}
    lock_file_name = {repr(str(self.lock_file.name))}
    def run_call(code, args, res_key='res', filename="<rpc>"):
        exec(compile(code, filename, 'exec'), namespace := {{'inject_server': server, 'args': args, '__file__': filename}})
        return namespace.get(res_key)

    server = injector.RpcServer(pipe_name, {{"run": run_call}})
    sys.stdout = type('_rpc_stdout', (), {{'write': lambda _, data: server.push_event('__std_out__', data), 'flush': lambda *_: None}})()
    sys.stderr = type('_rpc_stderr', (), {{'write': lambda _, data: server.push_event('__std_err__', data), 'flush': lambda *_: None}})()
    import logging
    for handler in logging.root.handlers[:]:
        handler.stream = sys.stdout
    mutex = injector.Mutex(lock_file_name)
    if not mutex.is_lock():
        setattr(sys, '__inject_server__', server)
        with mutex: server.serve()
import traceback
import ctypes
try:
    import sys
    sys.path = {repr(sys.path + self.paths)} + sys.path
    run_rpc_server_main()
except:
    ctypes.windll.user32.MessageBoxW(0, 'error:\\n'+traceback.format_exc() ,'error' , 0x40010)
    with open({repr(str(self.exc_file))},'w',encoding='utf-8') as f:
        f.write(traceback.format_exc())
'''
            compile(shell_code, 's', 'exec')
            self.process.exec_shell_code(shell_code, auto_inject=True)
            if self.exc_file.exists():
                self.logger.error('error occurred in injection:\n' + self.exc_file.read_text('utf-8'))
                self.exc_file.unlink(missing_ok=True)
            self.is_starting_server = False

        def wait_inject(self):
            if not self.is_active():
                self.logger.debug(f"python base {self.process.get_python_base(True):#x}")
                if not self.is_starting_server:
                    threading.Thread(target=self.start_server, daemon=True).start()
                time.sleep(.1)
                wait_until(self.is_active, timeout=10)

            if not self.client.is_connected.is_set():
                self.client.connect()

        def add_path(self, path):
            path = str(path)
            if self.is_active():
                self.run(f'import sys;\nif {path!r} not in sys.path:\n  sys.path.append({path!r})')
            else:
                self.paths.append(path)
            return self

        def run(self, code, *args, res_key='res', filename="<rpc>"):
            self.wait_inject()
            return self.client.rpc.run(code, args, res_key, filename)

    current: 'Process'

    def __init__(self, process_id: int):
        self.process_id = process_id
        self.handle = kernel32.OpenProcess(0x1F0FFF, False, process_id)
        self._cached_scanners = {}
        self._ldr_cache = {}

    @classmethod
    def from_name(cls, name: str | bytes):
        if (pid := next(pid_by_executable(name), None)) is None:
            raise ValueError(f'Process {name!r} not found')
        return cls(pid)

    def alloc(self, size: int, protect=0x40, address=0):
        return kernel32.VirtualAllocEx(self.handle, address, size, 0x1000 | 0x2000, protect)  # MEM_COMMIT|MEM_RESERVE

    def free(self, address: int, size: int):
        return kernel32.VirtualFreeEx(self.handle, address, size, 0x4000)  # MEM_DECOMMIT

    def virtual_query(self, address: int):
        kernel32.VirtualQueryEx(self.handle, address, ctypes.byref(mbi := MEMORY_BASIC_INFORMATION()), ctypes.sizeof(mbi))
        return mbi

    def virtual_protect(self, address: int, size: int, protect: int):
        return kernel32.VirtualProtectEx(self.handle, address, size, protect, ctypes.byref(ctypes.c_ulong()))

    def iter_memory_region(self, start=0, end=None):
        pos = start
        while mbi := self.virtual_query(pos):
            yield mbi
            next_addr = mbi.BaseAddress + mbi.RegionSize
            if pos >= next_addr or end is not None and end < next_addr: break
            pos = next_addr

    def alloc_near(self, size: int, address, protect=0x40):
        for mbi in self.iter_memory_region(max(address - 0x7fff0000, 0), address + 0x7fff0000):
            if mbi.State & 0x10000:  # MEM_FREE
                pos = (mbi.BaseAddress + 0xffff) & ~0xffff
                if mbi.RegionSize - (pos - mbi.BaseAddress) >= size:
                    return self.alloc(size, protect, pos)
        raise ValueError("No suitable memory region")

    def read(self, address, type_: typing.Type[_T] | int) -> _T:
        if isinstance(type_, int):
            value = (ctypes.c_ubyte * type_)()
            try:
                kernel32.ReadProcessMemory(self.handle, address, ctypes.byref(value), type_, None)
            except WindowsError as e:
                if e.winerror != 299: raise
            return bytes(value)
        value = type_()
        kernel32.ReadProcessMemory(self.handle, address, ctypes.byref(value), ctypes.sizeof(value), None)
        return value

    def write(self, address, value):
        if isinstance(value, (bytes, bytearray)):
            if isinstance(value, bytes): value = bytearray(value)
            size = len(value)
            value = (ctypes.c_ubyte * size).from_buffer(value)
        size = ctypes.sizeof(value)
        kernel32.WriteProcessMemory(self.handle, address, ctypes.byref(value), size, None)
        return size

    def read_i8(self, address: int) -> int:
        return self.read(address, ctypes.c_byte).value

    def read_i16(self, address: int) -> int:
        return self.read(address, ctypes.c_short).value

    def read_i32(self, address: int) -> int:
        return self.read(address, ctypes.c_int).value

    def read_i64(self, address: int) -> int:
        return self.read(address, ctypes.c_longlong).value

    def read_u8(self, address: int) -> int:
        return self.read(address, ctypes.c_ubyte).value

    def read_u16(self, address: int) -> int:
        return self.read(address, ctypes.c_ushort).value

    def read_u32(self, address: int) -> int:
        return self.read(address, ctypes.c_uint).value

    def read_u64(self, address: int) -> int:
        return self.read(address, ctypes.c_ulonglong).value

    def read_float(self, address: int) -> float:
        return self.read(address, ctypes.c_float).value

    def read_double(self, address: int) -> float:
        return self.read(address, ctypes.c_double).value

    def write_i8(self, address: int, value: int):
        return self.write(address, ctypes.c_byte(value))

    def write_i16(self, address: int, value: int):
        return self.write(address, ctypes.c_short(value))

    def write_i32(self, address: int, value: int):
        return self.write(address, ctypes.c_int(value))

    def write_i64(self, address: int, value: int):
        return self.write(address, ctypes.c_longlong(value))

    def write_u8(self, address: int, value: int):
        return self.write(address, ctypes.c_ubyte(value))

    def write_u16(self, address: int, value: int):
        return self.write(address, ctypes.c_ushort(value))

    def write_u32(self, address: int, value: int):
        return self.write(address, ctypes.c_uint(value))

    def write_u64(self, address: int, value: int):
        return self.write(address, ctypes.c_ulonglong(value))

    def write_float(self, address: int, value: float):
        return self.write(address, ctypes.c_float(value))

    def write_double(self, address: int, value: float):
        return self.write(address, ctypes.c_double(value))

    def read_ptr(self, address: int):
        return self.read(address, ctypes.c_size_t).value

    def write_ptr(self, address: int, value: int):
        return self.write(address, ctypes.c_size_t(value))

    def read_bytes_zero_trim_unk_size(self, address: int, chunk_size=0x100):
        mbi = self.virtual_query(address)
        max_addr = mbi.BaseAddress + mbi.RegionSize
        buf = bytearray()
        while address < max_addr:
            read_size = min(chunk_size, max_addr - address)
            _buf = self.read(address, read_size)
            if (sep := _buf.find(b'\0')) >= 0:
                buf.extend(_buf[:sep])
                break
            buf.extend(_buf)
            address += read_size
        return bytes(buf)

    def read_bytes_zero_trim(self, address: int, max_size: int = 0):
        if max_size == 0:
            return self.read_bytes_zero_trim_unk_size(address)
        res = self.read(address, max_size)
        if (sep := res.find(b'\0')) >= 0:
            return res[:sep]
        return res

    def read_string(self, address: int, max_size: int = 0, encoding='utf-8'):
        return self.read_bytes_zero_trim(address, max_size).decode(encoding)

    def write_string(self, address: int, value: str | bytes, encoding='utf-8'):
        if isinstance(value, str): value = value.encode(encoding)
        return self.write(address, value)

    def remote_memory(self, size: int):
        return self.RemoteMemory(self, size)

    def name_space(self):
        return self.Namespace(self)

    def enum_ldr_data(self):
        pbi = PROCESS_BASIC_INFORMATION()
        ntdll.NtQueryInformationProcess(self.handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
        peb = self.read(pbi.PebBaseAddress, PEB)
        ldr = self.read(peb.Ldr, PEB_LDR_DATA)
        p_data = p_end = ldr.InMemoryOrderModuleList.Flink
        offset = LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.offset
        while True:
            data = self.read(p_data - offset, LDR_DATA_TABLE_ENTRY)
            if data.DllBase:
                yield data
            p_data = data.InMemoryOrderLinks.Flink
            if p_data == p_end: break

    @functools.cached_property
    def base_ldr_data(self):
        return next(self.enum_ldr_data())

    def get_ldr_data(self, dll_name: str, rescan=False):
        dll_name = dll_name.lower()
        if dll_name in self._ldr_cache and not rescan:
            return self._ldr_cache[dll_name]
        self._ldr_cache.pop(dll_name, None)
        for data in self.enum_ldr_data():
            if data.BaseDllName.remote_value(self).lower() == dll_name:
                self._ldr_cache[dll_name] = data
                return data
        raise KeyError(f'dll {dll_name!r} not found')

    def scanner(self, dll_name: str, force_new=False):
        if dll_name not in self._cached_scanners or force_new:
            for data in self.enum_ldr_data():
                if data.BaseDllName.remote_value(self) == dll_name:
                    self._cached_scanners[dll_name] = self.CachedRawMemoryPatternScanner(self, data.DllBase, data.SizeOfImage)
                    break
            else:
                raise KeyError(f'dll {dll_name!r} not found')
        return self._cached_scanners[dll_name]

    def base_scanner(self, force_new=False):
        return self.scanner(self.base_ldr_data.BaseDllName.remote_value(self), force_new)

    def get_proc_address(self, dll: str | int, func_name: str):
        if isinstance(func_name, str): func_name = func_name.encode(DEFAULT_CODING)
        if isinstance(dll, str): dll = self.get_ldr_data(dll).DllBase
        return kernel32.GetProcAddress(dll, func_name)

    def load_library(self, filepath):
        if isinstance(filepath, pathlib.Path): filepath = str(filepath)
        if isinstance(filepath, str): filepath = filepath.encode(DEFAULT_CODING)
        with self.name_space() as name_space:
            result_at = name_space.take(0x10)
            shell = (
                    b"\x55"  # push rbp
                    b"\x48\x89\xe5"  # mov rbp, rsp
                    b"\x48\x83\xec\x28"  # sub rsp, 0x28
                    b"\x53"  # push rbx
                    b"\x48\xbb" + struct.pack('<Q', result_at) +  # movabs rbx, result_at
                    b"\x48\xb8" + struct.pack('<Q', self.get_proc_address('kernel32.dll', "LoadLibraryA")) +  # movabs rax, LoadLibraryA
                    b"\x48\xb9" + struct.pack('<Q', name_space.store(filepath + b'\0')) +  # movabs rcx, filepath
                    b"\xff\xd0"  # call rax
                    b"\x48\x85\xc0"  # test rax, rax
                    b"\x74\x0c"  # je fail
                    b"\x48\x89\x43\x08"  # mov qword ptr [rbx + 8], rax
                    b"\x48\x31\xc0"  # xor rax, rax
                    b"\x48\x89\x03"  # mov qword ptr [rbx], rax
                    b"\xeb\x16"  # jmp end
                    # fail:
                    b"\x48\xb8" + struct.pack('<Q', self.get_proc_address('kernel32.dll', "GetLastError")) +  # movabs rax, GetLastError
                    b"\xff\xd0"  # call rax
                    b"\x48\x89\x03"  # mov qword ptr [rbx], rax
                    b"\x48\x31\xc0"  # xor rax, rax
                    b"\x48\x89\x43\x08"  # mov qword ptr [rbx + 8], rax
                    # end:
                    b"\x5b"  # pop rbx
                    b"\x48\x83\xc4\x28"  # add rsp, 0x28
                    b"\x5d"  # pop rbp
                    b"\xc3"  # ret
            )
            self._call(name_space.store(shell), block=True)
            if err := self.read_u32(result_at): raise ctypes.WinError(err)
            return self.read_u64(result_at + 8)

    def _call(self, call_address, params=None, block=True):
        params = params or 0
        thread_h = kernel32.CreateRemoteThread(self.handle, None, 0, call_address, params, 0, None)
        if block: kernel32.WaitForSingleObject(thread_h, -1)
        return thread_h

    def call(self, func_ptr, *args: int | float | bytes | bool, push_stack_depth=0x28, block=True):
        _MOV_RBX = b'\x48\xBB'  # MOV rbx, n
        _INT_ARG = (
            b'\x48\xB9',  # MOV rcx, n
            b'\x48\xBA',  # MOV rdx, n
            b'\x49\xB8',  # MOV r8, n
            b'\x49\xB9',  # MOV r9, n
        )
        _FLOAT_ARG = (
            b'\xF3\x0F\x10\x03',  # MOVSS xmm0, [rbx]
            b'\xF3\x0F\x10\x0B',  # MOVSS xmm1, [rbx]
            b'\xF3\x0F\x10\x13',  # MOVSS xmm2, [rbx]
            b'\xF3\x0F\x10\x1B',  # MOVSS xmm3, [rbx]
        )

        if len(args) > 4:
            raise ValueError('not yet handle args more then 4')
        with self.name_space() as name_space:
            return_address = name_space.take(8)
            shell = (
                    b"\x55"  # PUSH rbp
                    b"\x48\x89\xE5"  # MOV rbp, rsp
                    b"\x48\x83\xec" + struct.pack('B', push_stack_depth) +  # SUB rsp, push_stack_depth
                    b"\x53"  # PUSH rbx
                    b"\x48\x31\xDB"  # XOR rbx, rbx
            )
            for i, a in enumerate(args):
                if isinstance(a, bytes):
                    a = name_space.store(a)
                elif isinstance(a, bool):
                    a = int(a)
                if isinstance(a, int):
                    shell += _INT_ARG[i] + struct.pack('q', a)
                elif isinstance(a, float):
                    shell += _MOV_RBX + struct.pack('f', a) + bytes(4) + _FLOAT_ARG[i]
                else:
                    raise TypeError(f'not support arg type {type(a)} at pos {i}')
            shell += (
                    b"\x48\xBB" + struct.pack('q', func_ptr) +  # MOV rbx, func_ptr
                    b"\xFF\xD3"  # CALL rbx
                    b"\x48\xBB" + struct.pack('q', return_address) +  # MOV rbx, return_address
                    b"\x48\x89\x03"  # MOV [rbx], rax
                    b"\x5B"  # POP rbx
                    b"\x48\x83\xc4" + struct.pack('B', push_stack_depth) +  # ADD rsp, 0x28
                    b"\x48\x89\xEC"  # MOV rsp, rbp
                    b"\x5D"  # POP rbp
                    b"\xC3"  # RET
            )
            code_address = name_space.store(shell)
            self._call(code_address, block=block)
            return self.read_u64(return_address)

    @functools.cache
    def _get_pyfunc_offset(self, func_name):
        c = Process.current
        ldr = c.get_ldr_data(PYTHON_DLL)
        base = ldr.DllBase
        return c.get_proc_address(base, func_name) - base

    def get_python_base(self, auto_inject=False):
        try:
            return self.get_ldr_data(PYTHON_DLL).DllBase
        except KeyError:
            if auto_inject:
                base = self.load_library(Process.current.get_ldr_data(PYTHON_DLL).FullDllName.value)
                self.call(base + self._get_pyfunc_offset("Py_Initialize"), 1, push_stack_depth=0x58)
                return base
            raise

    def exec_shell_code(self, code: str, p_dict=None, auto_inject=False):
        py_base = self.get_python_base(auto_inject)
        need_decref = False
        if p_dict is None:
            p_dict = self.call(py_base + self._get_pyfunc_offset("PyDict_New"))
            need_decref = True

        with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as f:
            f.write(code)
            f.close()
            res = self.call(py_base + self._get_pyfunc_offset("PyRun_String"), f'with open({f.name!r},encoding="utf-8") as f:exec(f.read())'.encode('utf-8'), 0x101, p_dict, p_dict)

        if not res:
            if error_occurred := self.call(py_base + self._get_pyfunc_offset("PyErr_Occurred")):
                type_name = self.read_string(self.read_ptr(error_occurred + 0x18))
                with self.name_space() as ns:
                    p_data = ns.take(0x18)
                    self.call(py_base + self._get_pyfunc_offset("PyErr_Fetch"), p_data, p_data + 0x8, p_data + 0x10)
                    exc_val = self.read_ptr(p_data + 0x8)
                    desc = None
                    if exc_val:
                        py_str = self.call(py_base + self._get_pyfunc_offset("PyObject_Str"), exc_val)
                        str_size = ns.take(8)
                        if p_str := self.call(py_base + self._get_pyfunc_offset("PyUnicode_AsUTF8AndSize"), py_str, str_size):
                            desc = self.read_string(p_str, self.read_u64(str_size))
                            # decref(py_str)
                        # decref(exc_val)
                    # decref(error_occurred)
                    if desc:
                        raise RuntimeError(f"Exception in shell: {type_name}: {desc}")
                    else:
                        raise RuntimeError(f"Exception in shell: {type_name}")
            else:
                raise RuntimeError(f"Exception in shell but no error occurred")
        else:
            pass  # decref(res)
        if need_decref:
            pass  # decref(p_dict)

    @functools.cached_property
    def injector(self):
        return self.Injector(self)


Process.current = Process(kernel32.GetCurrentProcessId())


class Hook:
    class HOOK_TRACE_INFO(ctypes.Structure):
        _fields_ = [("Link", ctypes.c_void_p)]

    class EasyHookException(Exception):
        def __init__(self):
            self.code = Hook.rtl_get_last_error()
            self.err_msg = Hook.rtl_get_last_error_string()

        def __str__(self):
            return f"EasyHookException {self.code:#X}:{self.err_msg}"

    dll = ctypes.cdll.LoadLibrary(ctypes.util.find_library(str(
        pathlib.Path(__file__).parent / 'EasyHook64.dll'
    )))
    lh_install_hook = _win_api(dll.LhInstallHook, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p))
    lh_uninstall_hook = _win_api(dll.LhUninstallHook, ctypes.c_ulong, (ctypes.c_void_p,))
    lh_uninstall_all_hooks = _win_api(dll.LhUninstallAllHooks, ctypes.c_ulong)
    rtl_get_last_error = _win_api(dll.RtlGetLastError, ctypes.c_ulong)
    rtl_get_last_error_string = _win_api(dll.RtlGetLastErrorString, ctypes.c_wchar_p)
    lh_set_inclusive_acl = _win_api(dll.LhSetInclusiveACL, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p))
    lh_set_exclusive_acl = _win_api(dll.LhSetExclusiveACL, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p))
    lh_get_bypass_address = _win_api(dll.LhGetHookBypassAddress, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_void_p))
    lh_wait_for_pending_removals = _win_api(dll.LhWaitForPendingRemovals, ctypes.c_ulong)

    def __init__(self, at: int, hook_func, restype: typing.Any = ctypes.c_void_p, argtypes=()):
        self.at = at
        self.interface = ctypes.CFUNCTYPE(restype, *argtypes)
        self.hook_func = hook_func

        self._enabled = False
        self._installed = False
        self.hook_info = self.HOOK_TRACE_INFO()
        self._hook_function = self.interface(lambda *args: self.hook_func(self, *args))
        self.call = self.interface(at)
        self.original = None
        self.ACL_entries = (ctypes.c_ulong * 1)(1)

    def install(self):
        if self._installed: return
        if self.lh_install_hook(self.at, self._hook_function, None, ctypes.byref(self.hook_info)):
            raise self.EasyHookException()
        self._installed = True

        original_func_p = ctypes.c_void_p()
        if self.lh_get_bypass_address(ctypes.byref(self.hook_info), ctypes.byref(original_func_p)):
            raise self.EasyHookException()
        self.original = self.interface(original_func_p.value)
        return self

    def uninstall(self):
        if not self._installed: return
        self.lh_uninstall_hook(ctypes.byref(self.hook_info))
        self.lh_wait_for_pending_removals()
        self._installed = False
        return self

    def enable(self):
        if not self._installed: return
        if self.lh_set_exclusive_acl(ctypes.byref(self.ACL_entries), 1, ctypes.byref(self.hook_info)):
            raise self.EasyHookException()
        self._enabled = True
        return self

    def disable(self):
        if not self._installed: return
        if self.lh_set_inclusive_acl(ctypes.byref(self.ACL_entries), 1, ctypes.byref(self.hook_info)):
            raise self.EasyHookException()
        self._enabled = False
        return self

    def install_and_enable(self):
        return self.install().enable()

    def __del__(self):
        self.uninstall()

    def __call__(self, *args):
        return self.call(*args)


def run_admin():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin(): return
    except:
        pass
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    raise PermissionError("Need admin permission, a new process should be started, if not, please run it as admin manually")


def get_server() -> RpcServer:
    return getattr(sys, '__inject_server__')


size_t_from = Process.current.read_ptr  # ctypes.c_size_t.from_address(a).value
i8_from = Process.current.read_i8  # lambda a: ctypes.c_int8.from_address(a).value
i32_from = Process.current.read_i32  # lambda a: ctypes.c_int32.from_address(a).value
u32_from = Process.current.read_u32  # lambda a: ctypes.c_uint32.from_address(a).value
u64_from = Process.current.read_u64  # lambda a: ctypes.c_uint64.from_address(a).value
v_func = lambda a, off: size_t_from(size_t_from(a) + off)

i_actor_0x50 = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t)
i_actor_0x58 = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t)


@functools.cache
def actor_base_name(a1):
    i_actor_0x50(v_func(a1, 0x50))(a1, ctypes.addressof(type_name := ctypes.c_char_p()))
    return type_name.value.decode()


@functools.cache
def actor_type_id(a1):
    i_actor_0x58(v_func(a1, 0x58))(a1, ctypes.addressof(val := ctypes.c_uint32()))
    return val.value


@functools.cache
def actor_idx(a1):
    return u32_from(a1 + 0x170)


def ensure_same(args):
    if len(s := set(args)) != 1: raise ValueError(f'not same {args=}')
    return s.pop()


class Act:
    _sys_key = '_act_'

    def __init__(self):
        self.server = get_server()
        scanner = Process.current.base_scanner()

        p_process_damage_evt, = scanner.find_val('e8 * * * * 66 83 bc 24 ? ? ? ? ?')
        self.process_damage_evt_hook = Hook(p_process_damage_evt, self._on_process_damage_evt, ctypes.c_size_t, [
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_uint8
        ])

        p_process_dot_evt, = ensure_same(map(tuple, scanner.find_vals('44 89 74 24 ? 48 ? ? ? ? 48 ? ? e8 * * * * 4c ? ? ? ? ? ?')))
        self.process_dot_evt_hook = Hook(p_process_dot_evt, self._on_process_dot_evt, ctypes.c_size_t, [
            ctypes.c_size_t,
            ctypes.c_size_t
        ])

        p_on_enter_area, = scanner.find_val('e8 * * * * c5 ? ? ? c5 f8 29 45 ? c7 45 ? ? ? ? ?')
        self.on_enter_area_hook = Hook(p_on_enter_area, self._on_enter_area, ctypes.c_size_t, [
            ctypes.c_uint,
            ctypes.c_size_t,
            ctypes.c_uint8
        ])

        self.i_a1_0x40 = ctypes.CFUNCTYPE(
            ctypes.c_uint32,
            ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t
        )

        self.p_qword_1467572B0, = scanner.find_val("48 ? ? * * * * 83 66 ? ? 48 ? ?")

        self.i_ui_comp_name = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_size_t)
        self.team_map = None

    def actor_data(self, a1):
        return actor_base_name(a1), actor_idx(a1), actor_type_id(a1), self.team_map.get(a1, -1) if self.team_map else -1

    def build_team_map(self):
        if self.team_map is not None: return
        res = {}
        qword_1467572B0 = size_t_from(self.p_qword_1467572B0)
        p_party_base = size_t_from(qword_1467572B0 + 0x20)
        p_party_tbl = size_t_from(p_party_base + 0x10 * (size_t_from(qword_1467572B0 + 0x38) & 0x6C4F1B4D) + 8)
        if p_party_tbl != size_t_from(qword_1467572B0 + 0x10) and (p_party_data := size_t_from(p_party_tbl + 0x30)):
            party_start = size_t_from(p_party_data + 0x18)
            party_end = size_t_from(p_party_data + 0x20)
            for i, p_data in enumerate(range(party_start, party_end, 0x10)):
                a1 = size_t_from(p_data + 8)
                if (self.i_ui_comp_name(v_func(a1, 0x8))(a1) == b'ui::component::ControllerPlParameter01' and
                        (p_actor := size_t_from(a1 + 0x5D0))):
                    p_actor_data = size_t_from(p_actor + 0x70)
                    res[p_actor_data] = i
                    print(f'[{i}] {p_actor=:#x}')
        self.team_map = res

    def _on_process_damage_evt(self, hook, a1, a2, a3, a4):
        source = target = 0
        try:
            self.build_team_map()
            target = size_t_from(size_t_from(a1 + 8))
            source = size_t_from(size_t_from(a2 + 0x18) + 0x70)
            flag = not (a4 or self.i_a1_0x40(v_func(a1, 0x40))(a1, a2, 0, target, source))
        except:
            logging.error('on_process_damage_evt', exc_info=True)
            flag = True
        res = hook.original(a1, a2, a3, a4)
        if flag: return res
        try:
            dmg = i32_from(a2 + 0xd0)
            flags_ = u64_from(a2 + 0xd8)
            if (1 << 7 | 1 << 50) & flags_:
                action_id = -1  # link attack
            elif (1 << 13 | 1 << 14) & flags_:
                action_id = -2  # limit break
            else:
                action_id = u32_from(a2 + 0x154)
            self._on_damage(source, target, dmg, flags_, action_id)
        except:
            logging.error('on_process_damage_evt', exc_info=True)
        return res

    def _on_process_dot_evt(self, hook, a1, a2):
        res = hook.original(a1, a2)
        try:
            dmg = i32_from(a2)
            target = size_t_from(size_t_from(a1 + 0x18) + 0x70)
            source = size_t_from(size_t_from(a1 + 0x30) + 0x70)
            self._on_damage(source, target, dmg, 0, -0x100)
        except:
            logging.error('on_process_dot_evt', exc_info=True)
        return res

    def _on_enter_area(self, hook, a1, a2, a3):
        res = hook.original(a1, a2, a3)
        try:
            self.team_map = None
            actor_base_name.cache_clear()
            actor_type_id.cache_clear()
            actor_idx.cache_clear()
            self.on_enter_area()
        except:
            logging.error('on_enter_area', exc_info=True)
        return res

    def _on_damage(self, source, target, damage, flags, action_id):
        # TODO: 找个通用方法溯源
        source_type_id = actor_type_id(source)
        if source_type_id == 0x2af678e8:  # 菲莉宝宝 # Pl0700Ghost
            source = size_t_from(size_t_from(source + 0xE48) + 0x70)
        elif source_type_id == 0x8364c8bc:  # 菲莉 绕身球  # Pl0700GhostSatellite
            source = size_t_from(size_t_from(source + 0x508) + 0x70)
        elif source_type_id == 0xc9f45042:  # 老男人武器
            source = size_t_from(size_t_from(source + 0x578) + 0x70)
        elif source_type_id == 0xf5755c0e:  # 龙人化
            source = size_t_from(size_t_from(source + 0xD028) + 0x70)
        return self.on_damage(self.actor_data(source), self.actor_data(target), damage, flags, action_id)

    def on_damage(self, source, target, damage, flags, action_id):
        pass

    def on_enter_area(self):
        pass

    def install(self):
        assert not hasattr(sys, self._sys_key), 'Act already installed'
        self.process_damage_evt_hook.install_and_enable()
        self.process_dot_evt_hook.install_and_enable()
        self.on_enter_area_hook.install_and_enable()
        setattr(sys, self._sys_key, self)
        return self

    def uninstall(self):
        assert getattr(sys, self._sys_key, None) is self, 'Act not installed'
        self.process_damage_evt_hook.uninstall()
        self.process_dot_evt_hook.uninstall()
        self.on_enter_area_hook.uninstall()
        delattr(sys, self._sys_key)
        return self

    @classmethod
    def get_or_create(cls):
        if hasattr(sys, cls._sys_key):
            return getattr(sys, cls._sys_key)
        return cls().install()

    @classmethod
    def remove(cls):
        if hasattr(sys, cls._sys_key):
            getattr(sys, cls._sys_key).uninstall()

    @classmethod
    def reload(cls):
        cls.remove()
        return cls.get_or_create()


class TestAct(Act):
    lock = threading.Lock()

    def on_damage(self, source, target, damage, flags, action_id):
        with self.lock:
            print(f'{source} -> {target} {action_id=} {damage=} {flags=}')

    def on_enter_area(self):
        with self.lock:
            print('on_enter_area')


def injected_main():
    print(f'i am in pid={os.getpid()}')
    TestAct.reload()
    print('Act installed')


def main(exe_name):
    run_admin()
    enable_privilege()
    process = Process.from_name(exe_name)
    process.injector.wait_inject()
    process.injector.reg_std_out(lambda _, s: print(s, end=''))
    process.injector.reg_std_err(lambda _, s: print(s, end=''))
    process.injector.run("import importlib;import injector;importlib.reload(injector).injected_main()")


if __name__ == '__main__':
    main('granblue_fantasy_relink.exe')
