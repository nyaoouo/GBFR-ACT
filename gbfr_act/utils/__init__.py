import ctypes.wintypes
import pathlib
import sys
import threading

import time

import msvcrt

from .native import *


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


class Counter:
    def __init__(self, start=0):
        self.value = start
        self.lock = threading.Lock()

    def get(self):
        with self.lock:
            self.value += 1
            return self.value


def run_admin():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin(): return
    except:
        pass
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    raise PermissionError("Need admin permission, a new process should be started, if not, please run it as admin manually")
