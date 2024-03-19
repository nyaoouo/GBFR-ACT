import ctypes
import ctypes.util
import pathlib
import typing

from ..native import def_win_api


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
    lh_install_hook = def_win_api(dll.LhInstallHook, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p))
    lh_uninstall_hook = def_win_api(dll.LhUninstallHook, ctypes.c_ulong, (ctypes.c_void_p,))
    lh_uninstall_all_hooks = def_win_api(dll.LhUninstallAllHooks, ctypes.c_ulong)
    rtl_get_last_error = def_win_api(dll.RtlGetLastError, ctypes.c_ulong)
    rtl_get_last_error_string = def_win_api(dll.RtlGetLastErrorString, ctypes.c_wchar_p)
    lh_set_inclusive_acl = def_win_api(dll.LhSetInclusiveACL, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p))
    lh_set_exclusive_acl = def_win_api(dll.LhSetExclusiveACL, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p))
    lh_get_bypass_address = def_win_api(dll.LhGetHookBypassAddress, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_void_p))
    lh_wait_for_pending_removals = def_win_api(dll.LhWaitForPendingRemovals, ctypes.c_ulong)

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
