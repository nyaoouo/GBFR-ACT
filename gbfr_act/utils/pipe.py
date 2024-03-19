import threading
import time
import typing
from .native import *

_T = typing.TypeVar('_T')


class PipeHandlerBase:
    active_pipe_handler = {}
    buf_size = 64 * 1024
    handle = None
    period = .001

    def __init__(self):
        self.serve_thread = threading.Thread(target=self.serve, daemon=True)
        self.work = False
        self.is_connected = threading.Event()

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
