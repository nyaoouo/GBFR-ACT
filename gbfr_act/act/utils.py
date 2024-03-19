import sys
from gbfr_act.utils.process import Process
from gbfr_act.utils.rpc import RpcServer


def get_server() -> 'RpcServer':
    return getattr(sys, '__inject_server__')


size_t_from = Process.current.read_ptr  # ctypes.c_size_t.from_address(a).value
i8_from = Process.current.read_i8  # lambda a: ctypes.c_int8.from_address(a).value
i64_from = Process.current.read_i64  # lambda a: ctypes.c_int8.from_address(a).value
i32_from = Process.current.read_i32  # lambda a: ctypes.c_int32.from_address(a).value
u32_from = Process.current.read_u32  # lambda a: ctypes.c_uint32.from_address(a).value
u64_from = Process.current.read_u64  # lambda a: ctypes.c_uint64.from_address(a).value
float_from = Process.current.read_float
string_from = Process.current.read_bytes_zero_trim
bytes_from = Process.current.read
v_func = lambda a, off: size_t_from(size_t_from(a) + off)
