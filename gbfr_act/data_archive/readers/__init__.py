import typing

import msgpack
from .tbl_reader import DataTabel

if typing.TYPE_CHECKING:
    from .. import DataArchive
readers = {}


def register_reader(name, reader=None):
    if reader is None:
        return lambda r: register_reader(name, r)
    readers[name] = reader


@register_reader('msg')
def read_msg(archive: 'DataArchive', path: str, raw: bytes):
    return msgpack.unpackb(raw, raw=False)
    # unpacker = msgpack.Unpacker(max_buffer_size=len(raw), raw=False)
    # unpacker.feed(raw)
    # res = []
    # while True:
    #     try:
    #         res.append(unpacker.unpack())
    #     except Exception:
    #         if not res:
    #             raise
    #         break
    # if len(res) == 1:
    #     return res[0]
    # return res


@register_reader('tbl')
def read_tbl(archive: 'DataArchive', path: str, raw: bytes):
    return DataTabel.load(archive, path, raw)
