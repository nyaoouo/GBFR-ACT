import enum
import functools
import logging
import struct
import typing

import requests
from ...utils import parse_version_string

if typing.TYPE_CHECKING:
    from ... import DataArchive
    from ..tbl_reader import DataTabel

logger = logging.getLogger('data_archive.tbl_reader.header')


class DBColumnType(enum.IntEnum):
    Unknown = 0
    Byte = enum.auto()
    Short = enum.auto()
    Int = enum.auto()
    UInt = enum.auto()
    HexUInt = enum.auto()
    Float = enum.auto()
    Int64 = enum.auto()
    Double = enum.auto()
    String = enum.auto()
    RawString = enum.auto()
    HashString = enum.auto()
    StringPointer = enum.auto()

    @classmethod
    def from_type_str(cls, s):
        match s:
            case "raw_string":
                return cls.RawString
            case "hash_string":
                return cls.HashString
            case "string_ptr":
                return cls.StringPointer
            case "str" | "string":
                return cls.String
            case "int8" | "sbyte":
                return cls.Byte
            case "int16" | "short" | "2":
                return cls.Short
            case "int32" | "int" | "4":
                return cls.Int
            case "int64" | "uint64" | "long" | "ulong" | "8":
                return cls.Int64
            case "uint8" | "byte" | "1":
                return cls.Byte
            case "uint16" | "ushort":
                return cls.Short
            case "uint32" | "uint":
                return cls.UInt
            case "hex_uint":
                return cls.HexUInt
            case "float":
                return cls.Float
            case "double":
                return cls.Double
            case _:
                raise ValueError(f'unknown type string {s}')


class TabelColumn(typing.NamedTuple):
    header: 'TabelHeader'
    name: str
    type: DBColumnType
    offset: int
    str_len: int = 0

    @property
    def reader(self) -> 'DBColumnReader':
        return DBColumnReader.mapping[self.type]


class DBColumnReader:
    mapping = {}
    type: DBColumnType
    size: int

    def __init_subclass__(cls, **kwargs):
        if hasattr(cls, 'type'):
            assert cls.type not in DBColumnReader.mapping, f'duplicate type {cls.type}'
            DBColumnReader.mapping[cls.type] = cls()

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        raise NotImplementedError


class DBColumnReaderRawString(DBColumnReader):
    type = DBColumnType.RawString
    size = 0

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        end = start = row_off + col.offset
        while row_view[end] != 0 and end - start <= col.str_len: end += 1
        return row_view[start:end].tobytes().decode('utf-8')


class DBColumnReaderHashString(DBColumnReader):
    class HashString(typing.NamedTuple):
        archive: 'DataArchive'
        value: int

        @property
        def hash_id(self):
            return self.archive.hashes.get(self.value)

        @property
        def text(self):
            if not self.archive.texts: return None
            return self.archive.texts.get(self.value)

        def __repr__(self):
            return f'<HashString value={self.value:08X} hash_id={self.hash_id}>'

        def __eq__(self, other):
            if isinstance(other, int):
                return self.value == other
            if isinstance(other, self.__class__):
                return self.value == other.value
            if isinstance(other, str):
                other = other.encode('utf-8')
            return self.hash_id == other or self.text == other

        def __bool__(self):
            return self.value != 0x887AE0B0

    type = DBColumnType.HashString
    size = 4

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return self.HashString(
            col.header.tbl.archive,
            struct.unpack_from('<I', row_view, col.offset + row_off)[0]
        )


class DBColumnReaderStringPointer(DBColumnReader):
    type = DBColumnType.StringPointer
    size = 8

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        off = col.offset + row_off
        s_off, = struct.unpack_from('<Q', row_view, off)
        end = start = s_off + off
        while row_view[end] != 0: end += 1
        return row_view[start:end].tobytes().decode('utf-8')


class DBColumnReaderInt64(DBColumnReader):
    type = DBColumnType.Int64
    size = 8

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return struct.unpack_from('<q', row_view, col.offset + row_off)[0]


class DBColumnReaderHexUInt(DBColumnReader):
    type = DBColumnType.HexUInt
    size = 4

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return "{:08X}".format(struct.unpack_from('<I', row_view, col.offset + row_off)[0])


class DBColumnReaderInt(DBColumnReader):
    type = DBColumnType.Int
    size = 4

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return struct.unpack_from('<i', row_view, col.offset + row_off)[0]


class DBColumnReaderUInt(DBColumnReader):
    type = DBColumnType.UInt
    size = 4

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return struct.unpack_from('<I', row_view, col.offset + row_off)[0]


class DBColumnReaderShort(DBColumnReader):
    type = DBColumnType.Short
    size = 2

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return struct.unpack_from('<h', row_view, col.offset + row_off)[0]


class DBColumnReaderByte(DBColumnReader):
    type = DBColumnType.Byte
    size = 1

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return struct.unpack_from('<B', row_view, col.offset + row_off)[0]


class DBColumnReaderFloat(DBColumnReader):
    type = DBColumnType.Float
    size = 4

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return struct.unpack_from('<f', row_view, col.offset + row_off)[0]


class DBColumnReaderDouble(DBColumnReader):
    type = DBColumnType.Double
    size = 8

    def read(self, row_view: memoryview, col: TabelColumn, row_off: int):
        return struct.unpack_from('<d', row_view, col.offset + row_off)[0]


@functools.cache
def get_header_text(tbl_name: str):
    (res := requests.get(f'https://raw.githubusercontent.com/Nenkai/GBFRDataTools/master/GBFRDataTools.Database/Headers/{tbl_name}.headers')).raise_for_status()
    return res.text


class TabelHeader:
    columns: typing.List[TabelColumn]

    def __init__(self, tbl: 'DataTabel'):
        self.tbl = tbl
        self.columns = []
        self.row_size = 0

    @classmethod
    def open(cls, tbl: 'DataTabel', path):
        tbl_name = path.rsplit('/', 1)[-1]
        assert tbl_name.endswith('.tbl')
        tbl_name = tbl_name[:-4]
        return cls(tbl).load(tbl_name)

    def load(self, tbl_name):
        return self.loads(get_header_text(tbl_name))

    def loads(self, text: str):
        min_version = None
        max_version = None
        for line in text.splitlines():
            if not line or line.startswith('//'): continue
            op, *args = line.split("|")
            match op:
                case 'set_min_version':
                    min_version = parse_version_string(args[0])
                    continue
                case 'reset_min_version':
                    min_version = None
                    continue
                case 'set_max_version':
                    max_version = parse_version_string(args[0])
                    continue
                case 'reset_max_version':
                    max_version = None
                    continue

            if min_version and min_version > self.tbl.archive.version: continue
            if max_version and max_version < self.tbl.archive.version: continue

            match op:
                case 'add_column':
                    if len(args) != 2 and len(args) != 3:
                        logger.warning(f'add_column operation with {len(args)} arguments instead of 2 or 3')
                    col_type = DBColumnType.from_type_str(args[1])
                    if col_type == DBColumnType.RawString:
                        col = TabelColumn(self, args[0], col_type, self.row_size, int(args[2], 16))
                        self.row_size += col.str_len
                    else:
                        col = TabelColumn(self, args[0], col_type, int(args[2], 16) if len(args) == 3 else self.row_size)
                        self.row_size += col.reader.size
                    self.columns.append(col)
                case 'padding':
                    if len(args) != 1:
                        logger.warning(f'padding operation with {len(args)} arguments instead of 1')
                    self.row_size += int(args[0], 16)
                case 'include':
                    if len(args) != 1:
                        logger.warning(f'include operation with {len(args)} arguments instead of 1')
                    self.load(args[0])
                case _:
                    logger.warning(f'unknown operation {op!r}')
        return self

    def __bool__(self):
        return bool(self.columns)

    def __repr__(self):
        return f'<TabelHeader col={len(self.columns)} row_size={self.row_size}>'
