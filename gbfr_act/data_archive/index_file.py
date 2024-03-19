import functools
import struct


class TBase:
    class DT:
        class SimpleStructTableDataType:
            size: int
            struct: struct.Struct

            @classmethod
            def size(cls) -> int:
                return cls.struct.size

            @classmethod
            def read(cls, buf, off):
                return cls.struct.unpack(buf.read(cls.struct.size, off))[0]

            def __init_subclass__(cls, **kwargs):
                if hasattr(cls, 'struct'):
                    cls.size = cls.struct.size

        class U8(SimpleStructTableDataType):  struct = struct.Struct("<B")

        class U16(SimpleStructTableDataType): struct = struct.Struct("<H")

        class U32(SimpleStructTableDataType): struct = struct.Struct("<I")

        class U64(SimpleStructTableDataType): struct = struct.Struct("<Q")

        class I8(SimpleStructTableDataType):  struct = struct.Struct("<b")

        class I16(SimpleStructTableDataType): struct = struct.Struct("<h")

        class I32(SimpleStructTableDataType): struct = struct.Struct("<i")

        class I64(SimpleStructTableDataType): struct = struct.Struct("<q")

        class F32(SimpleStructTableDataType): struct = struct.Struct("<f")

        class F64(SimpleStructTableDataType): struct = struct.Struct("<d")

        SOffset = I32
        UOffset = U32
        VOffset = U16

    class Attr:
        class Simple:
            def __init__(self, offset, type_):
                self.offset = offset
                self.type_ = type_

            def __get__(self, instance, owner):
                if instance is None: return self
                tab = instance.tab
                return tab.get(self.type_, self.offset + tab.pos)

            def __set_name__(self, owner, name):
                v = min(self.type_.size, 0x10) - 1
                owner.size = ((getattr(owner, 'size', 0) + v) & ~v) + self.type_.size

        class VSimple:
            def __init__(self, vtable_offset, type_):
                self.vtable_offset = vtable_offset
                self.type_ = type_

            def __get__(self, instance, owner):
                if instance is None: return self
                tab = instance.tab
                if o := tab.offset(self.vtable_offset):
                    return tab.get(self.type_, o + tab.pos)

        class VString:
            def __init__(self, vtable_offset):
                self.vtable_offset = vtable_offset

            def __get__(self, instance, owner):
                if instance is None: return self
                tab = instance.tab
                if o := tab.offset(self.vtable_offset):
                    return tab.string(o + tab.pos)

        class Vector_:
            def __init__(self, tab, offset, type_=None):
                self.tab = tab
                self.offset = offset
                self.type_ = type_

            def __len__(self):
                return self.tab.vector_len(self.offset)

            def __getitem__(self, item):
                if isinstance(item, slice): return tuple(self[i] for i in range(*item.indices(len(self))))
                return self.tab.get(self.type_, self.tab.vector(self.offset) + self.type_.size * item)

            def __iter__(self):
                for i in range(len(self)):
                    yield self[i]

        class VVector:
            def __init__(self, vtable_offset, type_=None):
                self.vtable_offset = vtable_offset
                self.type_ = type_

            def __get__(self, instance, owner):
                if instance is None: return self
                tab = instance.tab
                if o := tab.offset(self.vtable_offset):
                    return TBase.Attr.Vector_(tab, o, self.type_)

    class Reader:
        def __new__(cls, o):
            return o if isinstance(o, cls) else super().__new__(cls)

        def __init__(self, o):
            if not hasattr(self, 'read'):
                if isinstance(o, (bytes | bytearray | memoryview)):
                    self.buf = o if isinstance(o, memoryview) else memoryview(o)
                    self.read = self.read_mem
                else:
                    self.buf = o
                    self.read = self.read_buf

        def read_mem(self, size, offset):
            return self.buf[offset:offset + size]

        def read_buf(self, size, offset):
            self.buf.seek(offset)
            return self.buf.read(size)

    def __init__(self, buf, pos: int):
        self.buf = TBase.Reader(buf)
        self.pos = pos

    def get(self, reader, offset):
        return reader.read(self.buf, offset)

    vtable = functools.cached_property(lambda self: self.pos - self.get(TBase.DT.SOffset, self.pos))
    vtable_end = functools.cached_property(lambda self: self.get(TBase.DT.VOffset, self.vtable))

    def offset(self, vtable_offset):
        if vtable_offset < self.vtable_end:
            return self.get(TBase.DT.VOffset, self.vtable + vtable_offset)
        return 0

    def indirect(self, off):
        return off + self.get(TBase.DT.UOffset, off)

    def string(self, off):
        off += self.get(TBase.DT.UOffset, off)
        start = off + TBase.DT.UOffset.struct.size
        length = self.get(TBase.DT.UOffset, off)
        return bytes(self.buf.read(length, start))

    def vector_len(self, off):
        off += self.pos
        off += self.get(TBase.DT.UOffset, off)
        return self.get(TBase.DT.UOffset, off)

    def vector(self, off, type_=None):
        off += self.pos
        return off + self.get(TBase.DT.UOffset, off) + TBase.DT.UOffset.struct.size

    @classmethod
    def get_root(cls, buf, offset=0):
        buf = TBase.Reader(buf)
        n = TBase.DT.UOffset.read(buf, 0)
        return cls(buf, n + offset)


class Table:
    tab: TBase

    def __init__(self, *a):
        if len(a) == 1:
            self.tab = a[0]
        else:
            self.tab = TBase(*a)

    @classmethod
    def read(cls, buf, offset=0):
        return cls(TBase(buf, offset))

    @classmethod
    def get_root(cls, buf, offset=0):
        return cls(TBase.get_root(buf, offset))


class IndexFile(Table):
    class FileToChunkIndexer(Table):
        ChunkEntryIndex = TBase.Attr.Simple(0, TBase.DT.I32)
        FileSize = TBase.Attr.Simple(4, TBase.DT.U32)
        OffsetIntoDecompressedChunk = TBase.Attr.Simple(8, TBase.DT.U32)

    class DataChunk(Table):
        FileOffset = TBase.Attr.Simple(0, TBase.DT.U64)
        Size = TBase.Attr.Simple(8, TBase.DT.U32)
        UncompressedSize = TBase.Attr.Simple(12, TBase.DT.U32)
        AllocAlignment = TBase.Attr.Simple(16, TBase.DT.U32)
        UnkBool = TBase.Attr.Simple(20, TBase.DT.U8)
        pad = TBase.Attr.Simple(21, TBase.DT.U8)
        DataFileNumber = TBase.Attr.Simple(22, TBase.DT.U8)
        pad2 = TBase.Attr.Simple(23, TBase.DT.U8)

    Codename = TBase.Attr.VString(4)
    NumArchives = TBase.Attr.VSimple(6, TBase.DT.U16)
    XxhashSeed = TBase.Attr.VSimple(8, TBase.DT.U16)
    ArchiveFileHashes = TBase.Attr.VVector(10, TBase.DT.U64)
    FileToChunkIndexers = TBase.Attr.VVector(12, FileToChunkIndexer)
    Chunks = TBase.Attr.VVector(14, DataChunk)
    ExternalFileHashes = TBase.Attr.VVector(16, TBase.DT.U64)
    ExternalFileSizes = TBase.Attr.VVector(18, TBase.DT.U64)
    CachedChunkIndices = TBase.Attr.VVector(20, TBase.DT.U32)
