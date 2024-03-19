import csv
import struct
import typing

from .tbl_header import TabelHeader, DBColumnReaderHashString

if typing.TYPE_CHECKING:
    from ... import DataArchive


class DataTabel:
    def __init__(self, archive: 'DataArchive', name: str, view: memoryview):
        self.archive = archive
        self.name = name
        self.header = TabelHeader.open(self, name)
        self.view = view
        self.size, = struct.unpack_from('<q', view)

    @classmethod
    def load(cls, archive: 'DataArchive', path, raw):
        return cls(archive, path, memoryview(raw))

    def get_data(self, row, col):
        col_ = self.header.columns[col]
        return col_.reader.read(self.view, col_, row * self.header.row_size + 8)

    def save_csv(self, fp):
        with open(fp, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for row in self:
                row_list = []
                for data in row:
                    if isinstance(data, DBColumnReaderHashString.HashString):
                        data = f'{data.value:08X}:{data.hash_id}:{data.text}'
                    row_list.append(data)
                writer.writerow(row_list)

    def __len__(self):
        return self.size

    @typing.overload
    def __getitem__(self, idx: int) -> 'DataRow':
        ...

    @typing.overload
    def __getitem__(self, idx: slice) -> typing.List['DataRow']:
        ...

    @typing.overload
    def __getitem__(self, idx: tuple[int, int]) -> typing.Any:
        ...

    def __getitem__(self, idx):
        if isinstance(idx, int):
            return DataRow(self, idx)
        elif isinstance(idx, slice):
            return [DataRow(self, i) for i in range(*idx.indices(self.size))]
        elif isinstance(idx, tuple):
            return self.get_data(*idx)
        else:
            raise TypeError(f'Invalid index type {type(idx)}')

    def __iter__(self):
        for i in range(self.size):
            yield DataRow(self, i)

    def __repr__(self):
        return f'<DataTabel name={self.name} size={self.size}>'


class DataRow:
    def __init__(self, tbl: DataTabel, idx: int):
        self.tbl = tbl
        self.idx = idx

    def __getitem__(self, idx):
        if isinstance(idx, int):
            return self.tbl.get_data(self.idx, idx)
        elif isinstance(idx, slice):
            return [self.tbl.get_data(self.idx, i) for i in range(*idx.indices(len(self.tbl.header.columns)))]
        else:
            raise TypeError(f'Invalid index type {type(idx)}')

    def __repr__(self):
        return f'<DataRow tbl={self.tbl.name} idx={self.idx}>'

    def __iter__(self):
        for i in range(len(self.tbl.header.columns)):
            yield self.tbl.get_data(self.idx, i)

    def __len__(self):
        return len(self.tbl.header.columns)
