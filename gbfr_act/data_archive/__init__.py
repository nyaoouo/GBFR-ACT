import functools
import logging
import pathlib
import threading
import typing

from ..utils.requirements_controller import RequirementsCtrl

RequirementsCtrl.auto_install_requirements(*(pathlib.Path(__file__).parent / 'requirements.txt').read_text('utf-8').splitlines())

import requests
import lz4.block
import xxhash

from .game_xxhash32 import xxhash32
from .index_file import IndexFile
from .readers import readers
from .utils import getFileProperties, parse_version_string


@functools.cache
def get_file_list():
    (res := requests.get('https://raw.githubusercontent.com/Nenkai/GBFRDataTools/master/GBFRDataTools/filelist.txt')).raise_for_status()
    return res.text.splitlines()


@functools.cache
def external_hashes():
    (res_ := requests.get('https://raw.githubusercontent.com/Nenkai/GBFRDataTools/master/GBFRDataTools.Database/Data/ids.txt')).raise_for_status()
    res = {}
    for i, line in enumerate(res_.text.splitlines()):
        val, op, key = line.split('|')
        if op != 'ID':
            logging.warning(f'unknown op {op} in line {i} of external hashes')
            continue
        res[int(val, 16)] = key
    return res


def find_bisect(arr, x):
    i = 0
    j = len(arr)
    while i < j:
        h = (i + j) // 2
        if arr[h] < x:
            i = h + 1
        elif arr[h] > x:
            j = h
        else:
            return h
    return -1


def get_hash(v):
    if isinstance(v, str):
        return xxhash.xxh64(v.encode()).intdigest()
    elif isinstance(v, bytes):
        return xxhash.xxh64(v).intdigest()
    return v


def guess_suffix(raw):
    if raw.startswith(b'WTB\x00'): return 'wtb'
    if raw.startswith(b'AKPK'): return 'pck'
    if raw.startswith(b'COL2'): return 'col'
    if raw.startswith(b'VAT\x00'): return 'vat'
    if raw.startswith(b'EFF\x00'): return 'est'
    if raw[0] == 0xDF: return 'msg'
    if raw.startswith(b'DXBC'): return 'pso'
    if raw.startswith(b'\x01\x07\x63\x07'): return 'mot'
    if raw.startswith(b'\x36\x05\x00\x05'): return 'bxm'
    return ''


class DataArchive:
    logger = logging.getLogger('DataArchive')
    texts: dict[int, str] | None

    def __init__(self, dir_path):
        self.dir = dir_path if isinstance(dir_path, pathlib.Path) else pathlib.Path(dir_path)
        self.index = IndexFile.get_root((self.dir / 'data.i').read_bytes())
        self.version = parse_version_string(getFileProperties(self.dir / 'granblue_fantasy_relink.exe').get('FileVersion', '999'))
        self._streams = threading.local()
        self.current_lang = None
        self.texts = None
        self.hashes = {}

    def find_archive(self, v):
        return find_bisect(self.index.ArchiveFileHashes, get_hash(v))

    def find_external(self, v):
        return find_bisect(self.index.ExternalFileHashes, get_hash(v))

    def get_file(self, v, try_read=True) -> typing.Any:
        if isinstance(v, (str, bytes)):
            if isinstance(v, bytes): v = v.decode('utf-8')
            v = v.replace('\\', '/')
        if (i := self.find_archive(v)) == -1:
            raise FileNotFoundError(f'archive file {v} not found')
        indexer: IndexFile.FileToChunkIndexer = self.index.FileToChunkIndexers[i]
        if indexer.ChunkEntryIndex < 0:
            raise FileNotFoundError(f'archive file {v} invalid chunk index {indexer.ChunkEntryIndex}')
        chunk: IndexFile.DataChunk = self.index.Chunks[indexer.ChunkEntryIndex]
        assert chunk.DataFileNumber < self.index.NumArchives, f'archive file {v} invalid data file number {chunk.DataFileNumber}'
        # stream = self.get_stream(chunk.DataFileNumber)
        stream_key = str(chunk.DataFileNumber)
        if (stream := getattr(self._streams, stream_key, None)) is None:
            setattr(self._streams, stream_key, stream := (self.dir / f'data.{stream_key}').open('rb'))
        stream.seek(chunk.FileOffset)
        raw = stream.read(chunk.Size)
        if chunk.Size != chunk.UncompressedSize:
            raw = lz4.block.decompress(raw, uncompressed_size=chunk.UncompressedSize)
            assert len(raw) == chunk.UncompressedSize, f'archive file {v} decompressed size not match'
        raw = raw[indexer.OffsetIntoDecompressedChunk:indexer.OffsetIntoDecompressedChunk + indexer.FileSize]
        if try_read:
            suffix = v.rsplit('.', 1)[-1] if isinstance(v, str) else guess_suffix(raw)
            if suffix in readers:
                return readers[suffix](self, v, raw)
        return raw

    def xxhash32(self, v):
        if not isinstance(v, str): v = v.decode('utf-8')
        self.hashes[res := xxhash32(v.encode('utf-8') if isinstance(v, str) else v)] = v
        return res

    def load_texts(self, lang):
        if self.current_lang == lang: return
        self.current_lang = lang
        texts = {}
        prefix = f'system/table/text/{lang}/'
        for fn in get_file_list():
            if fn.startswith(prefix) and fn.endswith('.msg'):
                if fn == f'{prefix}text_steam.msg': continue  # skip steam text
                msg = self.get_file(fn)
                if 'rows_' in msg:
                    for row_ in msg['rows_']:
                        row = row_['column_']
                        text = row['text_']
                        int_hash = self.xxhash32(text_id := row['id_hash_'])
                        if text_id_sub := row['subid_hash_']:
                            int_hash_sub = self.xxhash32(text_id_sub)
                            int_hash = (int_hash_sub << 32) | int_hash
                        else:
                            int_hash_sub = 0
                        if int_hash in texts:
                            self.logger.warning(f'duplicate hash {int_hash:08x}: {texts[int_hash]!r} / {text!r}')
                        texts[int_hash] = text
                        if text_id.startswith('TXT_'):
                            texts[(int_hash_sub << 32) | self.xxhash32(text_id[4:])] = text
                # if 'Tag' in msg:
                #     for tag in msg['Tag']['tags_']:
                #         el = tag['Element']
                #         text = text_id = el['id_']
                #         int_hash = xxhash32(text_id.encode('utf-8'))
                #         if int_hash in res:
                #             self.logger.warning(f'duplicate hash {int_hash:08x}: {res[int_hash]!r} / {text!r}, {el}')
                #         res[int_hash] = text
        self.texts = texts

    def load_external_hashes(self):
        if hasattr(self, '__external_hashes_loaded'): return
        self.__external_hashes_loaded = True
        self.hashes.update(external_hashes())
