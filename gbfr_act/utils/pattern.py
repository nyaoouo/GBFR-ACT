# xx xx xx xx 空格分割
# [xx:yy] 单字节从 xx 到 yy
# [xx|yy|zz] 单字节 xx 或 yy 或 zz
# ? ? ? ? 视作变量（默认不储存）
# ^ ^ ^ ^ 视作字串（默认储存）
# * * * * 视作跳转（默认储存）
# ?{n} / *{n} 视作匹配n次
# ?{n:m} / *{n:m} 视作匹配n-m次
# (xx xx xx xx) 不存储的分组
# <xx xx xx xx> 储存的分组
# <* * * *: yy yy yy yy> 对分组数据二级匹配
# <* * * *: yy yy yy yy <* * * *:zz zz zz zz>> 对分组数据多级匹配，仅适用于跳转
import io
import re
import typing
from . import pefile

if typing.TYPE_CHECKING:
    from .process import Process

fl_is_ref = 1 << 0
fl_is_byes = 1 << 1
fl_store = 1 << 2

hex_chars = set(b'0123456789abcdefABCDEF')
dec_chars = set(b'0123456789')

special_chars_map = {i for i in b'()[]{}?*+-|^$\\.&~# \t\n\r\v\f'}


def take_dec_number(pattern: str, i: int):
    assert i < len(pattern) and ord(pattern[i]) in dec_chars
    j = i + 1
    while j < len(pattern) and ord(pattern[j]) in dec_chars:
        j += 1
    return int(pattern[i:j]), j


def take_cnt(pattern: str, i: int, regex_pattern: bytearray):
    if i < len(pattern) and pattern[i] == '{':
        regex_pattern.append(123)  # {
        n1, i = take_dec_number(pattern, i + 1)
        regex_pattern.extend(str(n1).encode())
        if pattern[i] == ':':
            n2, i = take_dec_number(pattern, i + 1)
            assert n1 <= n2
            regex_pattern.append(44)  # ,
            regex_pattern.extend(str(n2).encode())
        assert pattern[i] == '}'
        regex_pattern.append(125)  # }
        i += 1
    return i


def take_byte(pattern: str, i: int, regex_pattern: bytearray):
    assert i + 2 <= len(pattern)
    next_byte = int(pattern[i:i + 2], 16)
    if next_byte in special_chars_map:
        regex_pattern.append(92)  # \
    regex_pattern.append(next_byte)
    return i + 2


def _take_unk(pattern: str, i: int):
    start_chr = pattern[i]
    assert start_chr in ('?', '*', '^')
    if i + 1 < len(pattern) and pattern[i + 1] == start_chr:
        i += 1
    return start_chr, i + 1


def take_unk(pattern: str, i: int, regex_pattern: bytearray):
    start_unk, i = _take_unk(pattern, i)
    regex_pattern.append(46)
    i = take_cnt(pattern, i, regex_pattern)
    while i < len(pattern):
        match pattern[i]:
            case ' ':
                i += 1
            case c if c == start_unk:
                start_unk, i = _take_unk(pattern, i)
                regex_pattern.append(46)
                i = take_cnt(pattern, i, regex_pattern)
            case _:
                break
    return start_unk, i


def _compile_pattern(pattern: str, i=0, ret_at=None):
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
                i = take_byte(pattern, i, regex_pattern)
                while True:
                    match pattern[i]:
                        case ' ':
                            i += 1
                        case ']':
                            regex_pattern.append(93)  # ]
                            i += 1
                            break
                        case '|':
                            i = take_byte(pattern, i + 1, regex_pattern)
                        case ':':
                            regex_pattern.append(45)  # -
                            i = take_byte(pattern, i + 1, regex_pattern)
                        case c:
                            raise ValueError(f'Invalid character {c} in pattern {pattern!r} at {i}')

            case '(':
                base_flag = 0  # not fl_store
                regex_pattern.append(40)  # (
                unk_type, i = take_unk(pattern, i + 1, regex_pattern)
                if unk_type == '*':
                    base_flag |= fl_is_ref
                elif unk_type == '^':
                    base_flag |= fl_is_byes
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
                            sub_pattern, i = _compile_pattern(pattern, i + 1, ret_at=')')
                            assert pattern[i] == ')', f'Expected ) get {pattern[i]} at {i} in pattern {pattern!r}'
                            regex_pattern.append(41)
                            i += 1
                            break
                        case c:
                            raise ValueError(f'Invalid character {c} in pattern {pattern!r} at {i}')
                group_flags.append(base_flag)
                sub_matches.append(sub_pattern)
            case '<':
                base_flag = fl_store
                regex_pattern.append(40)
                unk_type, i = take_unk(pattern, i + 1, regex_pattern)
                if unk_type == '*':
                    base_flag |= fl_is_ref
                elif unk_type == '^':
                    base_flag |= fl_is_byes
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
                            sub_pattern, i = _compile_pattern(pattern, i + 1, ret_at='>')
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
                unk_type, i = take_unk(pattern, i, regex_pattern)
                regex_pattern.append(41)
                if c == '?':
                    group_flags.append(0)
                elif c == '*':
                    group_flags.append(fl_is_ref | fl_store)
                elif c == '^':
                    group_flags.append(fl_is_byes | fl_store)
                else:
                    raise ValueError(f'Invalid character {c} in pattern {pattern!r} at {i}')
                sub_matches.append(None)
            case c if ord(c) in hex_chars:
                i = take_byte(pattern, i, regex_pattern)
                i = take_cnt(pattern, i, regex_pattern)
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


def compile_pattern(pattern: str):
    return _compile_pattern(pattern)[0]


class Pattern:
    def __init__(self, regex: re.Pattern, sub_matches: 'typing.List[None | Pattern]', group_flags, pattern: str):
        self.regex = regex
        self.sub_matches = sub_matches
        self.group_flags = group_flags
        self.pattern = pattern
        self.res_is_ref = []
        for i, (sub, flag) in enumerate(zip(sub_matches, group_flags)):
            if flag & fl_store:
                self.res_is_ref.append(flag & fl_is_ref)
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
            if flag & fl_is_byes:
                res.append(match.group(i + 1))
            else:
                val = int.from_bytes(match.group(i + 1), 'little', signed=True)
                if flag & fl_is_ref:
                    val += match.end(i + 1)
                if flag & fl_store:
                    res.append(val)
                if sub_match is not None:
                    start = val if flag & fl_is_ref else val - ref_base
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
        s.write(fmt_bytes_regex_pattern(self.regex.pattern))
        s.write('\n')
        s.write(ind * _ind)
        s.write('res is ref:')
        for flag in self.res_is_ref:
            s.write(' ref' if flag else ' val')
        s.write('\n')
        for i, (sub, flag) in enumerate(zip(self.sub_matches, self.group_flags)):
            s.write(ind * _ind)
            s.write(f'{i}:{"ref" if flag & fl_is_ref else "val"}{" store" if flag & fl_store else ""}\n')
            if sub is not None:
                s.write(sub.fmt(ind, _ind + 1))
                s.write('\n')
        return s.getvalue().rstrip()


def fmt_bytes_regex_pattern(pat: bytes):
    s = ''
    is_escape = False
    is_in_bracket = 0
    for b in pat:
        if is_escape:
            is_escape = False
            s += f'\\x{b:02x}'
        elif b == 92:  # \
            is_escape = True
        elif b in special_chars_map:
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


class StaticPatternSearcher(IPatternScanner):
    def __init__(self, pe, base_address=0):
        self.pe = pe if isinstance(pe, pefile.PE) else pefile.PE(pe, fast_load=True)
        self.text_sections = [sect for sect in self.pe.sections if sect.Name.rstrip(b'\0') == b'.text']
        self.section_datas = [sect.get_data() for sect in self.text_sections]
        self.section_virtual_addresses = [sect.VirtualAddress for sect in self.text_sections]
        self.base_address = base_address

    def get_original_text(self, address, size):
        i = 0
        for i, a in enumerate(self.section_virtual_addresses):
            if a > address: break
        i -= 1
        section_address = address - self.base_address - self.section_virtual_addresses[i]
        return self.section_datas[i][section_address:section_address + size]

    def search(self, pattern: str | Pattern) -> typing.Generator[tuple[int, list[int]], None, None]:
        if isinstance(pattern, str):  pattern = compile_pattern(pattern)
        for i in range(len(self.text_sections)):
            sect_off = self.base_address + self.section_virtual_addresses[i]
            for offset, args in pattern.finditer(self.section_datas[i]):
                yield sect_off + offset, [a + sect_off if r else a for a, r in zip(args, pattern.res_is_ref)]


class MemoryPatternScanner(IPatternScanner):
    def __init__(self, process: 'Process', region_address, region_size):
        self.process = process
        self.region_address = region_address
        self.region_size = region_size

    def get_raw(self):
        return self.process.read(self.region_address, self.region_size)

    def search(self, pattern: str | Pattern) -> typing.Generator[tuple[int, list[int]], None, None]:
        if isinstance(pattern, str):  pattern = compile_pattern(pattern)
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
