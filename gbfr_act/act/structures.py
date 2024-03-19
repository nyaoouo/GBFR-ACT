import ctypes

from .utils import *


class VFunc:
    def __init__(self, i, off, vt_off=0):
        self.i = i
        self.off = off
        self.vt_off = vt_off

    def __get__(self, instance, owner):
        if instance is None: return self
        this = instance.address
        return lambda *a: self.i(v_func(this + self.vt_off, self.off))(this, *a)


# TODO: use aob to find the offset...

class VBuffer:
    # 20240315: 77 ? 48 89 7b ? 48 c7 43 ? ? ? ? ? 48 ? ? ? 4c ? ? 49 ? ? c5 ? ? e8 ? ? ? ? 48 ? ? ? 48 ? ? ? c6 ? ?
    def __init__(self, address):
        self.address = address

    ptr = property(lambda self: size_t_from(self.address) if self.max_size > 0xf else self.address)  # 0x10?
    used_size = property(lambda self: i64_from(self.address + 0x10))
    max_size = property(lambda self: u64_from(self.address + 0x18))
    raw = property(lambda self: bytes_from(self.ptr, self.used_size))


class Weapon(ctypes.Structure):  # size = 0x98
    _fields_ = [
        ('unk1', ctypes.c_uint32),
        ('weapon', ctypes.c_uint32),
        ('weapon_ap_tree', ctypes.c_uint32),
        ('unk2', ctypes.c_uint32),
        ('exp', ctypes.c_uint32),
        ('unk3', ctypes.c_uint32),
        ('unk4', ctypes.c_uint32),
        ('enhance_lv', ctypes.c_uint32),  # ?
        ('skill1', ctypes.c_uint32),
        ('skill1_lv', ctypes.c_uint32),
        ('skill2', ctypes.c_uint32),
        ('skill2_lv', ctypes.c_uint32),
        ('skill3', ctypes.c_uint32),
        ('skill3_lv', ctypes.c_uint32),
        ('bless_item', ctypes.c_uint32),
        # more unknown...
    ]


class Sigil(ctypes.Structure):
    _fields_ = [
        ('first_trait_id', ctypes.c_uint32),
        ('first_trait_level', ctypes.c_uint32),
        ('second_trait_id', ctypes.c_uint32),
        ('second_trait_level', ctypes.c_uint32),
        ('sigil_id', ctypes.c_uint32),
        ('equipped_character', ctypes.c_uint32),
        ('sigil_level', ctypes.c_uint32),
        ('acquisition_count', ctypes.c_uint32),
        ('notification_enum', ctypes.c_uint32),
    ]


class OverMastery(ctypes.Structure):
    _fields_ = [
        ('type_id', ctypes.c_uint32),
        ('level', ctypes.c_uint32),
        ('param', ctypes.c_uint32),
        ('param2', ctypes.c_float),
    ]


class Actor:
    _get_base_name = VFunc(ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t), 0x48)
    _get_type_name = VFunc(ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t), 0x50)
    _get_type_id = VFunc(ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t), 0x58)

    class Offsets:
        p_data_off = 0
        p_data_weapon_off = 0
        p_data_over_mastery_off = 0
        p_data_sigil_off = 0

    def __str__(self):
        return f"{self.type_name}#{self.address:x}"

    def __init__(self, address):
        self.address = address

    @property
    def type_name(self):
        self._get_base_name(ctypes.addressof(type_name := ctypes.c_char_p()))
        return type_name.value.decode()

    @property
    def base_name(self):
        self._get_type_name(ctypes.addressof(type_name := ctypes.c_char_p()))
        return type_name.value.decode()

    @property
    def type_id(self):
        self._get_type_id(ctypes.addressof(val := ctypes.c_uint32()))
        return val.value

    @property
    def idx(self):
        return u32_from(self.address + 0x170)

    @property
    def parent(self):
        # TODO: 找个通用方法溯源
        match self.type_id:
            case 0x2af678e8:  # 菲莉宝宝 # Pl0700Ghost
                return Actor(size_t_from(size_t_from(self.address + 0xE48) + 0x70))
            case 0x8364c8bc:  # 菲莉 绕身球  # Pl0700GhostSatellite
                return Actor(size_t_from(size_t_from(self.address + 0x508) + 0x70))
            case 0xc9f45042:  # 老男人武器 # Wp1890
                return Actor(size_t_from(size_t_from(self.address + 0x578) + 0x70))
            case 0xf5755c0e:  # 龙人化 # Pl2000
                return Actor(size_t_from(size_t_from(self.address + 0xD138) + 0x70))

    @property
    def canceled_action(self):
        return u32_from(self.address + 0xbff8)

    @property
    def weapon(self):
        p_weapon = self.address + self.Offsets.p_data_off + self.Offsets.p_data_weapon_off
        size_t_from(p_weapon)  # test address
        return Weapon.from_address(p_weapon)

    @property
    def over_mastery(self):
        p_over_mastery = self.address + self.Offsets.p_data_off + self.Offsets.p_data_over_mastery_off
        size_t_from(p_over_mastery)
        return (OverMastery * 4).from_address(p_over_mastery)

    @property
    def p_sigil_data(self):  # TODO: should have a proper name...
        return size_t_from(self.address + self.Offsets.p_data_off + self.Offsets.p_data_sigil_off)

    @property
    def sigils(self):
        size_t_from(p_data := self.p_sigil_data)  # test address
        return (Sigil * 12).from_address(p_data)

    @property
    def is_online(self):
        return u32_from(self.p_sigil_data + 0x1c8)

    @property
    def c_name(self):
        return VBuffer(self.p_sigil_data + 0x1e8).raw.decode('utf-8', 'ignore')

    @property
    def d_name(self):
        return VBuffer(self.p_sigil_data + 0x208).raw.decode('utf-8', 'ignore')

    @property
    def party_index(self):
        return u32_from(self.p_sigil_data + 0x230)

    def member_info(self):
        w = self.weapon
        return {
            'over_mastery': [{
                'type_id': om.type_id,
                'level': om.level.bit_length(),
            } for om in self.over_mastery],
            'weapon': {
                'weapon_id': w.weapon,
                'skill1': w.skill1,
                'skill1_lv': w.skill1_lv,
                'skill2': w.skill2,
                'skill2_lv': w.skill2_lv,
                'skill3': w.skill3,
                'skill3_lv': w.skill3_lv,
                'bless_item': w.bless_item,
            },
            'sigils': [
                {
                    'first_trait_id': s.first_trait_id,
                    'first_trait_level': s.first_trait_level,
                    'second_trait_id': s.second_trait_id,
                    'second_trait_level': s.second_trait_level,
                    'sigil_id': s.sigil_id,
                    'sigil_level': s.sigil_level,
                } for s in self.sigils
            ],
            'is_online': self.is_online,
            'c_name': self.c_name,
            'd_name': self.d_name,
        }


class ProcessDamageSource:
    # note: use v_func(address,0x2d8) to analyze the source parent...
    def __init__(self, address):
        self.address = address

    @property
    def actor(self):
        return Actor(size_t_from(size_t_from(self.address + 0x18) + 0x70))

    @property
    def damage(self):
        return i32_from(self.address + 0xd0)

    @property
    def flags(self):
        return u64_from(self.address + 0xd8)

    @property
    def critical(self):
        return i8_from(self.address + 0x149)

    @property
    def dmg_cap(self):
        return i32_from(self.address + 0x264)

    @property
    def attack_rate(self):
        return float_from(self.address + 0xd4)

    @property
    def action_id(self):
        return u32_from(self.address + 0x154)
