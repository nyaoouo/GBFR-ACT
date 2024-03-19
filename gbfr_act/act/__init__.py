import logging

from gbfr_act.utils.hook import Hook

from .utils import *
from .structures import *


def ensure_same(args):
    if len(s := set(args)) != 1: raise ValueError(f'not same {args=}')
    return s.pop()


class Act:
    _sys_key = '_act_'

    def __init__(self):
        self.server = get_server()
        scanner = Process.current.base_scanner()

        p_process_damage_evt, = scanner.find_val('e8 * * * * 66 83 bc 24 ? ? ? ? ?')
        self.process_damage_evt_hook = Hook(p_process_damage_evt, self._on_process_damage_evt, ctypes.c_size_t, [
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_uint8
        ])

        p_process_dot_evt, = ensure_same(map(tuple, scanner.find_vals('44 89 74 24 ? 48 ? ? ? ? 48 ? ? e8 * * * * 4c ? ? ? ? ? ?')))
        self.process_dot_evt_hook = Hook(p_process_dot_evt, self._on_process_dot_evt, ctypes.c_size_t, [
            ctypes.c_size_t,
            ctypes.c_size_t
        ])

        p_on_enter_area, = scanner.find_val('e8 * * * * c5 ? ? ? c5 f8 29 45 ? c7 45 ? ? ? ? ?')
        self.on_enter_area_hook = Hook(p_on_enter_area, self._on_enter_area, ctypes.c_uint64, [
            ctypes.c_uint,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
        ])

        self.p_qword_1467572B0, = scanner.find_val("48 ? ? * * * * 44 89 48")

        Actor.Offsets.p_data_off, = scanner.find_val("48 ? ? <? ? ? ?> 89 86 ? ? ? ? 44 89 96")
        Actor.Offsets.p_data_sigil_off, = scanner.find_val("49 89 84 24 <? ? ? ?> 48 ? ? 74 ? 49 ? ? ? ? ? ? ? 48 89 43 ? ")
        Actor.Offsets.p_data_weapon_off, = scanner.find_val("48 ? ? <?> 48 ? ? ? 48 ? ? e8 ? ? ? ? 31 ? ")
        Actor.Offsets.p_data_over_mastery_off = scanner.find_val(
            "49 ? ? <? ? ? ?> 49 ? ? ? ? ? ? ? e8 ? ? ? ? 49 ? ? ? ? ? ? 49 ? ? ? ? ? ? ? 41"
        )[0] + scanner.find_val(
            "49 ? ? ? <? ? ? ?> e8 ? ? ? ? 41 ? ? e9"
        )[0]

        self.i_ui_comp_name = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_size_t)
        self.team_map = None
        self.member_info = None

    def actor_data(self, actor: Actor):
        return actor.type_name, actor.idx, actor.type_id, self.team_map.get(actor.address, -1) if self.team_map else -1

    def build_team_map(self):
        if self.team_map is not None: return
        self.team_map = {}
        qword_1467572B0 = size_t_from(self.p_qword_1467572B0)
        p_party_base = size_t_from(qword_1467572B0 + 0x20)
        p_party_tbl = size_t_from(p_party_base + 0x10 * (size_t_from(qword_1467572B0 + 0x38) & 0x6C4F1B4D) + 8)
        if p_party_tbl != size_t_from(qword_1467572B0 + 0x10) and (p_party_data := size_t_from(p_party_tbl + 0x30)):
            party_start = size_t_from(p_party_data + 0x18)
            party_end = size_t_from(p_party_data + 0x20)
            for i, p_data in enumerate(range(party_start, party_end, 0x10)):
                a1 = size_t_from(p_data + 8)
                if (self.i_ui_comp_name(v_func(a1, 0x8))(a1) == b'ui::component::ControllerPlParameter01' and
                        (p_actor := size_t_from(a1 + 0x5f8))):
                    p_actor_data = size_t_from(p_actor + 0x70)
                    self.team_map[p_actor_data] = i
                    print(f'[{i}] {p_actor_data=:#x}')

        self.member_info = [None, None, None, None, None, ]
        for p_member, i in self.team_map.items():
            try:
                actor = Actor(p_member)
                self.member_info[i] = actor.member_info() | {
                    'common_info': self.actor_data(actor)
                }
            except:
                logging.error(f'build_team_map {i}', exc_info=True)
        self.on_load_party(self.member_info)

    def _on_process_damage_evt(self, hook, p_target_evt, p_source_evt, a3, a4):
        source_evt = ProcessDamageSource(p_source_evt)
        target = source = None
        try:
            self.build_team_map()
            target = Actor(size_t_from(size_t_from(p_target_evt + 8)))
            source = source_evt.actor
        except:
            logging.error('on_process_damage_evt', exc_info=True)
        res = hook.original(p_target_evt, p_source_evt, a3, a4)  # return 0 if it is non processed damage event
        if not (res and target and source): return res  # or if get target or source failed
        try:
            flags_ = source_evt.flags
            if source.type_id == 0x2af678e8:  # 菲莉宝宝 # Pl0700Ghost
                source = source.parent
                action_id = -0x10  # summon attack
            else:
                source = source.parent or source
                if (1 << 7 | 1 << 50) & flags_:
                    action_id = -1  # link attack
                elif (1 << 13 | 1 << 14) & flags_:
                    action_id = -2  # limit break
                else:
                    action_id = source_evt.action_id
                    if action_id == 0xFFFFFFFF:
                        action_id = source.canceled_action
            self._on_damage(source, target, source_evt.damage, flags_, action_id)
        except:
            logging.error('on_process_damage_evt', exc_info=True)
        return res

    def _on_process_dot_evt(self, hook, a1, a2):
        res = hook.original(a1, a2)
        try:
            dmg = i32_from(a2)
            target = Actor(size_t_from(size_t_from(a1 + 0x18) + 0x70))
            source = Actor(size_t_from(size_t_from(a1 + 0x30) + 0x70))
            source = source.parent or source
            self._on_damage(source, target, dmg, 0, -0x100)
        except:
            logging.error('on_process_dot_evt', exc_info=True)
        return res

    def _on_enter_area(self, hook, *a):
        res = hook.original(*a)
        try:
            self.team_map = None
            self.member_info = None
            self.on_enter_area()
        except:
            logging.error('on_enter_area', exc_info=True)
        return res

    def _on_damage(self, source, target, damage, flags, action_id):
        return self.on_damage(self.actor_data(source), self.actor_data(target), damage, flags, action_id)

    def on_damage(self, source, target, damage, flags, action_id):
        pass

    def on_load_party(self, datas):
        pass

    def on_enter_area(self):
        pass

    def install(self):
        assert not hasattr(sys, self._sys_key), 'Act already installed'
        self.process_damage_evt_hook.install_and_enable()
        self.process_dot_evt_hook.install_and_enable()
        self.on_enter_area_hook.install_and_enable()
        setattr(sys, self._sys_key, self)
        return self

    def uninstall(self):
        assert getattr(sys, self._sys_key, None) is self, 'Act not installed'
        self.process_damage_evt_hook.uninstall()
        self.process_dot_evt_hook.uninstall()
        self.on_enter_area_hook.uninstall()
        delattr(sys, self._sys_key)
        return self

    @classmethod
    def get_or_create(cls):
        if hasattr(sys, cls._sys_key):
            return getattr(sys, cls._sys_key)
        return cls().install()

    @classmethod
    def remove(cls):
        if hasattr(sys, cls._sys_key):
            getattr(sys, cls._sys_key).uninstall()

    @classmethod
    def reload(cls):
        cls.remove()
        return cls.get_or_create()
