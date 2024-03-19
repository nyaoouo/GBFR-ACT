import json
import pathlib
import re

from gbfr_act.data_archive import DataArchive
from gbfr_act.data_archive.game_xxhash32 import xxhash32

archive = DataArchive(r'H:\game\steam\steamapps\common\Granblue Fantasy Relink')
out = pathlib.Path(r'../assets/dump_texts.js')


def load_by_tbl(lang_key):
    archive.load_texts(lang_key)
    actors = {}
    for row in archive.get_file(r'system/table/chara.tbl'):
        if not row[0]: continue
        id_ = row[18]
        if not id_.hash_id: continue
        actors[f"{id_.value:08X}"] = {
            'key': id_.hash_id,
            'text': id_.text,
        }
    for row in archive.get_file(r'system/table/enemy.tbl'):
        if not row[1].text: continue
        actors[f"{xxhash32(row[0].encode()):08X}"] = {
            'key': row[0],
            'text': row[1].text,
        }

    sigils = {}
    for row in archive.get_file(r'system/table/gem.tbl'):
        id_ = row[2]
        name = row[3]
        sigils[f"{id_.value:08X}"] = {
            'key': id_.hash_id,
            'text': name.text,
        }

    skills = {}
    for row in archive.get_file(r'system/table/skill.tbl'):
        if not row[4]: continue
        id_ = row[3]
        name = row[4]
        skills[f"{id_.value:08X}"] = {
            'key': id_.hash_id,
            'text': name.text,
        }

    weapons = {}
    for row in archive.get_file(r'system/table/weapon.tbl'):
        id_ = row[23]
        name = row[27]
        if not name.text: continue
        weapons[f"{id_.value:08X}"] = {
            'key': id_.hash_id,
            'text': name.text,
        }

    items = {}
    for row in archive.get_file(r'system/table/item.tbl'):
        id_ = row[2]
        name = row[3]
        if not name.text: continue
        items[f"{id_.value:08X}"] = {
            'key': id_.hash_id,
            'text': name.text,
        }
    over_mastery = {}
    for row in archive.get_file(r'system/table/limit_bonus_param.tbl'):
        id_ = row[13]
        name = row[15]
        if not name.text: continue
        over_mastery[f"{id_.value:08X}"] = {
            'key': id_.hash_id,
            'text': name.text,
        }
    return {
        'actors': actors,
        'sigils': sigils,
        'skills': skills,
        'weapons': weapons,
        'items': items,
        'over_mastery': over_mastery,
    }


def main():
    archive.load_external_hashes()
    res = {lang_name: load_by_tbl(lang_key) for lang_name, lang_key in (
        ('zhs', 'cs'),
        ('zht', 'ct'),
        ('en', 'en'),
    )}
    with open(out, 'w', encoding='utf-8') as f:
        s = json.dumps(res, ensure_ascii=False, indent=2)
        f.write(f'(()=>{{window.dump_texts = {s};}})()\n')


if __name__ == '__main__':
    main()
