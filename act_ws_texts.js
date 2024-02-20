const i18nCfg = {
    onLocaleChange: (locale) => {
        localStorage.setItem('locale', locale);
    }, locale: (() => {
        const ls_locale = localStorage.getItem('locale');
        if (ls_locale !== null) return ls_locale;
        const default_locale = (() => {
            switch (navigator.language) {
                case 'zh-CN':
                case 'zh-Hans':
                    return 'zhs';
                case 'zh-Hant':
                case 'zh-TW':
                case 'zh-HK':
                    return 'zht';
                default:
                    return 'en';
            }
        })();
        localStorage.setItem('locale', default_locale);
        return default_locale;
    })(),
    fallbackLocale: 'en',
    messages: {
        zhs: {
            locale_name: '简体中文',
            ui: {
                name: "名称",
                damage: "伤害",
                targets: "目标",
                actions: "技能",
                hit: "命中",
                min: "最小值",
                max: "最大值",
                damage_avg: "平均伤害",
                dps_in_minute: "dps/分",
                damage_in_minute: "伤害/分",
                detail: "详情",
                dps: "dps",
            },
            game: {
                actions: {
                    common: {
                        link: "Link",
                        lb: "奥义",
                        bonus: "追击",
                    },
                    "f96a90c2": {
                        "100": "X",
                        "101": "（X）X",
                        "102": "（XX）X",
                        "103": "（XXX）Y",
                        "104": "收招",
                        "110": "（X）Y",
                        "111": "（XY）Y",
                        "120": "（XX）Y",
                        "121": "（XXY）Y",
                        "200": "Y1",
                        "201": "Y2",
                        "202": "Y3",
                        "203": "Y4",
                        "204": "Y5",
                        "300": "（空中）X1",
                        "301": "（空中）X2",
                        "302": "（空中）X3",
                        "400": "上挑攻击",
                        "410": "（空中）Y",
                        "1100": "裂空连斩",
                        "1300": "巨力重击",
                        "1400": "英勇打击",
                        "1600": "活力灭击",
                    }
                },
                actors: {
                    "9498420d": "姬塔",
                    "26a4848a": "古兰",
                    "c3155079": "赛达",
                    "34d4fd8f": "卡塔莉娜",
                    "f8d73d33": "拉卡姆",
                    "7b5934ad": "伊欧",
                    "443d46bb": "欧根",
                    "a9d6569e": "萝赛塔",
                    "2b4aa114": "夏洛特",
                    "bcc238de": "冈达葛萨",
                    "fba6615d": "菲莉",
                    "601aa977": "娜露梅",
                    "63a7c3f0": "兰斯洛特",
                    "f96a90c2": "巴恩",
                    "28ac1108": "珀西瓦尔",
                    "94e2514e": "齐格飞",
                    "6fdd6932": "卡莉奥丝特罗",
                    "c97f3365": "尤达哈拉",
                    "d16cfbde": "巴萨拉卡",
                    "8056abcd": "伊德",
                }
            },
        }, zht: {
            locale_name: '繁體中文',
            ui: {
                name: "名稱",
                damage: "傷害",
                targets: "目標",
                actions: "技能",
                hit: "命中",
                min: "最小值",
                max: "最大值",
                damage_avg: "平均傷害",
                dps_in_minute: "dps/分",
                damage_in_minute: "傷害/分",
                detail: "詳情",
                dps: "dps",
            },
        }, en: {
            locale_name: 'en',
            ui: {
                name: "name",
                damage: "damage",
                targets: "targets",
                actions: "actions",
                hit: "hit",
                min: "min",
                max: "max",
                damage_avg: "damage_avg",
                dps_in_minute: "dps_in_minute",
                damage_in_minute: "damage_in_minute",
                detail: "detail",
                dps: "dps",
            },
            game: {
                "f96a90c2": {
                    "100": "X",
                    "101": "（X）X",
                    "102": "（XX）X",
                    "103": "（XXX）Y",
                    "104": "Y(derive)",
                    "110": "（X）Y",
                    "111": "（XY）Y",
                    "120": "（XX）Y",
                    "121": "（XXY）Y",
                    "200": "Y1",
                    "201": "Y2",
                    "202": "Y3",
                    "203": "Y4",
                    "204": "Y5",
                    "300": "(jump)X1",
                    "301": "(jump)X2",
                    "302": "(jump)X3",
                    "400": "upward attack",
                    "410": "(jump)Y",
                },
                actors: {
                    "9498420d": "Zeta",
                    "26a4848a": "Gran",
                    "c3155079": "Djeeta",
                    "34d4fd8f": "Katalina",
                    "f8d73d33": "Rackam",
                    "7b5934ad": "Io",
                    "443d46bb": "Eugen",
                    "a9d6569e": "Rosetta",
                    "2b4aa114": "Charlotta",
                    "bcc238de": "Ghandagoza",
                    "fba6615d": "Ferry",
                    "601aa977": "Narmaya",
                    "63a7c3f0": "Lancelot",
                    "f96a90c2": "Vane",
                    "28ac1108": "Percival",
                    "94e2514e": "Siegfried",
                    "6fdd6932": "Cagliostro",
                    "c97f3365": "Yodarha",
                    "d16cfbde": "Vaseraga",
                    "8056abcd": "Id",
                }
            }
        }
    }
};
