import os
import threading

from gbfr_act.act import Act
from gbfr_act.utils import run_admin, enable_privilege
from gbfr_act.utils.process import Process


def injected_main():
    print(f'i am in pid={os.getpid()}')

    class TestAct(Act):
        lock = threading.Lock()

        def on_damage(self, source, target, damage, flags, action_id):
            with self.lock:
                flags_ = [off for off in range(flags.bit_length()) if flags & (1 << off)]
                print(f'{source} -> {target} {action_id=} {damage=} {flags_=}')

        def on_enter_area(self):
            with self.lock:
                print('on_enter_area')

        def on_load_party(self, datas):
            with self.lock:
                print('on_load_party', datas)

    TestAct.reload()
    print('Act installed')


def main(exe_name):
    run_admin()
    enable_privilege()
    process = Process.from_name(exe_name)
    process.injector.wait_inject()
    process.injector.reg_std_out(lambda _, s: print(s, end=''))
    process.injector.reg_std_err(lambda _, s: print(s, end=''))
    process.injector.run("import importlib;import test_act;importlib.reload(test_act).injected_main()")
    os.system('pause')  # wait for user to close the console


if __name__ == '__main__':
    main('granblue_fantasy_relink.exe')
