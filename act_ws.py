import json
import os
import sys
import threading
import time
import traceback

if __name__ == '__main__':
    _current_dir = os.path.dirname(__file__)
    if _current_dir not in sys.path:
        sys.path.insert(0, _current_dir)

from gbfr_act.act import Act
from gbfr_act.utils import run_admin, enable_privilege
from gbfr_act.utils.process import Process
from gbfr_act.utils.websocket import WebSocket, WebSocketServer


class BroadcastHandler(WebSocket):
    clients = []

    @classmethod
    def broadcast(cls, o):
        s = json.dumps(o)
        for client in cls.clients:
            client.send_message(s)

    def connected(self):
        self.clients.append(self)

        if ActWs.instance.member_info:  # init data
            self.send_message(json.dumps({
                'time_ms': int(time.time() * 1000),
                'type': 'load_party',
                'data': ActWs.instance.member_info
            }))

    def handle_close(self):
        self.clients.remove(self)


class ActWs(Act):
    instance: 'ActWs' = None

    def __init__(self):
        super().__init__()
        self.ws_server = WebSocketServer('', 24399, BroadcastHandler)
        self.ws_thread = threading.Thread(target=self.ws_server.serve_forever)
        ActWs.instance = self

    def on_damage(self, source, target, damage, flags, action_id):
        BroadcastHandler.broadcast({
            'time_ms': int(time.time() * 1000),
            'type': 'damage',
            'data': {
                'source': source,
                'target': target,
                'action_id': action_id,
                'damage': damage,
                'flags': flags
            }
        })

    def on_load_party(self, datas):
        BroadcastHandler.broadcast({
            'time_ms': int(time.time() * 1000),
            'type': 'load_party',
            'data': datas
        })

    def on_enter_area(self):
        BroadcastHandler.broadcast({
            'time_ms': int(time.time() * 1000),
            'type': 'enter_area'
        })
    
    def on_inc_death_cnt(self, actor, death_cnt):
        BroadcastHandler.broadcast({
            'time_ms': int(time.time() * 1000),
            'type': 'inc_death_cnt',
            'data': {
                'actor': actor,
                'death_cnt': death_cnt
            }
        })

    def install(self):
        super().install()
        self.ws_thread.start()

    def uninstall(self):
        self.ws_server.close()
        self.ws_thread.join()
        super().uninstall()


def injected_main():
    print(f'i am in pid={os.getpid()}')
    ActWs.reload()
    print('Act installed, if you want to reload, restart the game and run this script again.')


def main():
    run_admin()
    enable_privilege()
    while True:
        try:
            process = Process.from_name('granblue_fantasy_relink.exe')
        except ValueError:
            print('granblue_fantasy_relink.exe not found, waiting...')
            time.sleep(5)
            continue
        break
    process.injector.wait_inject()
    process.injector.reg_std_out(lambda _, s: print(s, end=''))
    process.injector.reg_std_err(lambda _, s: print(s, end=''))
    process.injector.add_path(os.path.dirname(__file__))
    process.injector.run("import act_ws;act_ws.injected_main()")


if __name__ == '__main__':
    try:
        main()
    except:
        traceback.print_exc()
    finally:
        os.system('pause')
