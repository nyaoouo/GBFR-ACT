import argparse
import ctypes.wintypes
import os.path
import threading
import time
import sys

import webview
from webview.window import FixPoint


def get_mouse_pos() -> tuple[int, int]:
    ctypes.windll.user32.GetCursorPos(ctypes.byref(point := ctypes.wintypes.POINT()))
    return point.x, point.y


class Api:
    _window: webview.Window = None
    _guilib = None
    _hwnds = []

    def __init__(self):
        self.resize_size = None
        self.resize_start = None
        self.resize_direction = None

        self.move_start = None
        self.move_position = None

    def _set_guilib(self, _, guilib):
        self._guilib = guilib

    def window_init(self):
        pass

    def window_resize_start(self, direction):
        self.resize_direction = direction
        self.resize_start = get_mouse_pos()
        self.resize_size = self._window.width, self._window.height

    def window_resize_end(self):
        if not self.resize_start: return
        self.resize_start = None
        self.resize_size = None
        self.resize_direction = None

    def window_resize_update(self):
        if not self.resize_start: return
        width, height = self.resize_size
        start_x, start_y = self.resize_start
        x, y = get_mouse_pos()
        delta_x, delta_y = x - start_x, y - start_y
        match self.resize_direction:
            case 'left':
                width = width - delta_x
                fix = FixPoint.EAST
            case 'right':
                width = width + delta_x
                fix = FixPoint.WEST
            case 'top':
                height = height - delta_y
                fix = FixPoint.SOUTH
            case 'bottom':
                height = height + delta_y
                fix = FixPoint.NORTH
            case 'left-top':
                width = width - delta_x
                height = height - delta_y
                fix = FixPoint.SOUTH | FixPoint.EAST
            case 'right-top':
                width = width + delta_x
                height = height - delta_y
                fix = FixPoint.SOUTH | FixPoint.WEST
            case 'left-bottom':
                width = width - delta_x
                height = height + delta_y
                fix = FixPoint.NORTH | FixPoint.EAST
            case 'right-bottom':
                width = width + delta_x
                height = height + delta_y
                fix = FixPoint.NORTH | FixPoint.WEST
            case _:
                return
        self._window.resize(width, height, fix)

    def window_close(self):
        self._window.destroy()

    def window_minimize(self):
        self._window.minimize()

    def _check_hover_worker(self, cond):
        self._window.restore()
        view = self._guilib.BrowserView.instances['master']
        last_state = None
        extra = 10
        while cond:
            win_x, win_y = self._window.x, self._window.y
            x, y = get_mouse_pos()
            new_state = (
                    bool(self.resize_start) or
                    win_x - extra <= x <= win_x + self._window.width + extra and
                    win_y - extra <= y <= win_y + self._window.height + extra
            )
            if new_state != last_state:
                if new_state:
                    view.BackColor = self._guilib.Color.FromArgb(255, 255, 255, 255)
                else:
                    view.BackColor = self._guilib.Color.FromArgb(255, 255, 0, 0)
                    view.TransparencyKey = self._guilib.Color.FromArgb(255, 255, 0, 0)
                last_state = new_state
            time.sleep(0.2)


def hook_guilib_init(cb):
    def py_hook(parent, name):
        def wrapper(func):
            old_func = getattr(parent, name)
            setattr(parent, name, lambda *a, **kw: func(old_func, *a, **kw))

        return wrapper

    @py_hook(webview, 'initialize')
    def hook_initialize(old, forced_gui=None):
        res = old(forced_gui)
        cb(forced_gui, res)
        return res


def main():
    current_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)
    if current_dir not in sys.path: sys.path.insert(0, current_dir)

    args = argparse.ArgumentParser()
    args.add_argument('--debug', action='store_true', default=False)
    # args.add_argument('--no-transparent', dest='transparent', action='store_false', default=True)
    args.add_argument('--transparent', action='store_true', default=False)
    args.add_argument('url', nargs='?', default=f'{current_dir}/act_ws.html')
    args = args.parse_args()

    webpage_dir = os.path.dirname(args.url)
    os.chdir(webpage_dir)

    api = Api()
    hook_guilib_init(api._set_guilib)
    api._window = webview.create_window(
        'act_ws', args.url + '?isWebView=1',
        easy_drag=False, frameless=True, js_api=api, on_top=True, transparent=args.transparent,
    )
    working = [1]
    if args.transparent:
        (t := threading.Thread(target=api._check_hover_worker, args=(working,))).start()
    webview.start(debug=args.debug)
    working.clear()
    if args.transparent:
        t.join()


if __name__ == '__main__':
    main()
