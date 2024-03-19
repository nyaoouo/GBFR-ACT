import argparse
import ctypes.wintypes
import os.path
import sys

import webview
from webview.window import FixPoint


def get_mouse_position() -> tuple[int, int]:
    ctypes.windll.user32.GetCursorPos(ctypes.byref(point := ctypes.wintypes.POINT()))
    return point.x, point.y


class Api:
    _window: webview.Window = None

    def __init__(self):
        self.resize_size = None
        self.resize_start = None
        self.resize_direction = None

        self.move_start = None
        self.move_position = None

    def on_web_init(self):
        setup_all_windows_borderless()

    def window_resize_start(self, direction):
        self.resize_direction = direction
        self.resize_start = get_mouse_position()
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
        x, y = get_mouse_position()
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

    def window_move_start(self):
        self.move_start = get_mouse_position()
        self.move_position = self._window.x, self._window.y

    def window_move_end(self):
        self.move_start = None
        self.move_position = None

    def window_move_update(self):
        if not self.move_start: return
        start_x, start_y = self.move_start
        x, y = get_mouse_position()
        delta_x, delta_y = x - start_x, y - start_y
        self._window.move(self.move_position[0] + delta_x, self.move_position[1] + delta_y)

    def window_close(self):
        self._window.destroy()


def main():
    current_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)
    if current_dir not in sys.path: sys.path.insert(0, current_dir)
    os.chdir(current_dir)

    args = argparse.ArgumentParser()
    args.add_argument('--debug', action='store_true', default=False)
    args = args.parse_args()

    api = Api()
    api._window = webview.create_window(
        'act_ws', f'{current_dir}/act_ws.html?isWebView=1',
        easy_drag=False, frameless=True, js_api=api, on_top=True
    )
    webview.start(
        debug=args.debug,
    )


if __name__ == '__main__':
    main()