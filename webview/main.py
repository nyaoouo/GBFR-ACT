import argparse
import ctypes.wintypes
import os.path
import sys

import webview
from webview.window import FixPoint


def get_mouse_pos() -> tuple[int, int]:
    ctypes.windll.user32.GetCursorPos(ctypes.byref(point := ctypes.wintypes.POINT()))
    return point.x, point.y


def get_mouse_info() -> tuple[tuple[int, int], tuple[float, float]]:
    if not ctypes.windll.user32.GetCursorPos(ctypes.byref(point := ctypes.wintypes.POINT())): raise ctypes.WinError()
    hmontor = ctypes.windll.user32.MonitorFromPoint(point, 2)
    if not hmontor: raise ctypes.WinError()
    dpi_x = ctypes.wintypes.UINT(1)
    dpi_y = ctypes.wintypes.UINT(1)
    ctypes.windll.shcore.GetDpiForMonitor(hmontor, 0, ctypes.byref(dpi_x), ctypes.byref(dpi_y))
    return (point.x, point.y), (dpi_x.value / 100, dpi_y.value / 100)


class Api:
    _window: webview.Window = None

    def __init__(self):
        self.resize_size = None
        self.resize_start = None
        self.resize_direction = None

        self.move_start = None
        self.move_position = None

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

    def window_move_start(self):
        self.move_start, (scale_x, scale_y) = get_mouse_info()
        self.move_position = self._window.x / scale_x, self._window.y / scale_y

    def window_move_end(self):
        self.move_start = None
        self.move_position = None

    def window_move_update(self):
        if not self.move_start: return
        start_x, start_y = self.move_start
        (x, y), (scale_x, scale_y) = get_mouse_info()
        delta_x, delta_y = (x - start_x) / scale_x, (y - start_y) / scale_y
        self._window.move(self.move_position[0] + delta_x, self.move_position[1] + delta_y)

    def window_close(self):
        self._window.destroy()

    def window_minimize(self):
        self._window.minimize()


def main():
    current_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)
    if current_dir not in sys.path: sys.path.insert(0, current_dir)

    args = argparse.ArgumentParser()
    args.add_argument('--debug', action='store_true', default=False)
    args.add_argument('url', nargs='?', default=f'{current_dir}/act_ws.html')
    args = args.parse_args()

    webpage_dir = os.path.dirname(args.url)
    os.chdir(webpage_dir)

    api = Api()
    api._window = webview.create_window(
        'act_ws', args.url + '?isWebView=1',
        easy_drag=False, frameless=True, js_api=api, on_top=True
    )
    webview.start(
        debug=args.debug,
    )


if __name__ == '__main__':
    main()
