import io
import sys
sys.stdout = io.StringIO()
sys.stderr = io.StringIO()    
import eel
import webview
from threading import Thread
from act_ws import main as act_ws_main  # 从act_ws.py导入main函数并重命名为act_ws_main
import atexit
import ctypes


def cleanup():
    print("清理资源...")
    # 结束线程、关闭服务等清理操作
    webview.destroy_window()
    sys.exit(0)

atexit.register(cleanup)

def on_close():
    print("窗口关闭...")
    # 执行清理操作
    webview.destroy_window()
    sys.exit(0)

eel.init('.')

def start_ws_server():
    act_ws_main()


@eel.expose
def start_server():
    thread = Thread(target=start_ws_server)
    thread.start()
    print("websocket server started!")

def start_eel():
    """启动Eel的函数"""
    eel.start('act_ws.html', size=(1280, 720), block=True,mode=None)  # 使用block=False以非阻塞方式启动Eel




if __name__ == '__main__':
    # eel.start('act_ws.html',size=(1280,720),block=False)
# 使用线程启动Eel，避免阻塞主线程
    start_server()
    eel_thread = Thread(target=start_eel,daemon=True)
    eel_thread.start()
    
    

    # 获取Eel启动的本地服务器地址
    eel_host = f'http://localhost:8000/act_ws.html'

    # 使用PyWebView创建窗口并加载Eel的前端页面
    window = webview.create_window('GBFR_ACT', eel_host, width=1280, height=720)
    window.events.closed += on_close
    webview.start()