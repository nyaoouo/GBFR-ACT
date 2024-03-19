import logging
import pickle
import threading
import traceback
import types
import typing

from . import Counter
from .pipe import PipeServer, PipeServerHandler, PipeClient

_T = typing.TypeVar('_T')


class _Rpc:
    CLIENT_CALL = 0
    CLIENT_SUBSCRIBE = 1
    CLIENT_UNSUBSCRIBE = 2

    SERVER_RETURN = 0
    SERVER_EVENT = 1

    RETURN_NORMAL = 0
    RETURN_EXCEPTION = 1
    RETURN_GENERATOR = 2
    RETURN_GENERATOR_END = 3

    REMOTE_TRACE_KEY = '_remote_trace'

    @classmethod
    def format_exc(cls, e):
        return getattr(e, cls.REMOTE_TRACE_KEY, None) or traceback.format_exc()

    @classmethod
    def set_exc(cls, e, tb):
        setattr(e, cls.REMOTE_TRACE_KEY, tb)
        return e


class RpcHandler(PipeServerHandler):
    server: 'RpcServer'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribed = set()

    def on_data_received(self, data: bytes):
        cmd, *arg = pickle.loads(data)
        if cmd == _Rpc.CLIENT_CALL:  # call
            threading.Thread(target=self.handle_call, args=arg).start()
        elif cmd == _Rpc.CLIENT_SUBSCRIBE:  # subscribe
            key, = arg
            if key not in self.subscribed:
                self.subscribed.add(key)
                self.server.add_subscribe(key, self.client_id)
        elif cmd == _Rpc.CLIENT_UNSUBSCRIBE:  # unsubscribe
            key, = arg
            if key in self.subscribed:
                self.subscribed.remove(key)
                self.server.remove_subscribe(key, self.client_id)

    def on_close(self, e: Exception | None):
        for k in self.subscribed:
            self.server.remove_subscribe(k, self.client_id)

    def handle_call(self, reply_id, key, arg, kwargs):
        try:
            res = self.server.call_map[key](*arg, *kwargs)
        except Exception as e:
            self.reply_call_exc(reply_id, e)
        else:
            if isinstance(res, types.GeneratorType):
                self.reply_call_gen(reply_id, res)
            else:
                self.reply_call_normal(reply_id, res)

    def reply_call_normal(self, reply_id, res):
        self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_NORMAL, res)))

    def reply_call_exc(self, reply_id, exc):
        self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_EXCEPTION, (exc, traceback.format_exc()))))

    def reply_call_gen(self, reply_id, gen):
        try:
            for res in gen:
                self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_GENERATOR, res)))
            self.send(pickle.dumps((_Rpc.SERVER_RETURN, reply_id, _Rpc.RETURN_GENERATOR_END, None)))
        except Exception as e:
            self.reply_call_exc(reply_id, e)

    def send_event(self, event_id, event):
        self.send(pickle.dumps((_Rpc.SERVER_EVENT, event_id, event)))


class RpcServer(PipeServer[RpcHandler]):

    def __init__(self, name, call_map, *args, **kwargs):
        super().__init__(name, *args, handler_class=RpcHandler, **kwargs)
        self.subscribe_map = {}
        if isinstance(call_map, (tuple, list,)):
            call_map = {i.__name__: i for i in call_map}
        self.call_map = call_map

    def push_event(self, event_id, data):
        cids = self.subscribe_map.get(event_id, set())
        for cid in list(cids):
            if client := self.handlers.get(cid):
                client.send_event(event_id, data)
            else:
                try:
                    cids.remove(cid)
                except KeyError:
                    pass

    def add_subscribe(self, key, cid):
        if not (s := self.subscribe_map.get(key)):
            self.subscribe_map[key] = s = set()
        s.add(cid)

    def remove_subscribe(self, key, cid):
        if s := self.subscribe_map.get(key):
            try:
                s.remove(cid)
            except KeyError:
                pass
            if not s:
                self.subscribe_map.pop(key, None)


class RpcClient(PipeClient):
    class ResEventList(typing.Generic[_T]):
        class ResEvent(threading.Event, typing.Generic[_T]):
            def __init__(self):
                super().__init__()
                self.res = None
                self.is_exc = False
                self.is_waiting = False

            def set(self, data: _T = None) -> None:
                assert not self.is_set()
                self.res = data
                self.is_exc = False
                super().set()

            def set_exception(self, exc) -> None:
                assert not self.is_set()
                self.res = exc
                self.is_exc = True
                super().set()

            def wait(self, timeout: float | None = None) -> _T:
                self.is_waiting = True
                try:
                    if super().wait(timeout):
                        if self.is_exc:
                            raise self.res
                        else:
                            return self.res
                    else:
                        raise TimeoutError()
                finally:
                    self.is_waiting = False

        queue: typing.List[ResEvent[_T]]

        def __init__(self):
            self.queue = [self.ResEvent()]
            self.lock = threading.Lock()

        def put(self, data: _T):
            with self.lock:
                if not self.queue or self.queue[-1].is_set():
                    self.queue.append(self.ResEvent())
                self.queue[-1].set(data)

        def get(self) -> _T:
            with self.lock:
                if not self.queue:
                    self.queue.append(self.ResEvent())
                evt = self.queue[0]
            res = evt.wait()
            with self.lock:
                if self.queue and self.queue[0] is evt:
                    self.queue.pop(0)
            return res

    reply_map: typing.Dict[int, ResEventList]
    logger = logging.getLogger('RpcClient')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reply_map = {}
        self.subscribe_map = {}
        self.counter = Counter()

        class Rpc:
            def __getattr__(_self, item):
                def func(*_args, **_kwargs):
                    return self.remote_call(item, _args, _kwargs)

                func.__name__ = item
                return func

        self.rpc = Rpc()

    def on_data_received(self, data: bytes):
        cmd, *args = pickle.loads(data)
        if cmd == _Rpc.SERVER_RETURN:
            reply_id, reply_type, res = args
            if l := self.reply_map.get(reply_id):
                l.put((reply_type, res))
        elif cmd == _Rpc.SERVER_EVENT:
            key, data = args
            s = self.subscribe_map.get(key, set())
            if s:
                for c in s:
                    try:
                        c(key, data)
                    except Exception as e:
                        self.logger.error(f'error in rpc client [{self.name}] event', exc_info=e)
            else:
                self.send(pickle.dumps((_Rpc.CLIENT_UNSUBSCRIBE, key)))

    def subscribe(self, key, call):
        if key not in self.subscribe_map:
            self.subscribe_map[key] = set()
            self.send(pickle.dumps((_Rpc.CLIENT_SUBSCRIBE, key)))
        self.subscribe_map[key].add(call)

    def unsubscribe(self, key, call):
        s = self.subscribe_map.get(key, set())
        try:
            s.remove(call)
        except KeyError:
            pass
        if not s:
            self.subscribe_map.pop(key, None)
            self.send(pickle.dumps((_Rpc.CLIENT_UNSUBSCRIBE, key)))

    def res_iterator(self, reply_id, evt_list, first_res):
        try:
            yield first_res
            while True:
                reply_type, res = evt_list.get()
                if reply_type == _Rpc.RETURN_EXCEPTION: raise _Rpc.set_exc(*res)
                if reply_type == _Rpc.RETURN_GENERATOR_END: break
                yield res
        finally:
            self.reply_map.pop(reply_id, None)

    def remote_call(self, key, args, kwargs):
        if not self.is_connected.is_set():
            self.connect()
        reply_id = self.counter.get()
        self.reply_map[reply_id] = evt_list = self.ResEventList()
        self.send(pickle.dumps((_Rpc.CLIENT_CALL, reply_id, key, args, kwargs)))
        reply_type, res = evt_list.get()
        if reply_type == _Rpc.RETURN_NORMAL:  # normal
            self.reply_map.pop(reply_id, None)
            return res
        if reply_type == _Rpc.RETURN_EXCEPTION:  # exc
            self.reply_map.pop(reply_id, None)
            raise _Rpc.set_exc(*res)
        if reply_type == _Rpc.RETURN_GENERATOR:  # generator
            return self.res_iterator(reply_id, evt_list, res)
        if reply_type == _Rpc.RETURN_GENERATOR_END:  # end of generator
            self.reply_map.pop(reply_id, None)

            def empty_iterator(): yield from ()

            return empty_iterator()
