import faulthandler
import gc
import threading

from middlewared.client import Client


def objects(cls):
    return [obj for obj in gc.get_objects() if isinstance(obj, cls)]


def test__thread_count(request):
    """Having outstanding threads can prevent python from exiting cleanly."""
    count = threading.active_count()
    if count > 1:
        faulthandler.dump_traceback()
        with open('threads.trace', 'w') as f:
            faulthandler.dump_traceback(f)
        assert count == 1


def test__client_objects(request):
    """Check whether any Client objects still exist, and attempt to close them if so."""
    objs = objects(Client)
    for obj in objs:
        try:
            obj.close()
        except Exception:
            pass
    assert 0 == len(objs)
