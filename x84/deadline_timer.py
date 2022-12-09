"""
DeadLine timer class created timed call back when wait for tasks to complete.
Also includes a secondary async task for executing methods in their own thread.

Michael Griffin
"""

import time
from threading import Thread


class DeadLineTimer:
    """
    DeadLine timer to mimic boost ASIO is a simplistic way
    For import and telnet negotiations we need a timer to let us know
    when were done without blocking.
    """
    def __new__(cls):
        """
        Each Connection will have its own unique instance created
        :param cls:
        :return:
        """
        inst = object.__new__(cls)
        return inst

    @staticmethod
    def async_timer(interval, callback):
        """
        Async Timer waits for the interval then executes the callback
        :param interval:
        :param callback:
        :return:
        """
        BackgroundTimer(interval=interval, callback=callback).start()

    @staticmethod
    def async_task(interval, reference, callback):
        """
        Async Tasks executes work until interval is read, then executes callback.
        :param interval:
        :param reference:
        :param callback:
        :return:
        """
        BackgroundTask(interval=interval, reference=reference, callback=callback).start()


class BackgroundTimer(Thread):
    """
    Background thread with Callback that executes after the interval.
    interval = time to wait before executing callback method
    callback = execute callback once interval completes
    """
    def __init__(self, interval, callback):
        """
        Setup Thread Method
        :param interval:
        :param callback:
        """
        Thread.__init__(self)
        self._interval = interval
        self._callback = callback

    def run(self):
        """
        Main Thread Execution Method
        :return:
        """
        time.sleep(self._interval)
        self._callback()


class BackgroundTask(Thread):
    """
    Background thread with Callback that executes after the interval.
    interval = time to wait before executing callback method
    reference = reference to class or method to execute before callback
                also passed the interval to exit when it's cycles are completed.
    callback executes on completion of the reference method
    """
    def __init__(self, interval, reference, callback):
        """
        Setup Thread Method
        :param interval:
        :param callback:
        """
        Thread.__init__(self)
        self._interval = interval
        self._reference = reference
        self._callback = callback

    def run(self):
        """
        Main Thread Execution Method
        :return:
        """
        self._reference(self._interval)
        self._callback()
