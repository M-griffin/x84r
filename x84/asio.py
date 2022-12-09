"""
Asynchronous socket service inspired by the basic design of Boost ASIO.
This service currently supports TCP sockets only, and supports asynchronous
versions of common client operations (connect, read, write) and server operations
(accept).

This implementation supports the use of select, poll, epoll, or kqueue as the
underlying poll system call.

Aaron Riekenberg - aaron.riekenberg@gmail.com
MIT licence.

Source Recipe:
https://code.activestate.com/recipes/577662-asio/

Michael Griffin - mrmisticismo@hotmail.com 2022
Refactoring Python 3 Updates, SonarLint and PyLint Fixes
PyLint Catches alot more items, since external Recipe will just exclude some items.
"""

# Update pylint Exclusions for External Recipe
# pylint: disable=consider-using-f-string
# pylint: disable=missing-function-docstring
import collections
import errno
import functools
import logging
import select
import socket

# Handle Constants For Exception Messages
ASYNC_SOCKET_CLOSED_MSG = "AsyncSocket closed"
ASYNC_ACCEPT_IN_PROGRESS_MSG = "Accept already in progress"
ASYNC_CONNECT_IN_PROGRESS_MSG = "Connect already in progress"
ASYNC_READ_IN_PROGRESS_MSG = "Read already in progress"
ASYNC_WRITE_IN_PROGRESS_MSG = "Write all already in progress"


class AsyncException(Exception):
    """ Async Exception Class """

    def __init__(self, value):
        self.__value = value
        super().__init__(value)

    def __str__(self):
        return repr(self.__value)


class AsyncSocket:
    """Socket class supporting asynchronous operations."""

    # pylint: disable=too-many-instance-attributes
    def __init__(self, async_io_service, sock=None):
        self.__async_io_service = async_io_service
        self.__accept_callback = None
        self.__connect_callback = None
        self.__read_callback = None
        self.__write_all_callback = None
        self.__write_buffer = b''
        self.__max_read_bytes = 0
        self.__closed = False
        super().__init__()

        if sock:
            self.__socket = sock
        else:
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.setblocking(False)
        async_io_service.add_async_socket(self)

    def __str__(self):
        return "AsyncSocket [ fileno = %d ]" % self.get_fileno()

    def get_socket_name(self):
        return self.__socket.getsockname()

    def get_peer_name(self):
        return self.__socket.getpeername()

    def closed(self):
        return self.__closed

    def get_socket(self):
        return self.__socket

    def get_fileno(self):
        return self.__socket.fileno()

    def set_reuse_address(self):
        self.__socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def listen(self, backlog=socket.SOMAXCONN):
        self.__socket.listen(backlog)

    def bind(self, addr):
        self.__socket.bind(addr)

    def async_connect(self, address, callback):
        if self.__accept_callback:
            raise AsyncException(ASYNC_ACCEPT_IN_PROGRESS_MSG)
        if self.__connect_callback:
            raise AsyncException(ASYNC_CONNECT_IN_PROGRESS_MSG)
        if self.__read_callback:
            raise AsyncException(ASYNC_READ_IN_PROGRESS_MSG)
        if self.__write_all_callback:
            raise AsyncException(ASYNC_WRITE_IN_PROGRESS_MSG)
        if self.__closed:
            raise AsyncException(ASYNC_SOCKET_CLOSED_MSG)

        err = self.__socket.connect_ex(address)
        if err in (errno.EINPROGRESS, errno.EWOULDBLOCK):
            self.__connect_callback = callback
            self.__async_io_service.register_async_socket_for_write(self)
        else:
            self.__async_io_service.register_callback_event(functools.partial(callback, err=err))

    def async_accept(self, callback):
        if self.__accept_callback:
            raise AsyncException(ASYNC_ACCEPT_IN_PROGRESS_MSG)
        if self.__connect_callback:
            raise AsyncException(ASYNC_CONNECT_IN_PROGRESS_MSG)
        if self.__read_callback:
            raise AsyncException(ASYNC_READ_IN_PROGRESS_MSG)
        if self.__write_all_callback:
            raise AsyncException(ASYNC_WRITE_IN_PROGRESS_MSG)
        if self.__closed:
            raise AsyncException(ASYNC_SOCKET_CLOSED_MSG)

        try:
            # pylint: disable=unused-variable
            (new_socket, addr) = self.__socket.accept()
            accept_socket = AsyncSocket(self.__async_io_service, new_socket)
            self.__async_io_service.register_callback_event(
                functools.partial(callback, sock=accept_socket, err=0))
        except socket.error as err:
            if err.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self.__accept_callback = callback
                self.__async_io_service.register_async_socket_for_read(self)
            else:
                self.__async_io_service.register_callback_event(
                    functools.partial(callback, sock=None, err=err.args[0]))

    def async_read(self, max_bytes, callback):
        if self.__accept_callback:
            raise AsyncException(ASYNC_ACCEPT_IN_PROGRESS_MSG)
        if self.__connect_callback:
            raise AsyncException(ASYNC_CONNECT_IN_PROGRESS_MSG)
        if self.__read_callback:
            raise AsyncException(ASYNC_READ_IN_PROGRESS_MSG)
        if self.__closed:
            raise AsyncException(ASYNC_SOCKET_CLOSED_MSG)

        self.__max_read_bytes = max_bytes
        data = None

        try:
            data = self.__socket.recv(self.__max_read_bytes)
            self.__async_io_service.register_callback_event(
                functools.partial(callback, data=data, err=0))
        except socket.error as err:
            if err.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self.__read_callback = callback
                self.__async_io_service.register_async_socket_for_read(self)
            else:
                self.__async_io_service.register_callback_event(
                    functools.partial(callback, data=data, err=err.args[0]))

    def async_write_all(self, data, callback):
        if self.__accept_callback:
            raise AsyncException(ASYNC_ACCEPT_IN_PROGRESS_MSG)
        if self.__connect_callback:
            raise AsyncException(ASYNC_CONNECT_IN_PROGRESS_MSG)
        if self.__write_all_callback:
            raise AsyncException(ASYNC_WRITE_IN_PROGRESS_MSG)
        if self.__closed:
            raise AsyncException(ASYNC_CONNECT_IN_PROGRESS_MSG)

        self.__write_buffer += data
        use_write_block = False
        try:
            bytes_sent = self.__socket.send(self.__write_buffer)
            self.__write_buffer = self.__write_buffer[bytes_sent:]
            if len(self.__write_buffer) == 0:
                self.__async_io_service.register_callback_event(functools.partial(callback, err=0))
            else:
                use_write_block = True
        except socket.error as err:
            if err.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                use_write_block = True
            else:
                self.__async_io_service.register_callback_event(
                    functools.partial(callback, err=err.args[0]))

        if use_write_block:
            self.__write_all_callback = callback
            self.__async_io_service.register_async_socket_for_write(self)

    def close(self):
        if self.__closed:
            return

        self.__async_io_service.remove_async_socket(self)
        self.__socket.close()
        self.__closed = True

        if self.__accept_callback:
            self.__async_io_service.register_callback_event(
                functools.partial(self.__accept_callback, sock=None, err=errno.EBADF))
            self.__accept_callback = None

        if self.__connect_callback:
            self.__async_io_service.register_callback_event(
                functools.partial(self.__connect_callback, err=errno.EBADF))
            self.__connect_callback = None

        if self.__read_callback:
            self.__async_io_service.register_callback_event(
                functools.partial(self.__read_callback, data=None, err=errno.EBADF))
            self.__read_callback = None

        if self.__write_all_callback:
            self.__async_io_service.register_callback_event(
                functools.partial(self.__write_all_callback, err=errno.EBADF))
            self.__write_all_callback = None

    def handle_errors(self):
        err = self.__socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)

        if self.__connect_callback:
            self.__async_io_service.unregister_async_socket_for_write(self)
            self.__async_io_service.register_callback_event(
                functools.partial(self.__connect_callback, err=err))
            self.__connect_callback = None

        if self.__accept_callback:
            self.__async_io_service.unregister_async_socket_for_read(self)
            self.__async_io_service.register_callback_event(
                functools.partial(self.__accept_callback, sock=None, err=err))
            self.__accept_callback = None

        if self.__read_callback:
            self.__async_io_service.unregister_async_socket_for_read(self)
            self.__async_io_service.register_callback_event(
                functools.partial(self.__read_callback, data=None, err=err))
            self.__read_callback = None

        if self.__write_all_callback:
            self.__async_io_service.unregister_async_socket_for_write(self)
            self.__async_io_service.register_callback_event(
                functools.partial(self.__write_all_callback, err=err))
            self.__write_all_callback = None

    def handle_read(self):
        if self.__accept_callback:
            try:
                # pylint: disable=unused-variable
                (new_socket, addr) = self.__socket.accept()
                read_socket = AsyncSocket(self.__async_io_service, new_socket)
                self.__async_io_service.unregister_async_socket_for_read(self)
                self.__async_io_service.register_callback_event(
                    functools.partial(self.__accept_callback, sock=read_socket, err=0))
                self.__accept_callback = None
            except socket.error as err:
                if err.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                    pass
                else:
                    self.__async_io_service.unregister_async_socket_for_read(self)
                    self.__async_io_service.register_callback_event(
                        functools.partial(self.__accept_callback, sock=None, err=err.args[0]))
                    self.__accept_callback = None

        if self.__read_callback:
            try:
                data = self.__socket.recv(self.__max_read_bytes)
                self.__async_io_service.unregister_async_socket_for_read(self)
                self.__async_io_service.register_callback_event(
                    functools.partial(self.__read_callback, data=data, err=0))
                self.__read_callback = None
            except socket.error as err:
                if err.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                    pass
                else:
                    self.__async_io_service.unregister_async_socket_for_read(self)
                    self.__async_io_service.register_callback_event(
                        functools.partial(self.__read_callback, data=None, err=err.args[0]))
                    self.__read_callback = None

    def handle_write(self):
        if self.__connect_callback:
            err = self.__socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                self.__async_io_service.unregister_async_socket_for_write(self)
                self.__async_io_service.register_callback_event(
                    functools.partial(self.__connect_callback, err=err))
                self.__connect_callback = None

        if self.__write_all_callback:
            try:
                bytes_sent = self.__socket.send(self.__write_buffer)
                self.__write_buffer = self.__write_buffer[bytes_sent:]
                if len(self.__write_buffer) == 0:
                    self.__async_io_service.unregister_async_socket_for_write(self)
                    self.__async_io_service.register_callback_event(
                        functools.partial(self.__write_all_callback, err=0))
                    self.__write_all_callback = None
            except socket.error as err:
                if err.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                    pass
                else:
                    self.__async_io_service.unregister_async_socket_for_write(self)
                    self.__async_io_service.register_callback_event(
                        functools.partial(self.__write_all_callback, err=err.args[0]))
                    self.__write_all_callback = None


class AsyncIOService:
    """ Service used to poll asynchronous sockets. """

    def __init__(self):
        self.__fd_to_async_socket = {}
        self.__fds_registered_for_read = set()
        self.__fds_registered_for_write = set()
        self.__event_queue = collections.deque()

    def create_async_socket(self):
        return AsyncSocket(async_io_service=self)

    def add_async_socket(self, async_socket):
        self.__fd_to_async_socket[async_socket.get_fileno()] = async_socket

    def remove_async_socket(self, async_socket):
        fileno = async_socket.get_fileno()
        if fileno in self.__fd_to_async_socket:
            del self.__fd_to_async_socket[fileno]
        if ((fileno in self.__fds_registered_for_read) or
                (fileno in self.__fds_registered_for_write)):
            self.unregister_for_events(async_socket)
            self.__fds_registered_for_read.discard(fileno)
            self.__fds_registered_for_write.discard(fileno)

    def register_callback_event(self, event):
        self.__event_queue.append(event)

    def register_async_socket_for_read(self, async_socket):
        fileno = async_socket.get_fileno()
        if fileno not in self.__fds_registered_for_read:
            if fileno in self.__fds_registered_for_write:
                self.modify_registration_for_events(
                    async_socket, read_events=True, write_events=True)
            else:
                self.register_for_events(
                    async_socket, read_events=True, write_events=False)
            self.__fds_registered_for_read.add(fileno)

    def unregister_async_socket_for_read(self, async_socket):
        fileno = async_socket.get_fileno()
        if fileno in self.__fds_registered_for_read:
            if fileno in self.__fds_registered_for_write:
                self.modify_registration_for_events(
                    async_socket, read_events=False, write_events=True)
            else:
                self.unregister_for_events(async_socket)
            self.__fds_registered_for_read.discard(fileno)

    def register_async_socket_for_write(self, async_socket):
        fileno = async_socket.get_fileno()
        if fileno not in self.__fds_registered_for_write:
            if fileno in self.__fds_registered_for_read:
                self.modify_registration_for_events(
                    async_socket, read_events=True, write_events=True)
            else:
                self.register_for_events(
                    async_socket, read_events=False, write_events=True)
            self.__fds_registered_for_write.add(fileno)

    def unregister_async_socket_for_write(self, async_socket):
        fileno = async_socket.get_fileno()
        if fileno in self.__fds_registered_for_write:
            if fileno in self.__fds_registered_for_read:
                self.modify_registration_for_events(
                    async_socket, read_events=True, write_events=False)
            else:
                self.unregister_for_events(async_socket)
            self.__fds_registered_for_write.discard(fileno)

    def get_read_fd_set(self):
        return self.__fds_registered_for_read

    def get_write_fd_set(self):
        return self.__fds_registered_for_write

    def get_fd_count(self):
        return len(self.__fd_to_async_socket)

    def register_for_events(self, async_socket, read_events, write_events):
        raise NotImplementedError

    def modify_registration_for_events(self, async_socket, read_events, write_events):
        raise NotImplementedError

    def unregister_for_events(self, async_socket):
        raise NotImplementedError

    def do_poll(self, block):
        raise NotImplementedError

    def run(self):
        while True:
            # As we process events in self.__event_queue, more events are likely
            # to be added to it by invoke_callback.  We don't want to starve events
            # coming in from doPoll, so we limit the number of events processed
            # from self.__event_queue to the initial size of the queue.  After this if
            # the queue is still not empty, set do_poll to be non-blocking, so we get
            # back to processing events in the queue in a timely manner.
            initial_queue_length = len(self.__event_queue)
            events_processed = 0
            while ((len(self.__event_queue) > 0) and
                   (events_processed < initial_queue_length)):
                event = self.__event_queue.popleft()
                event()
                events_processed += 1

            if ((len(self.__event_queue) == 0) and
                    (len(self.__fds_registered_for_read) == 0) and
                    (len(self.__fds_registered_for_write) == 0)):
                break

            block = True
            if len(self.__event_queue) > 0:
                block = False
            self.do_poll(block=block)

    def handle_event_for_fd(self, file_descriptor, read_ready, write_ready, error_ready):
        if file_descriptor in self.__fd_to_async_socket:
            async_socket = self.__fd_to_async_socket[file_descriptor]
            if read_ready:
                async_socket.handle_read()
            if write_ready:
                async_socket.handle_write()
            if error_ready:
                async_socket.handle_errors()


# Windows doesn't have FD polling members, but would be sockets by abstraction.
# pylint: disable=no-member
class EPollAsyncIOService(AsyncIOService):
    """ Event Polling For Async IO Service """

    def __init__(self):
        self.__poller = select.epoll()
        super().__init__()

    def __str__(self):
        return "EPollAsyncIOService [ fileno = %d ]" % self.__poller.fileno()

    def register_for_events(self, async_socket, read_events, write_events):
        fileno = async_socket.get_fileno()
        event_mask = 0
        if read_events:
            event_mask |= select.EPOLLIN
        if write_events:
            event_mask |= select.EPOLLOUT
        self.__poller.register(fileno, event_mask)

    def modify_registration_for_events(self, async_socket, read_events, write_events):
        fileno = async_socket.get_fileno()
        event_mask = 0
        if read_events:
            event_mask |= select.EPOLLIN
        if write_events:
            event_mask |= select.EPOLLOUT
        self.__poller.modify(fileno, event_mask)

    def unregister_for_events(self, async_socket):
        fileno = async_socket.get_fileno()
        self.__poller.unregister(fileno)

    def do_poll(self, block):
        ready_list = self.__poller.poll(-1 if block else 0)
        for (file_descriptor, event_mask) in ready_list:
            read_ready = ((event_mask & select.EPOLLIN) != 0)
            write_ready = ((event_mask & select.EPOLLOUT) != 0)
            error_ready = ((event_mask &
                            (select.EPOLLERR | select.EPOLLHUP)) != 0)
            self.handle_event_for_fd(file_descriptor=file_descriptor,
                                     read_ready=read_ready,
                                     write_ready=write_ready,
                                     error_ready=error_ready)


class KQueueAsyncIOService(AsyncIOService):
    """ KQueue Async IO Service """

    def __init__(self):
        self.__kqueue = select.kqueue()
        super().__init__()

    def __str__(self):
        return "KQueueAsyncIOService [ fileno = %d ]" % self.__kqueue.fileno()

    def register_for_events(self, async_socket, read_events, write_events):
        fileno = async_socket.get_fileno()
        if read_events:
            read_ke = select.kevent(ident=fileno,
                                    filter=select.KQ_FILTER_READ,
                                    flags=select.KQ_EV_ADD)
        else:
            read_ke = select.kevent(ident=fileno,
                                    filter=select.KQ_FILTER_READ,
                                    flags=(select.KQ_EV_ADD | select.KQ_EV_DISABLE))
        if write_events:
            write_ke = select.kevent(ident=fileno,
                                     filter=select.KQ_FILTER_WRITE,
                                     flags=select.KQ_EV_ADD)
        else:
            write_ke = select.kevent(ident=fileno,
                                     filter=select.KQ_FILTER_WRITE,
                                     flags=(select.KQ_EV_ADD | select.KQ_EV_DISABLE))
        # Should be able to put read_ke and write_ke in a list in
        # one call to kqueue.control, but this is broken due to Python issue 5910
        self.__kqueue.control([read_ke], 0, 0)
        self.__kqueue.control([write_ke], 0, 0)

    def modify_registration_for_events(self, async_socket, read_events, write_events):
        fileno = async_socket.get_fileno()
        if read_events:
            read_ke = select.kevent(ident=fileno,
                                    filter=select.KQ_FILTER_READ,
                                    flags=select.KQ_EV_ENABLE)
        else:
            read_ke = select.kevent(ident=fileno,
                                    filter=select.KQ_FILTER_READ,
                                    flags=select.KQ_EV_DISABLE)
        if write_events:
            write_ke = select.kevent(ident=fileno,
                                     filter=select.KQ_FILTER_WRITE,
                                     flags=select.KQ_EV_ENABLE)
        else:
            write_ke = select.kevent(ident=fileno,
                                     filter=select.KQ_FILTER_WRITE,
                                     flags=select.KQ_EV_DISABLE)
        # Should be able to put read_ke and write_ke in a list in
        # one call to kqueue.control, but this is broken due to Python issue 5910
        self.__kqueue.control([read_ke], 0, 0)
        self.__kqueue.control([write_ke], 0, 0)

    def unregister_for_events(self, async_socket):
        fileno = async_socket.get_fileno()
        read_ke = select.kevent(ident=fileno,
                                filter=select.KQ_FILTER_READ,
                                flags=select.KQ_EV_DELETE)
        write_ke = select.kevent(ident=fileno,
                                 filter=select.KQ_FILTER_WRITE,
                                 flags=select.KQ_EV_DELETE)
        # Should be able to put read_ke and write_ke in a list in
        # one call to kqueue.control, but this is broken due to Python issue 5910
        self.__kqueue.control([read_ke], 0, 0)
        self.__kqueue.control([write_ke], 0, 0)

    def do_poll(self, block):
        event_list = self.__kqueue.control(
            None,
            self.get_fd_count() * 2,
            None if block else 0)
        for kqueue_event in event_list:
            file_descriptor = kqueue_event.ident
            read_ready = (kqueue_event.filter == select.KQ_FILTER_READ)
            write_ready = (kqueue_event.filter == select.KQ_FILTER_WRITE)
            error_ready = ((kqueue_event.flags & select.KQ_EV_EOF) != 0)
            self.handle_event_for_fd(file_descriptor=file_descriptor,
                                     read_ready=read_ready,
                                     write_ready=write_ready,
                                     error_ready=error_ready)


class PollAsyncIOService(AsyncIOService):
    """ Polling Async IO Service """

    def __init__(self):
        self.__poller = select.poll()
        super().__init__()

    def __str__(self):
        return "PollAsyncIOService"

    def register_for_events(self, async_socket, read_events, write_events):
        fileno = async_socket.get_fileno()
        event_mask = 0
        if read_events:
            event_mask |= select.POLLIN
        if write_events:
            event_mask |= select.POLLOUT
        self.__poller.register(fileno, event_mask)

    def modify_registration_for_events(self, async_socket, read_events, write_events):
        fileno = async_socket.get_fileno()
        event_mask = 0
        if read_events:
            event_mask |= select.POLLIN
        if write_events:
            event_mask |= select.POLLOUT
        self.__poller.modify(fileno, event_mask)

    def unregister_for_events(self, async_socket):
        fileno = async_socket.get_fileno()
        self.__poller.unregister(fileno)

    def do_poll(self, block):
        ready_list = self.__poller.poll(None if block else 0)
        for (file_descriptor, event_mask) in ready_list:
            read_ready = ((event_mask & select.POLLIN) != 0)
            write_ready = ((event_mask & select.POLLOUT) != 0)
            error_ready = ((event_mask &
                            (select.POLLERR | select.POLLHUP | select.POLLNVAL)) != 0)
            self.handle_event_for_fd(file_descriptor=file_descriptor,
                                     read_ready=read_ready,
                                     write_ready=write_ready,
                                     error_ready=error_ready)


class SelectAsyncIOService(AsyncIOService):
    """ Select Async IO Service """

    # Useless Parent-delegation, No change in signature.
    # def __init__(self):
    #    super().__init__()

    def __str__(self):
        return "SelectAsyncIOService"

    def register_for_events(self, async_socket, read_events, write_events):
        # Not Implemented in this Implementation
        pass

    def modify_registration_for_events(self, async_socket, read_events, write_events):
        # Not Implemented in this Implementation
        pass

    def unregister_for_events(self, async_socket):
        # Not Implemented in this Implementation
        pass

    def do_poll(self, block):
        all_fd_set = self.get_read_fd_set() | self.get_write_fd_set()
        (read_list, write_list, except_list) = \
            select.select(self.get_read_fd_set(), self.get_write_fd_set(), all_fd_set,
                          None if block else 0)
        for file_descriptor in all_fd_set:
            read_ready = file_descriptor in read_list
            write_ready = file_descriptor in write_list
            error_ready = file_descriptor in except_list

            if read_ready or write_ready or error_ready:
                self.handle_event_for_fd(file_descriptor=file_descriptor,
                                         read_ready=read_ready,
                                         write_ready=write_ready,
                                         error_ready=error_ready)


def create_async_io_service(allow_epoll=True,
                            allow_kqueue=True,
                            allow_poll=True):
    """
    Create an AsyncIOService supported by the platform and parameters.
    :param allow_epoll:
    :param allow_kqueue:
    :param allow_poll:
    :return:
    """
    if allow_epoll and hasattr(select, 'epoll'):
        logging.info("create_async_io_service [epoll]")
        return EPollAsyncIOService()
    if allow_kqueue and hasattr(select, 'kqueue'):
        logging.info("create_async_io_service [kqueue]")
        return KQueueAsyncIOService()
    if allow_poll and hasattr(select, 'poll'):
        logging.info("create_async_io_service [poll]")
        return PollAsyncIOService()

    logging.info("create_async_io_service [Select]")
    return SelectAsyncIOService()
