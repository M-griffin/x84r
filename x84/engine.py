#!/usr/bin/env python
"""
Command-line launcher and Async Connection loop for x/84r.
The system waits for Connections Events and spawns unique session instances
Keeping them selves alive with Events and Callbacks.  No Threads per session instance
and no blocking i/o or loops.  All receives data is state tracked and pushed through to the
Interface or script then returns right away for next event.

Michael Griffin
"""
# Place ALL metadata in setup.py, except where not suitable, place here.
# For any contributions, feel free to tag __author__ etc. at top of such file.
__author__ = "Johannes Lundberg (jojo), Jeff Quast (dingo), Michael Griffin (Mercyful Fate)"
__url__ = u'https://github.com/jquast/x84/'
__copyright__ = "Copyright 2003"
__credits__ = [
    # use 'scene' names unless preferred or unavailable.
    "zipe",
    "jojo",
    "maze",
    "dingo",
    "spidy",
    "beardy",
    "haliphax",
    "megagumbo",
    "hellbeard",
    "Mercyful Fate",
]
__license__ = 'ISC'

import logging
import subprocess
import sys
# import os
# import sys

from x84 import asio
from x84 import session
from x84 import session_mgr

MAX_READ_BYTES = 2 ** 16


class TTSHandler(logging.Handler):
    """
    Only Available in Posix is seems !!  Audible speaking logs!
    """
    def emit(self, record):
        msg = self.format(record)
        # Speak slowly in a female English voice
        cmd = ['espeak', '-s150', '-ven+f3', msg]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        # wait for the program to finish
        p.communicate()


def configure_logging():
    """
    Initial Logging Setup, work this into individual sessions logging in the future too.
    :return:
    """
    # console_handler = TTSHandler()
    root = logging.getLogger(__name__)
    root.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    root = logging.getLogger()
    root.addHandler(console_handler)
    # the default formatter just returns the message
    root.setLevel(logging.DEBUG)


class Connection(object):
    """
    Async Connection Object, Unique per each connection
    This gets attached to each new Session Instance
    """

    def __init__(self, io_service, client_socket):
        """
        Startup
        :param io_service:
        :param client_socket:
        """
        self.__ioService = io_service
        self.__dataFromClient = ''
        self.__writingToClient = False
        self.__client_socket = client_socket
        self.__clientHostnameString = ('{peer} -> {name}'.format(peer=self.__client_socket.getpeername(),
                                                                 name=self.__client_socket.getsockname()))

    def close(self) -> None:
        """
        Closes the Socket On Error or Disconnect
        :return:
        """
        if not self.__writingToClient:
            if ((not self.__client_socket.closed()) and
                    (len(self.__clientHostnameString) > 0)):
                logging.info('disconnect %s' % self.__clientHostnameString)

            self.__client_socket.close()

    def get_socket(self) -> object:
        return self.__client_socket


class Acceptor(object):
    """
    Async Connection Handler, Spawn new Session Instances
    Attached the Async Connection object to the session on incoming connections
    """

    def __init__(self, io_service, local_address, local_port):

        self.__io_service = io_service
        self.__async_socket = io_service.createAsyncSocket()
        self.__async_socket.setReuseAddress()
        self.__async_socket.bind((local_address, local_port))
        self.__async_socket.listen()
        self.__async_socket.asyncAccept(self.__accept_callback)

        logging.info('listening for Telnet on %s' % str(self.__async_socket.getsockname()))

    def __accept_callback(self, sock, err) -> None:
        """
        Callback that Spawns the new Session, and attaches to the Session Manager
        :param sock:
        :param err:
        :return:
        """
        if err == 0 and sock is not None:
            logging.info('accept %s -> %s' % (sock.getpeername(), sock.getsockname()))

            ''' Spawn new session instance passing ioService for socket call backs.'''
            logging.info('creating session')
            new_session = session.ClientSession(connection=Connection(self.__io_service, sock))

            logging.info('start_up_async_session')
            new_session.wait_for_async_data()

            # not needed just yet, playing around with singleton!
            # Session Manager should also Determine and assign the session's node number!
            #
            # logger.info('add_session to manager')
            # manager = session_mgr.SessionManager()
            # manager.add_session(new_session)

        else:
            logging.error('Errors during accept callback')

        # Loop back to setup callback event for accepting the next connection
        self.__async_socket.asyncAccept(self.__accept_callback)


def main() -> int:

    configure_logging()

    """
    Main x/84 Command line Telnet Server Startup.
    """

    # Setup Async IO_Service for handling connections
    io_service = asio.createAsyncIOService()
    logging.info('io_service = ' + str(io_service))

    # Setup Acceptor to listen for new telnet connections and spawn sessions '''
    Acceptor(io_service, local_address='0', local_port=6023)

    io_service.run()

    logging.info('shutdown complete')
    return 0


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
