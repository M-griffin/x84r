#!/usr/bin/env python
"""
Command-line launcher and Async Connection loop
The system waits for Connections Events and spawns unique session instances
Keeping themselves alive with Events and Callbacks.  No Threads per session instance
and no blocking i/o or loops.  All received data is state tracked and pushed through to the
Interface or script then returns right away for next event.

Michael Griffin
High Level Shell based off of X/84 BBS, re-written for Python 3 and Extending Concepts.
"""
# Place ALL metadata in setup.py, except where not suitable, place here.
# For any contributions, feel free to tag __author__ etc. at top of such file.
__author__ = "Michael Griffin"
__url__ = "https://github.com/m-griffin"
__copyright__ = "Copyright 2018-2022"
__credits__ = [
    # use 'scene' names unless preferred or unavailable.
    "dingo"
]
__license__ = 'N/A'

import logging

from x84 import asio
from x84 import session

# from x84 import session_mgr

MAX_READ_BYTES = 2 ** 16

# PyLint for some Legacy Python 2 Stuff for Refactoring
"""
    # pylint: disable=consider-using-f-string
    # pylint: disable=logging-not-lazy
"""


def configure_logging():
    """
    Initial Logging Setup, work this into individual sessions logging in the future too.
    :return:
    """

    root = logging.getLogger(__name__)
    root.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # formatter = logging.Formatter('%(asctime)s - %(name)s[%(levelname)s]: %(message)s')
    # logging.basicConfig(format="{processName:<12} {message} ({filename}:{lineno})", style="{")
    formatter = logging.Formatter(
        "{asctime} - {processName:<12} [{levelname}]: {message} ({filename}:{lineno})", style="{")

    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # Reset the Root Logger Now.
    root = logging.getLogger()
    root.addHandler(console_handler)
    root.setLevel(logging.INFO)


class Connection:
    """
    Async Connection Object, Unique per each connection
    This gets attached to each new Session Instance
    """

    def __init__(self, client_socket):
        """
        Startup
        :param client_socket:
        """
        # pylint: disable=unused-private-member
        self.__data_from_client = ''
        self.__writing_to_client = False
        self.__client_socket = client_socket
        self.__client_hostname_string = ("%s -> %s",
                                         self.__client_socket.get_peer_name(),
                                         self.__client_socket.get_socket_name())

    def close(self) -> None:
        """
        Closes the Socket On Error or Disconnect
        :return:
        """
        if not self.__writing_to_client:
            if ((not self.__client_socket.closed()) and
                    (len(self.__client_hostname_string) > 0)):
                logging.info('disconnect %s', self.__client_hostname_string)

            self.__client_socket.close()

    def get_socket(self) -> object:
        """ Retrieve Socket handle """
        return self.__client_socket


# pylint: disable=too-few-public-methods
class Acceptor:
    """
    Async Connection Handler, Spawn new Session Instances
    Attached the Async Connection object to the session on incoming connections
    """

    def __init__(self, io_service, local_address, local_port):

        self.__io_service = io_service
        self.__async_socket = self.__io_service.create_async_socket()
        self.__async_socket.set_reuse_address()
        self.__async_socket.bind((local_address, local_port))
        self.__async_socket.listen()
        self.__async_socket.async_accept(self.__accept_callback)

        logging.info('listening for Telnet on %s', self.__async_socket.get_socket_name())

    def __accept_callback(self, sock, err) -> None:
        """
        Callback that Spawns the new Session, and attaches to the Session Manager
        :param sock:
        :param err:
        :return:
        """
        if err == 0 and sock is not None:
            logging.info('accept %s -> %s', sock.get_peer_name(), sock.get_socket_name())

            # Spawn new session instance passing ioService for socket call backs.
            logging.info("creating session")
            new_session = session.ClientSession(connection=Connection(sock))

            logging.info("start_up_async_session")
            new_session.wait_for_async_data()

            # not needed just yet, playing around with singleton!
            # Session Manager should also Determine and assign the session's node number!
            #
            # logger.info('add_session to manager')
            # manager = session_mgr.SessionManager()
            # manager.add_session(new_session)

        else:
            logging.error("Errors during accept callback")

        # Loop back to set up callback event for accepting the next connection
        self.__async_socket.async_accept(self.__accept_callback)


def main() -> int:
    """ Main x/84 Command line Telnet Server Startup. """

    configure_logging()

    # Setup Async IO_Service for handling connections
    io_service = asio.create_async_io_service()

    # logging.info('io_service = ' + str(io_service))
    logging.info('io_service = %s', io_service)

    # Setup Acceptor to listen for new telnet connections and spawn sessions '''
    # Using 127.0.0.1 will only allow local host connection,
    # using 0.0.0.0 open up to external connections.
    # Acceptor(io_service, local_address='127.0.0.1', local_port=6023)
    Acceptor(io_service, local_address='0.0.0.0', local_port=6023)

    logging.info('starting service = %s', io_service)
    io_service.run()

    logging.info('shutdown complete')
    return 0


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
