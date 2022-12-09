# -*- coding: utf-8 -*-
"""
Async Session engine for x/84.
Each connection generates its own session instance
Async Reads Events keeps the session and instance alive with callbacks

Data is parsed into a read buffers, parsed through TelnetOptionParsing then pushed
Through to the script or interface.  No while loops or waiting for data (Non Blocking IO)

Michael Griffin
"""

# std imports
import collections
import logging
import time

from colors import color

from x84.telnet import TelnetNegotiation, TelnetOptionParser

# local
# from x84.bbs.exception import Disconnected, Goto
# from x84.bbs.script_def import Script
# from x84.bbs.userbase import User
# from x84.bbs.ini import get_ini

MAX_READ_BYTES = 2 ** 16


def configure_logging():
    """
    Standard Logging, work this into individual sessions in the future.
    :return:
    """
    # console_handler = TTSHandler()
    root = logging.getLogger('node_' + __name__)
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


# pylint: disable=too-many-instance-attributes
class ClientSession:
    """
    Asynchronous client session unique per connection
    """
    __telnet_parser = None
    __message_queue = None
    __connection = None
    __client_socket = None
    __logger = None
    __is_active = False
    __is_detection_completed = False

    # Not used yet.
    __encoding = None
    __decoder = None
    __activity = None
    __user = None

    # Not used yet!
    script_module = []

    #: Override in subclass: a general string identifier for the
    #: connecting protocol (for example, 'telnet', 'ssh', 'rlogin')
    kind = None

    #: terminal type identifier when not yet negotiated
    TTYPE_UNDETECTED = 'unknown'
    addr_port = None

    # pylint: disable=unused-argument
    def __new__(cls, connection):
        """
        Each Connection will have its own unique instance created
        :param connection:
        :return:
        """
        return object.__new__(cls)

    def __init__(self, connection):
        """
        Async_Connection is passed from the Acceptor
        We then instantiate the Telnet Option Parser for
            1. Sending Initial Negotiation Options
            2. Ongoing parsing of telnet commands received from client.

        :param connection:
        """
        self.__connection = connection
        self.__client_socket = self.__connection.get_socket()
        self.__telnet_startup = TelnetNegotiation(session_handle=self)
        self.__telnet_parser = TelnetOptionParser(session_handle=self)

        # Figure out better way to handle the logger.
        # configure_logging()
        logging.info('session __init__')

        self.__is_active = True
        self.__is_detection_completed = False

        # Accessible from other classes
        self.env = dict([('TERM', self.TTYPE_UNDETECTED),
                         ('LINES', 24),
                         ('COLUMNS', 80),
                         ('connection-type', self.kind),
                         ])

        self.receive_buffer = collections.deque()

        self.connect_time = time.time()
        self.last_input_time = time.time()

        self.addr_port = connection.get_socket().get_peer_name()

        """ Start the Telnet Banner Negotiation """
        self.__telnet_startup.run_telnet_startup()

    def idle(self) -> float:
        """ Time elapsed since data was last received. """
        return time.time() - self.last_input_time

    def duration(self) -> float:
        """ Time elapsed since connection was made. """
        return time.time() - self.connect_time

    def is_active(self) -> bool:
        """ Track if the session is still active or disconnecting """
        return self.__is_active

    def async_read(self) -> None:
        """
        Sets up a Read Callback Handler, when data is received it will execute
        the associated callback with the data.  (Non-Blocking)
        :return:
        """
        if self.__is_active:
            # logging.info('session asyncRead')
            self.__client_socket.async_read(MAX_READ_BYTES, self.__async_read_callback)

    def __async_read_callback(self, data, err) -> None:
        """
        Read Callback Handler, data is returned here when received from the client
        Also calls back to wait_for_async_data() which then waits for the next
        data event to come in.  If this loop is broken, then the connection is usually closed.
        Data = ByteArrays
        :return:
        """
        if err != 0:
            logging.info('async_read (1): disconnected')
            self.close()
        elif not data:
            logging.info('async_read (2): disconnected')
            self.close()
        elif self.__is_active:
            # Push incoming data through Telnet Option Parser.
            self.receive_buffer.clear()
            for byte in data:
                # Add parsed text data
                return_byte = self.__telnet_parser.iac_sniffer(bytes([byte]))
                if return_byte is not None:
                    # logging.info('byte received: {byte}'.format(byte=return_byte))
                    # bytes_parsed = bytes_parsed + return_byte
                    self.receive_buffer.append(return_byte)

            # Data other than Telnet Options, then send back to client. or push through system!!
            if len(self.receive_buffer) > 0:
                # This should now be pushed through for
                # Input on the STATE instead of echoed back!
                logging.info("Echo %s", self.receive_buffer)
                self.async_write(b''.join(self.receive_buffer))

            # Ready for next set of incoming data
            self.wait_for_async_data()

    def async_write(self, data) -> None:
        """
        Async Write Handler, sends data to the client (Non-Blocking)
        Errors are handled in the callback handler.
        Data = ByteArrays
        :return:
        """
        if data and self.__is_active:
            # logging.info('async_write: ' + str(data))
            self.__client_socket.async_write_all(data, self.__async_write_callback)

        # logging.info('async_write done')

    def __async_write_callback(self, err) -> None:
        """ Async Callback, executed once data is received """
        if err != 0:
            logging.info('async_write: disconnected')
            self.close()
        # elif self.__is_active:
        # Data was writen to socket.  just handle errors if any.
        # logging.info('async_write: OK')

    def close(self) -> None:
        """ Close and shutdown sockets and connection """
        self.__is_active = False
        if self.__connection is not None:
            self.__connection.close()

    def wait_for_async_data(self) -> None:
        """ Startup Async Waiting for Data """
        if self.__is_active:
            self.async_read()

    def is_detection_complete(self) -> bool:
        """ If Terminal Negotiation is still in progress """
        return self.__is_detection_completed

    def format_byte_string(self, value, encoding, use_newline) -> bytes:
        """ Quick Formatting, more from Common IO """

        val = use_newline or b'\r\n'
        str_detect = b'%s' % bytes([value, val], encoding=encoding)
        return str_detect

    def async_timeout_callback(self) -> None:
        """
        Callback for Async Telnet Negotiation Timeout
        :return:
        """

        # Use detected output encoding
        encoding = self.env.get('ENCODING', 'ascii')

        # Pull final encoding detected into session
        self.__telnet_startup.set_encoding()
        self.async_write(bytes(color(
            'Terminal Detection Completed.\r\n', fg='blue', style='bold'), encoding=encoding))

        self.__is_detection_completed = True

        # Print out initial detection
        str_detect = b'\r\n'
        str_detect += b'term     : %s \r\n' \
                      % bytes(self.env.get('TERM', None), encoding=encoding)
        str_detect += b'encoding : %s \r\n' \
                      % bytes(self.env.get('ENCODING', None), encoding=encoding)
        str_detect += b'lines    : %s \r\n' \
                      % bytes(self.env.get('LINES', None), encoding=encoding)
        str_detect += b'cols     : %s \r\n\r\n' \
                      % bytes(self.env.get('COLUMNS', None), encoding=encoding)
        self.async_write(str_detect)
