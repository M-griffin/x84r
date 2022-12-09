"""
Telnet server for x84.
Converted 5/6/2018 to more of a Telnet Parser then a session spawn.

Limitations:

- No linemode support, character-at-a-time only.
- No out-of-band / data mark (DM) / sync supported
- No flow control (``^S``, ``^Q``)

This is a modified version of miniboa retrieved from svn address
http://miniboa.googlecode.com/svn/trunk/miniboa which is meant for
MUD's. This server would not be safe for most (linemode) MUD clients.

Changes from miniboa:

- character-at-a-time input instead of linemode
- encoding option on send
- strict rejection of linemode
- terminal type detection
- environment variable support
- GA and SGA
- utf-8 safe
"""

from __future__ import absolute_import

import collections
import itertools
import logging

from telnetlib3 import BINARY, SGA, ECHO, STATUS, TTYPE, TSPEED, LFLOW
from telnetlib3 import IP, AO, AYT, EC, EL, GA, SB
from telnetlib3 import LINEMODE, NAWS, NEW_ENVIRON, ENCRYPT, AUTHENTICATION
from telnetlib3 import XDISPLOC, IAC, DONT, DO, WONT, WILL, SE, NOP, DM, BRK

# Not sure why this is complaining, it's working and appears correct.
# pylint: disable=import-error
from x84.deadline_timer import DeadLineTimer

# Some Pylint Items to Disable, until more time to rewrite
# Majority was Python 2 Code rewritten.
# pylint: disable=logging-format-interpolation
# pylint: disable=consider-using-f-string
# pylint: disable=too-many-branches
# pylint: disable=logging-not-lazy
# pylint: disable=consider-using-generator

# ------------------------------------------------------------------------------
#   miniboa/async.py
#   miniboa/telnet.py
#
#   Copyright 2009 Jim Storch
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain a
#   copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
# ------------------------------------------------------------------------------


IS = bytes([0])  # Sub-process negotiation IS command
SEND = bytes([1])  # Sub-process negotiation SEND command
UNSUPPORTED_WILL = (LINEMODE, LFLOW, TSPEED, ENCRYPT, AUTHENTICATION)

# ---[ Telnet Notes ]-----------------------------------------------------------
# (See RFC 854 for more information)
#
# Negotiating a Local Option
# --------------------------
#
# Side A begins with:
#
#    "IAC WILL/WONT XX"   Meaning "I would like to [use|not use] option XX."
#
# Side B replies with either:
#
#    "IAC DO XX"     Meaning "OK, you may use option XX."
#    "IAC DONT XX"   Meaning "No, you cannot use option XX."
#
#
# Negotiating a Remote Option
# ----------------------------
#
# Side A begins with:
#
#    "IAC DO/DONT XX"  Meaning "I would like YOU to [use|not use] option XX."
#
# Side B replies with either:
#
#    "IAC WILL XX"   Meaning "I will begin using option XX"
#    "IAC WONT XX"   Meaning "I will not begin using option XX"
#
#
# The syntax is designed so that if both parties receive simultaneous requests
# for the same option, each will see the other's request as a positive
# acknowledgment of it's own.
#
# If a party receives a request to enter a mode that it is already in, the
# request should not be acknowledged.

# Where you see DE in my comments I mean 'Distant End', e.g. the client.

UNKNOWN = -1

# -----------------------------------------------------------------Telnet Option

# pylint: disable=consider-using-dict-comprehension
#: List of globals that may match an iac command option bytes
_DEBUG_OPTS = dict([(value, key)
                    for key, value in globals().items() if key in
                    ('LINEMODE', 'LMODE_FORWARDMASK', 'NAWS', 'NEW_ENVIRON',
                     'ENCRYPT', 'AUTHENTICATION', 'BINARY', 'SGA', 'ECHO',
                     'STATUS', 'TTYPE', 'TSPEED', 'LFLOW', 'XDISPLOC', 'IAC',
                     'DONT', 'DO', 'WONT', 'WILL', 'SE', 'NOP', 'DM', 'TM',
                     'BRK', 'IP', 'ABORT', 'AO', 'AYT', 'EC', 'EL', 'EOR',
                     'GA', 'SB', 'EOF', 'SUSP', 'ABORT', 'CMD_EOR', 'LOGOUT',
                     'CHARSET', 'SNDLOC', 'MCCP_COMPRESS', 'MCCP2_COMPRESS',
                     'ENCRYPT', 'AUTHENTICATION', 'TN3270E', 'XAUTH', 'RSP',
                     'COM_PORT_OPTION', 'SUPPRESS_LOCAL_ECHO', 'TLS',
                     'KERMIT', 'SEND_URL', 'FORWARD_X', 'PRAGMA_LOGON',
                     'SSPI_LOGON', 'PRAGMA_HEARTBEAT', 'EXOPL', 'X3PAD',
                     'VT3270REGIME', 'TTYLOC', 'SUPDUPOUTPUT', 'SUPDUP',
                     'DET', 'BM', 'XASCII', 'RCP', 'NAMS', 'RCTE', 'NAOL',
                     'NAOP', 'NAOCRD', 'NAOHTS', 'NAOHTD', 'NAOFFD', 'NAOVTS',
                     'NAOVTD', 'NAOLFD',)])


def name_command(byte):
    """Return string description for (maybe) telnet command byte."""
    return _DEBUG_OPTS.get(byte, repr(byte))


def name_commands(cmds, sep=' '):
    """Return string description for array of (maybe) telnet command bytes."""
    return sep.join([name_command(bytes([byte])) for byte in cmds])


class TelnetOption:
    """
    Simple class used to track the status of an extended Telnet option.

    Attributes and their state values:

    - ``local_option``: UNKNOWN (default), True, or False.
    - ``remote_option``: UNKNOWN (default), True, or False.
    - ``reply_pending``: True or Fale.
    """

    # pylint: disable=R0903
    #         Too few public methods (0/2)

    def __init__(self):
        """
        Set attribute defaults on init.
        """
        self.local_option = UNKNOWN  # Local state of an option
        self.remote_option = UNKNOWN  # Remote state of an option
        self.reply_pending = False  # Are we expecting a reply?


# ------------------------------------------------------------------------Telnet

class TelnetOptionParser:
    """
    Represents a remote Telnet Client, instantiated from TelnetServer.
    """
    # pylint: disable=R0902,R0904
    #         Too many instance attributes
    #         Too many public methods

    kind = 'telnet'
    env_requested = False
    env_replied = False

    #: maximum size of telnet sub-negotiation string, allowing for a fairly
    #: large value for NEW_ENVIRON.
    MAX_LENGTH = 65534
    __session = None

    def __init__(self, session_handle):

        self.__session = session_handle
        self.env_requested = False
        self.env_replied = False
        self.telnet_sb_buffer = collections.deque()

        # State variables for interpreting incoming telnet commands
        self.telnet_got_iac = False
        self.telnet_got_cmd = None
        self.telnet_got_sb = False
        self.telnet_opt_dict = {}

    def is_active(self) -> bool:
        """ Check if Session Is Still Active """
        return self.__session.is_active()

    def send_str(self, data: bytes) -> None:
        """
        Sends Byte Array from String to Client
        :return:
        """
        self.__session.async_write(data)

    def request_will_sga(self) -> None:
        """
        Request DE to Suppress Go-Ahead.  See RFC 858.
        """
        self._iac_will(SGA)
        self._note_reply_pending(SGA, True)

    def request_will_echo(self) -> None:
        """
        Tell the DE that we would like to echo their text.  See RFC 857.
        """
        self._iac_will(ECHO)
        self._note_reply_pending(ECHO, True)

    def request_will_binary(self) -> None:
        """
        Tell the DE that we would like to use binary 8-bit (utf8).
        """
        self._iac_will(BINARY)
        self._note_reply_pending(BINARY, True)

    def request_do_binary(self) -> None:
        """
        Tell the DE that we would like them to input binary 8-bit (utf8).
        """
        self._iac_do(BINARY)
        self._note_reply_pending(BINARY, True)

    def request_do_sga(self) -> None:
        """
        Request to Negotiate SGA.  See ...
        """
        self._iac_do(SGA)
        self._note_reply_pending(SGA, True)

    def request_do_naws(self) -> None:
        """
        Request to Negotiate About Window Size.  See RFC 1073.
        """
        self._iac_do(NAWS)
        self._note_reply_pending(NAWS, True)

    def request_do_env(self) -> None:
        """
        Request to Negotiate About Window Size.  See RFC 1073.
        """
        self._iac_do(NEW_ENVIRON)
        self._note_reply_pending(NEW_ENVIRON, True)

    def request_env(self) -> None:
        """
        Request sub-negotiation NEW_ENVIRON. See RFC 1572.
        """
        if self.env_requested:
            # avoid asking twice ..
            return

        rstr = b''.join([IAC, SB, NEW_ENVIRON, SEND, BINARY, SGA])
        rstr += bytes(str("USER TERM SHELL COLUMNS LINES C_CTYPE XTERM_LOCALE DISPLAY "
                          "SSH_CLIENT SSH_CONNECTION SSH_TTY HOME HOSTNAME PWD MAIL LANG "
                          "PWD UID USER_ID EDITOR LOGNAME".split()), encoding='utf8')

        rstr += b''.join([SGA, IAC, SE])
        self.env_requested = True
        self.send_str(rstr)

    def request_do_ttype(self) -> None:
        """
        Begins TERMINAL-TYPE negotiation
        """
        if self.check_remote_option(TTYPE) in (False, UNKNOWN):
            self._iac_do(TTYPE)
            self._note_reply_pending(TTYPE, True)

    def request_ttype(self) -> None:
        """
        Sends IAC SB TTYPE SEND IAC SE
        """
        self.send_str(b''.join([IAC, SB, TTYPE, SEND, IAC, SE]))

    def send_unicode(self, ucs, encoding='utf8') -> None:
        """ Buffer unicode string, encoded for client as 'ENCODING'. """
        # Must be escaped 255 (IAC + IAC) to avoid IAC interpretation.
        self.send_str(ucs.encode(encoding, 'replace').replace(IAC, 2 * IAC))

    # Commented out, Not used at this time.
    # def _recv_byte(self, byte) -> None:
    #    """
    #    Buffer non-telnet commands byte strings into recv_buffer.
    #    """
    #    self.recv_buffer.fromstring(byte)

    def iac_sniffer(self, byte: bytes):
        """
        Watches incoming data for Telnet IAC sequences.
        Passes the data, if any, with the IAC commands stripped to
        _recv_byte().
        """
        # Are we not currently in an IAC sequence coming from the DE?
        if self.telnet_got_iac is False:
            if byte == IAC:
                self.telnet_got_iac = True
            # Are we currently in a sub-negotiation?
            elif self.telnet_got_sb is True:
                self.telnet_sb_buffer.append(byte)
                # Sanity check on length
                if len(self.telnet_sb_buffer) > (1 << 15):  # 32k SB buffer
                    # Disconnect and close
                    self.__session.close()
            else:
                # Just a normal NVT character
                # logging.info('return sniff {byte}: '.format(byte=byte))
                # return bytes([byte])
                # self._recv_byte(byte)
                return byte

            # None
            return None

        # Did we get sent a second IAC?
        if byte == IAC and self.telnet_got_sb is True:
            # Must be an escaped 255 (IAC + IAC)
            self.telnet_sb_buffer.append(byte)
            self.telnet_got_iac = False

        # Do we already have an IAC + CMD?
        elif self.telnet_got_cmd is not None:
            # Yes, so handle the option
            self._three_byte_cmd(byte)

        # We have IAC but no CMD
        else:
            # Is this the middle byte of a three-byte command?
            if byte in ([DO, DONT, WILL, WONT]):
                self.telnet_got_cmd = byte
            else:
                # Nope, must be a two-byte command
                self._two_byte_cmd(byte)

        return None

    def _two_byte_cmd(self, cmd):
        """
        Handle incoming Telnet commands that are two bytes long.
        """

        logging.info('recv _two_byte_cmd %s', name_command(cmd))

        if cmd == SB:
            # Begin capturing a sub-negotiation string
            self.telnet_got_sb = True
            self.telnet_sb_buffer.clear()
        elif cmd == SE:
            # Stop capturing a sub-negotiation string
            self.telnet_got_sb = False
            self._sb_decoder()
        elif cmd == IAC:
            # IAC, IAC is used for a literal \xff character.
            # self._recv_byte(IAC)
            return bytes([IAC])
        elif cmd == IP:
            # Disconnect and close
            self.__session.close()
            logging.info('{client.addr_port} received (IAC, IP): closing.'
                         .format(client=self.__session))
        elif cmd == AO:
            logging.warning('Abort Output (AO) received; ignored.')
        elif cmd == AYT:
            self.send_str(bytes('\b'))
            logging.info('Are You There (AYT); "\\b" sent.')
        elif cmd == EC:
            logging.warning('Erase Character (EC) received; ignored.')
        elif cmd == EL:
            logging.warning('Erase Line (EL) received; ignored.')
        elif cmd == GA:
            logging.warning('Go Ahead (GA) received; ignored.')
        elif cmd == NOP:
            logging.info('NUL ignored.')
        elif cmd == DM:
            logging.warning('Data Mark (DM) received; ignored.')
        elif cmd == BRK:
            logging.warning('Break (BRK) received; ignored.')
        else:
            logging.error('_two_byte_cmd invalid: %r', cmd)

        self.telnet_got_iac = False
        self.telnet_got_cmd = None

        return None

    def _three_byte_cmd(self, option) -> None:
        """
        Handle incoming Telnet commands that are three bytes long.
        """
        cmd = bytes(self.telnet_got_cmd)

        logging.info('recv IAC %s %s', name_command(cmd), name_command(option))

        # Incoming DO and DON'T refer to the status of this end
        if cmd == DO:
            self._handle_do(option)
        elif cmd == DONT:
            self._handle_dont(option)
        elif cmd == WILL:
            self._handle_will(option)
        elif cmd == WONT:
            self._handle_wont(option)
        else:
            logging.info('{client.addr_port}: unhandled _three_byte_cmd: {opt}.'
                         .format(client=self.__session, opt=name_command(option)))

        self.telnet_got_iac = False
        self.telnet_got_cmd = None

    def _handle_do(self, option) -> None:
        """
        Process a DO command option received by DE.
        """
        # pylint: disable=R0912
        #         TelnetClient._handle_do: Too many branches (13/12)
        # if any pending WILL options were send, they have been received
        self._note_reply_pending(option, False)
        if option == ECHO:
            # DE requests us to echo their input
            if self.check_local_option(ECHO) is not True:
                self._note_local_option(ECHO, True)
                self._iac_will(ECHO)
        elif option == BINARY:
            # DE requests to recv BINARY
            if self.check_local_option(BINARY) is not True:
                self._note_local_option(BINARY, True)
                self._iac_will(BINARY)
        elif option == SGA:
            # DE wants us to supress go-ahead
            if self.check_local_option(SGA) is not True:
                self._note_local_option(SGA, True)
                # always send DO SGA after WILL SGA, requesting the DE
                # also supress their go-ahead. this order seems to be the
                # 'magic sequence' to disable linemode on certain clients
                self._iac_will(SGA)
                self._iac_do(SGA)
        elif option == LINEMODE:
            # DE wants to do linemode editing
            # denied
            if self.check_local_option(option) is not False:
                self._note_local_option(option, False)
                self._iac_wont(LINEMODE)
        elif option == ENCRYPT:
            # DE is willing to receive encrypted data
            # denied
            if self.check_local_option(option) is not False:
                self._note_local_option(option, False)
                # let DE know we refuse to send encrypted data.
                self._iac_wont(ENCRYPT)
        elif option == STATUS:
            # DE wants to know if we support STATUS,
            if self.check_local_option(option) is not True:
                self._note_local_option(option, True)
                self._iac_will(STATUS)
                self._send_status()
        else:
            if self.check_local_option(option) is UNKNOWN:
                self._note_local_option(option, False)
                logging.info('{client.addr_port}: unhandled do: {opt}.'
                             .format(client=self.__session, opt=name_command(option)))
                self._iac_wont(option)

    def _send_status(self) -> None:
        """
        Process a DO STATUS sub-negotiation received by DE. (rfc859)
        """
        # warning:
        rstr = b''.join([IAC, SB, STATUS, IS])
        for opt, status in self.telnet_opt_dict.items():

            # my_want_state_is_will
            if status.local_option is True:
                logging.info('send WILL %s', name_command(opt))
                rstr += b''.join([WILL, opt])
            elif status.reply_pending is True and opt in (ECHO, SGA):
                logging.info('send WILL %s (want)', name_command(opt))
                rstr += b''.join([WILL, opt])
            # his_want_state_is_will
            elif status.remote_option is True:
                logging.info('send DO %s', name_command(opt))
                rstr += b''.join([DO, opt])
            elif status.reply_pending is True and opt in (NEW_ENVIRON, NAWS, TTYPE):
                logging.info('send DO %s (want)', name_command(opt))
                rstr += b''.join([DO, opt])

        rstr += b''.join([IAC, SE])
        logging.info('send %s', ' '.join(name_command(opt) for opt in rstr))
        self.send_str(rstr)

    def _handle_dont(self, option) -> None:
        """
        Process a DONT command option received by DE.
        """
        self._note_reply_pending(option, False)
        if option == ECHO:
            # client demands we do not echo
            if self.check_local_option(ECHO) is not False:
                self._note_local_option(ECHO, False)
        elif option == BINARY:
            # client demands no binary mode
            if self.check_local_option(BINARY) is not False:
                self._note_local_option(BINARY, False)
        elif option == SGA:
            # DE demands that we start or continue transmitting
            # GAs (go-aheads) when transmitting data.
            if self.check_local_option(SGA) is not False:
                self._note_local_option(SGA, False)
        elif option == LINEMODE:
            # client demands no linemode.
            if self.check_remote_option(LINEMODE) is not False:
                self._note_remote_option(LINEMODE, False)
        else:
            logging.info('{client.addr_port}: unhandled dont: {opt}.'
                         .format(client=self.__session, opt=name_command(option)))

    def _handle_will(self, option) -> None:
        """
        Process a WILL command option received by DE.
        """
        # pylint: disable=R0912
        #        Too many branches (19/12)
        self._note_reply_pending(option, False)
        if option == ECHO:
            # Disconnect and close
            self.__session.close()
            # 'Refuse WILL ECHO by client, closing connection.')
        elif option == BINARY:
            if self.check_remote_option(BINARY) is not True:
                self._note_remote_option(BINARY, True)
                # agree to use BINARY
                self._iac_do(BINARY)
        elif option == NAWS:
            if self.check_remote_option(NAWS) is not True:
                self._note_remote_option(NAWS, True)
                self._note_local_option(NAWS, True)
                # agree to use NAWS, / go ahead ?
                self._iac_do(NAWS)
        elif option == STATUS:
            if self.check_remote_option(STATUS) is not True:
                self._note_remote_option(STATUS, True)
                self.send_str(b''.join([IAC, SB, STATUS, SEND, IAC, SE]))  # go ahead
        elif option in UNSUPPORTED_WILL:
            if self.check_remote_option(option) is not False:
                # let DE know we refuse to do linemode, encryption, etc.
                self._iac_dont(option)
        elif option == SGA:
            #  IAC WILL SUPPRESS-GO-AHEAD
            #
            # The sender of this command requests permission to begin
            # suppressing transmission of the TELNET GO AHEAD (GA)
            # character when transmitting data characters, or the
            # sender of this command confirms it will now begin suppressing
            # transmission of GAs with transmitted data characters.
            if self.check_remote_option(SGA) is not True:
                # sender of this command confirms that the sender of data
                # is expected to suppress transmission of GAs.
                self._iac_do(SGA)
                self._note_remote_option(SGA, True)
        elif option == NEW_ENVIRON:
            if self.check_remote_option(NEW_ENVIRON) in (False, UNKNOWN):
                self._note_remote_option(NEW_ENVIRON, True)
                self.request_env()
            self._note_local_option(NEW_ENVIRON, True)
        elif option == XDISPLOC:
            # if they want to send it, go ahead.
            if self.check_remote_option(XDISPLOC):
                self._note_remote_option(XDISPLOC, True)
                self._iac_do(XDISPLOC)
                self.send_str(b''.join([IAC, SB, XDISPLOC, SEND, IAC, SE]))
        elif option == TTYPE:
            if self.check_remote_option(TTYPE) in (False, UNKNOWN):
                self._note_remote_option(TTYPE, True)
                self.request_ttype()
        else:
            logging.info('{client.addr_port}: unhandled will: {opt} (ignored).'
                         .format(client=self.__session, opt=name_command(option)))

    def _handle_wont(self, option) -> None:
        """
        Process a WONT command option received by DE.
        """
        # pylint: disable=R0912
        #         TelnetClient._handle_wont: Too many branches (13/12)
        self._note_reply_pending(option, False)
        if option == ECHO:
            if self.check_remote_option(ECHO) in (True, UNKNOWN):
                self._note_remote_option(ECHO, False)
                self._iac_dont(ECHO)
        elif option == BINARY:
            # client demands no binary mode
            if self.check_remote_option(BINARY) in (True, UNKNOWN):
                self._note_remote_option(BINARY, False)
                self._iac_dont(BINARY)
        elif option == SGA:
            if self._check_reply_pending(SGA):
                self._note_reply_pending(SGA, False)
                self._note_remote_option(SGA, False)
            elif self.check_remote_option(SGA) in (True, UNKNOWN):
                self._note_remote_option(SGA, False)
                self._iac_dont(SGA)
        elif option == TTYPE:
            if self._check_reply_pending(TTYPE):
                self._note_reply_pending(TTYPE, False)
                self._note_remote_option(TTYPE, False)
            elif self.check_remote_option(TTYPE) in (True, UNKNOWN):
                self._note_remote_option(TTYPE, False)
                self._iac_dont(TTYPE)
        elif option in (NEW_ENVIRON, NAWS):
            if self._check_reply_pending(option):
                self._note_reply_pending(option, False)
                self._note_remote_option(option, False)
            elif self.check_remote_option(option) in (True, UNKNOWN):
                self._note_remote_option(option, False)
        else:
            logging.info('{client.addr_port}: unhandled wont: {opt}.'
                         .format(client=self.__session, opt=name_command(option)))
            self._note_remote_option(option, False)

    def _sb_decoder(self) -> None:
        """
        Figures out what to do with a received sub-negotiation block.
        """
        buf = self.telnet_sb_buffer
        if 0 == len(buf):
            logging.error('nil SB')
            return

        logging.info('recv [SB]: %s %s',
                     name_command(buf[0]),
                     'IS %r' % (collections.deque(itertools.islice(buf, 2, len(buf))),)
                     if len(buf) > 1 and buf[1] is IS
                     else repr(collections.deque(itertools.islice(buf, 1, len(buf)))))

        if 1 == len(buf) and buf[0] == BINARY:
            logging.error('0nil SB')
            return

        if len(buf) < 2:
            logging.error('SB too short')
            return

        if buf[0] in (TTYPE, XDISPLOC, NEW_ENVIRON, NAWS, STATUS):
            cmd = buf.popleft()
            opt = b''

            # Naws has no option
            if cmd != NAWS:
                opt = buf.popleft()

            if cmd == TTYPE and opt == IS:
                # logging.error('TTYPE')
                self._sb_ttype(buf)

            elif cmd == XDISPLOC and opt == IS:
                # logging.error('XDISPLOC')
                self._sb_xdisploc(buf)

            elif cmd == NEW_ENVIRON and opt == IS:
                # logging.error('NEW_ENVIRON')
                self._sb_env(buf)

            elif cmd == NAWS:
                # logging.error('NAWS')
                self._sb_naws(buf)

            elif cmd == STATUS and opt == SEND:
                # logging.error('STATUS')
                self._send_status()

        else:
            logging.error('unsupported sub negotiation, %s: %r', name_command(buf[0]), buf)

        self.telnet_sb_buffer.clear()

    def _sb_xdisploc(self, bytestring) -> None:
        """
        Process incoming sub-negotiation XDISPLOC
        """
        prev_display = self.__session.env.get('DISPLAY', None)
        if prev_display is None:
            logging.info("env['DISPLAY'] = %r.", bytestring)
        elif prev_display != bytestring:
            logging.info("env['DISPLAY'] = %r by XDISPLOC was:%s.",
                         bytestring, prev_display)
        else:
            logging.info('XDSIPLOC ignored (DISPLAY already set).')
        self.__session.env['DISPLAY'] = bytestring

    def _sb_ttype(self, bytestring) -> None:
        """
        Processes incoming subnegotiation TTYPE
        """
        ttype_str = b''.join(bytestring).decode('ascii')

        prev_term = self.__session.env.get('TERM', None)
        if prev_term is None:
            logging.info("env['TERM'] = %r.", ttype_str)

        elif prev_term != ttype_str:
            logging.info("env['TERM'] = %r by TTYPE%s.", ttype_str,
                         ', was: %s' % (prev_term,)
                         if prev_term != self.__session.TTYPE_UNDETECTED else '')
        else:
            logging.info('TTYPE ignored (TERM already set).')

        self.__session.env['TERM'] = ttype_str

    def _sb_env(self, bytestring) -> None:
        """
        Processes incoming sub-negotiation NEW_ENVIRON
        """
        breaks = list([idx for (idx, byte) in enumerate(bytestring)
                       if byte in (BINARY, SGA)])

        for start, end in zip(breaks, breaks[1:]):

            pair = bytestring[start + 1:end].split(chr(1))
            if len(pair) == 1:
                if (pair[0] in self.__session.env
                        and pair[0] not in ('LINES', 'COLUMNS', 'TERM')):
                    logging.warning("del env[%r]", pair[0])
                    del self.__session.env[pair[0]]

            elif len(pair) == 2:
                if pair[0] == 'TERM':
                    pair[1] = pair[1].lower()
                overwrite = (pair[0] == 'TERM'
                             and self.__session.env['TERM'] == self.__session.TTYPE_UNDETECTED)

                if pair[0] not in self.__session.env or overwrite:
                    logging.info('env[%r] = %r', pair[0], pair[1])
                    self.__session.env[pair[0]] = pair[1]
                elif pair[1] == self.__session.env[pair[0]]:
                    logging.info('env[%r] repeated', pair[0])
                else:
                    logging.warning('%s=%s; conflicting value %s ignored.',
                                    pair[0], self.__session.env[pair[0]], pair[1])
            else:
                logging.error('client NEW_ENVIRON; invalid %r', pair)
        self.env_replied = True

    def _sb_naws(self, charbuf) -> None:
        """
        Processes incoming subnegotiation NAWS
        """
        if 4 != len(charbuf):
            logging.error('{client.addr_port}: bad length in NAWS buf ({buflen})'
                          .format(client=self.__session, buflen=len(charbuf)))
            return

        columns = (256 * ord(charbuf[0])) + ord(charbuf[1])
        rows = (256 * ord(charbuf[2])) + ord(charbuf[3])
        old_rows = self.__session.env.get('LINES', None)
        old_columns = self.__session.env.get('COLUMNS', None)

        if old_rows == str(rows) and old_columns == str(columns):
            logging.info('{client.addr_port}: NAWS repeated'.format(client=self.__session))
            return

        if rows <= 0:
            logging.info('LINES %s ignored', rows)
            rows = old_rows

        if columns <= 0:
            logging.info('COLUMNS %s ignored', columns)
            columns = old_columns

        self.__session.env['LINES'] = str(rows)
        self.__session.env['COLUMNS'] = str(columns)

    # ---[ State Juggling for Telnet Options ]----------------------------------
    def check_local_option(self, option):
        """
        Test the status of local negotiated Telnet options.
        """
        if option not in self.telnet_opt_dict:
            self.telnet_opt_dict[option] = TelnetOption()
        return self.telnet_opt_dict[option].local_option

    def _note_local_option(self, option, state):
        """
        Record the status of local negotiated Telnet options.
        """
        if option not in self.telnet_opt_dict:
            self.telnet_opt_dict[option] = TelnetOption()
        self.telnet_opt_dict[option].local_option = state

    def check_remote_option(self, option):
        """
        Test the status of remote negotiated Telnet options.
        """
        if option not in self.telnet_opt_dict:
            self.telnet_opt_dict[option] = TelnetOption()
        return self.telnet_opt_dict[option].remote_option

    def _note_remote_option(self, option, state):
        """
        Record the status of local negotiated Telnet options.
        """
        if option not in self.telnet_opt_dict:
            self.telnet_opt_dict[option] = TelnetOption()
        self.telnet_opt_dict[option].remote_option = state

    def _check_reply_pending(self, option):
        """
        Test the status of requested Telnet options.
        """
        if option not in self.telnet_opt_dict:
            self.telnet_opt_dict[option] = TelnetOption()
        return self.telnet_opt_dict[option].reply_pending

    def _note_reply_pending(self, option, state):
        """
        Record the status of requested Telnet options.
        """
        if option not in self.telnet_opt_dict:
            self.telnet_opt_dict[option] = TelnetOption()
        self.telnet_opt_dict[option].reply_pending = state

    # ---[ Telnet Command Shortcuts ]-------------------------------------------
    def _iac_do(self, option) -> None:
        """
        Send a Telnet IAC "DO" sequence.
        """
        logging.info('send IAC DO %s', name_command(option))
        self.send_str(data=b''.join([IAC, DO, option]))

    def _iac_dont(self, option) -> None:
        """
        Send a Telnet IAC "DONT" sequence.
        """
        logging.info('send IAC DONT %s', name_command(option))
        self.send_str(data=b''.join([IAC, DONT, option]))

    def _iac_will(self, option) -> None:
        """
        Send a Telnet IAC "WILL" sequence.
        """
        logging.info('send IAC WILL %s', name_command(option))
        self.send_str(data=b''.join([IAC, WILL, option]))

    def _iac_wont(self, option) -> None:
        """
        Send a Telnet IAC "WONT" sequence.
        """
        logging.info('send IAC WONT %s', name_command(option))
        self.send_str(data=b''.join([IAC, WONT, option]))


class TelnetNegotiation:
    """ Main Telnet Startup Class for Detection of Telnet Options """

    #: maximum time elapsed allowed to begin on-connect negotiation
    __time_negotiate = 2.50
    __option_parser = None
    __session = None

    def __init__(self, session_handle):
        """
        Accept new Telnet Connection and negotiate options.
        """
        self.__option_parser = TelnetOptionParser(session_handle)
        self.__session = session_handle

    def banner(self) -> None:
        """
        This method is called after the connection is initiated.

        This routine happens to communicate with a wide variety of network
        scanners when listening on the default port on a public IP address.
        """
        # According to Roger Espel Llima (espel@drakkar.ens.fr), you can
        #   have your server send a sequence of control characters:
        # (0xff 0xfb 0x01) (0xff 0xfb 0x03) (0xff 0xfd 0x0f3).
        #   Which translates to:
        # (IAC WILL ECHO) (IAC WILL SUPPRESS-GO-AHEAD)
        # (IAC DO SUPPRESS-GO-AHEAD).
        self.__option_parser.request_will_echo()
        self.__option_parser.request_will_sga()
        self.__option_parser.request_do_sga()
        # add DO & WILL BINARY, for utf8 input/output.
        self.__option_parser.request_do_binary()
        self.__option_parser.request_will_binary()
        # and terminal type, naws, and env,
        self.__option_parser.request_do_ttype()
        self.__option_parser.request_do_naws()
        self.__option_parser.request_do_env()

        # Replace with asyn send
        # self.__option_parser.send()  # push

    def run_telnet_startup(self) -> None:
        """
        Negotiate and inquire about terminal type, telnet options, window size,
        and tcp socket options before spawning a new session. Deadline Timer
        Will timeout the negation process and continue on.
        """
        self.banner()

        logging.info('timer: {self.TIME_NEGOTIATE} ')

        # New Async Timer with Callback and Interval.
        timer = DeadLineTimer()
        timer.async_timer(interval=self.__time_negotiate,
                          callback=self.__session.async_timeout_callback)

        logging.info('{client.addr_port}: starting negotiation'.format(client=self.__session))

    @staticmethod
    def to_bytes(bytes_or_str):
        """ Convert Byte or String to Bytes """
        if isinstance(bytes_or_str, str):
            value = bytes_or_str.encode()  # uses 'utf-8' for encoding
        else:
            value = bytes_or_str
        return value  # Instance of bytes

    @staticmethod
    def to_str(bytes_or_str):
        """ Convert Byte or String to String """
        if isinstance(bytes_or_str, bytes):
            value = bytes_or_str.decode()  # uses 'utf-8' for encoding
        else:
            value = bytes_or_str
        return value  # Instance of str

    def set_encoding(self) -> None:
        """
        # set encoding to utf8 for clients negotiating BINARY mode and
        # not beginning with TERM 'ansi'.
        #
        # This assumes a very simple dualistic model: modern unix terminal
        # (probably using bsd telnet client), or SyncTerm.
        #
        # Clients *could* negotiate CHARSET for encoding, or simply forward a
        # LANG variable -- SyncTerm does neither. So we just assume any
        # terminal that says its "ansi" is just any number of old-world DOS
        # terminal emulating clients that are incapable of comprehending
        # "encoding" (Especially multi-byte!), they only decide upon a "font"
        # or "code page" to map char 0-255 to.
        """

        self.__session.env['ENCODING'] = 'cp437'
        term = self.__session.env.get('TERM', '')

        logging.info('set encoding Term: ' + self.to_str(term))

        local = self.__option_parser.check_local_option
        remote = self.__option_parser.check_remote_option

        if local(BINARY) and remote(BINARY):
            if self.to_str(term) != 'ansi':
                self.__session.env['ENCODING'] = 'utf8'
            else:
                self.__session.env['ENCODING'] = 'cp437'
        else:
            # Default to cp437 or maybe just ascii
            self.__session.env['ENCODING'] = 'cp437'
