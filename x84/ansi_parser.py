"""
Ansi Parser - For internal Virtual Terminal
That will keep track of all screen data and current
cursor x/y positions pushed from internal screens and user input!

This does not handle external applications and doors.
In most cases this only needs a minimal subset for tracking the
internal screen since this isn't parsing all possible terminal data.
it only needs to know what the user is seeing when interacting with internal
screen and data pushed out. So it should handle the basic of what a system
will push out at any given time.

Michael Griffin
"""

import collections


class ScreenBlockPixel(object):

    def __init__(self):
        """
        Screen Block Pixel host individual character / position
        Attributes
        """
        # Init will \x00 as we will skip these bytes when parsing.
        self.attributes = self.create_attribute()
        # Used Later on for light-bars.
        # 'selected_attribute': 0,
        # 'selected_foreground': 0,
        # 'selected_background': 0

    @staticmethod
    def create_attribute() -> dict:
        """ Screen Block / Glyph Attributes """
        return dict({
            'glyph': b'\x00',
            'x_position': 1,
            'y_position': 1,
            'foreground': 37,
            'background': 40,
            'attribute': 0
        })

    def set(self, attribute) -> None:
        """
        Set or overwrite the current position
        :param attribute:
        :return:
        """
        self.attributes = attribute.copy()

    def clear(self) -> None:
        """
        Clear or fill with passed attribute
        :return:
        """
        self.attributes = ScreenBlockPixel.create_attribute()


class AnsiScreenProcessor(object):

    def __init__(self, term_height, term_width, session_handle):
        """
        Startup for Ansi Parser & Screen Buffering
        :param term_height:
        :param term_width:
        :param session_handle:
        """
        # Session for access to encoding and other data.
        self.__session = session_handle

        # Screen buffer
        self._byte_data_buffer = collections.deque()
        self._screen_buffer = [ScreenBlockPixel() for _ in range(term_height * term_width)]

        self._glyph = b'\x00'
        self._text_output = b''
        self._is_screen_cleared = False
        self._is_line_wrapping = False
        self._center_ansi_output = False

        self._number_lines = term_height  # TERM Height
        self._characters_per_line = term_width  # TERM Width

        self._attributes = ScreenBlockPixel.create_attribute()
        self._saved_attributes = ScreenBlockPixel.create_attribute()

        # Max positions used in the current buffer
        self._max_x_position = 1
        self._max_y_position = 1

        # Saving data to Screen Buffer
        # self._screen_buffer[self._position].set(self._glyph, self.attributes)

    def save_attributes(self) -> None:
        """ Save Current Screen Attributes and position """
        self._saved_attributes = self._attributes.copy()

    def restore_attributes(self) -> None:
        """ Restore to Previously Saved Screen Attributes and position """
        self._attributes = self._saved_attributes.copy()

    def scroll_up(self) -> None:
        """ Removing starting line of characters, then append empty line to the end"""
        screen_buffer = self._screen_buffer[self._characters_per_line: None]
        for _ in range(0, self._characters_per_line):
            screen_buffer.append(ScreenBlockPixel())
        self._screen_buffer = screen_buffer

    def clear_screen(self) -> None:
        """ Clear Screen Buffer and re-allocate """
        self._screen_buffer.clear()
        self._screen_buffer = [ScreenBlockPixel()
                               for _ in range(self._number_lines *
                                              self._characters_per_line)]
        self._is_screen_cleared = True
        self._attributes = ScreenBlockPixel.create_attribute()
        self._max_y_position = 1
        self._max_x_position = 1

    def clear_screen_by_range(self, start, end) -> None:
        """ Clear Range of the buffer by different ESC[J sequences
        :param start:
        :param end:
        :return:
        """
        start_position = ((self._attributes['y_position'] - 1) * self._characters_per_line) + start
        end_position = start_position + (end - start)

        for count in range(start_position, end_position):
            self._screen_buffer[count].clear()

    def reset_colors(self) -> None:
        """ Reset Colors to default """
        self._attributes['foreground'] = 37
        self._attributes['background'] = 40
        self._attributes['attribute'] = 0

    def home_cursor(self) -> None:
        """ Reset Colors to default """
        self._attributes['x_position'] = 1
        self._attributes['y_position'] = 1

    def get_position(self) -> int:
        """ Returns array position """
        return ((self._attributes['y_position'] - 1) * self._characters_per_line) + \
               (self._attributes['x_position'] - 1)

    def set_screen_pixel(self, screen_pixel) -> None:
        """
        Set the Block Pixel to the Buffer
        :param screen_pixel:
        :return:
        """
        if self._attributes['x_position'] > self._max_x_position:
            self._max_x_position = self._attributes['x_position']

        if self._attributes['y_position'] > self._number_lines:
            self.scroll_up()
            self._attributes['y_position'] = self._number_lines

        self._attributes = ScreenBlockPixel.create_attribute()
        position = self.get_position()

        # Set the pixel in the buffer
        if position < len(self._screen_buffer):
            self._screen_buffer[position] = screen_pixel.copy()
        else:
            raise Exception("Position out of Bounds!")

        # Move to Next Position (Test This, if needed here!)
        if self._attributes['x_position'] >= self._characters_per_line:
            self._attributes['x_position'] = 1
            self._attributes['y_position'] += 1
        else:
            self._attributes['x_position'] += 1

    def parse_data(self, byte_data) -> None:
        """
        Main Entry for parsing screen data from bytes
        :param byte_data:
        :return:
        """
        if len(byte_data) == 0:
            return

        param = []
        current_param = 0
        first_param_implied = False
        esc_sequence = b'\x00'

        # Handle specific escape sequences
        # CURSOR_POSITION_ALT():
        def set_cursor_position():
            if current_param == 0:
                self._attributes['x_position'] = 1
                self._attributes['y_position'] = 1
            elif current_param == 1:
                self._attributes['x_position'] = 1
                self._attributes['y_position'] = param[0]
            elif first_param_implied:
                self._attributes['x_position'] = param[1]
            else:
                self._attributes['x_position'] = param[1]
                self._attributes['y_position'] = param[0]

            # screen_buff.esc_sequence += esc_sequence;
            esc_sequence = b'\x00'

        # CURSOR_PREV_LIVE:
        def move_cursor_up():
            if current_param == 0:
                if self._attributes['y_position'] > 1:
                    self._attributes['y_position'] -= 1
            else:
                if param[0] > self._attributes['y_position']:
                    self._attributes['y_position'] = 1
                else:
                    self._attributes['y_position'] -= param[0]
                    if self._attributes['y_position'] < 1:
                        self._attributes['y_position'] = 1

            # screen_buff.esc_sequence += esc_sequence;
            esc_sequence = b'\x00'

        # CURSOR_NEXT_LINE:
        def move_cursor_down():
            if current_param == 0:
                if self._attributes['y_position'] < self._number_lines:
                    self._attributes['y_position'] += 1
            else:

                if param[0] > self._number_lines - self._attributes['y_position']:
                    self._attributes['y_position'] = self._number_lines
                else:
                    self._attributes['y_position'] += param[0]
                    if self._attributes['y_position'] > self._number_lines:
                        self._attributes['y_position'] = self._number_lines

            esc_sequence = b'\x00'

        def move_cursor_forward():
            if current_param == 0:
                if self._attributes['x_position'] < self._characters_per_line:
                    self._attributes['x_position'] += 1

                else:
                    if param[0] > self._characters_per_line - self._attributes['x_position']:
                        self._attributes['x_position'] = self._characters_per_line
                    else:
                        self._attributes['x_position'] += param[0]
                        if self._attributes['x_position'] > self._characters_per_line:
                            self._attributes['x_position'] = self._characters_per_line

            esc_sequence = b'\x00'

        def move_cursor_backwards():
            if current_param == 0:
                if self._attributes['x_position'] > 1:
                    self._attributes['x_position'] -= 1
                else:
                    if param[0] > self._attributes['x_position']:
                        self._attributes['x_position'] = 1
                    else:
                        self._attributes['x_position'] -= param[0]
                        if self._attributes['x_position'] < 1:
                            self._attributes['x_position'] = 1

            esc_sequence = b'\x00'

        def move_abs_x_position():
            if current_param == 0:
                self._attributes['x_position'] = 1
            else:
                self._attributes['x_position'] = param[0]

            if self._attributes['x_position'] < 1:
                self._attributes['x_position'] = 1
            elif self._attributes['x_position'] > self._characters_per_line:
                self._attributes['x_position'] = self._characters_per_line

            esc_sequence = b'\x00'

        def erase_display():
            if current_param == 0 or param[0] == 2:
                self.clear_screen()

                esc_sequence = b'\x00'

        def erase_to_end_of_line():
            # Not implemented
            # position = ((y_position - 1) * characters_per_line) + (x_position - 1);
            pass

        def set_graphics_mode():
            # Change text attributes / All Attributes off
            if current_param == 0:
                self.reset_colors()
            else:
                # Loop through and push out to each attribute
                # current_color = "\x1b[";
                for attr in range(current_param):

                    if param[attr] < 30:
                        self._attributes['attribute'] = param[attr]
                    elif param[attr] < 38:
                        self._attributes['foreground'] = param[attr]
                    elif param[attr] < 48:
                        self._attributes['background'] = param[attr]
                    else:
                        pass

        def reset_mode():  # ?7h
            if param[0] == 7:
                self._is_line_wrapping = False

            escape_sequence = b'\x00'

        def set_mode():  # ?7h & 25

            if param[0] == 7:
                self._is_line_wrapping = True

            escape_sequence = b'\x00'

        def set_keyboard_strings():
            pass

        # Method Mapping
        esc_control_methods = dict({
            b'H': set_cursor_position,
            b'f': set_cursor_position, ''' Alt position '''
                                       b'A': move_cursor_up,
            b'F': move_cursor_up, ''' previous Line TODO x-position updates'''
                                  b'B': move_cursor_down,
            b'E': move_cursor_down, ''' Next Line TODO x-position updates '''
                                    b'C': move_cursor_forward,
            b'D': move_cursor_backwards,
            b'G': move_abs_x_position,
            b's': self.save_attributes,
            b'r': self.restore_attributes,
            b'J': erase_display,
            b'K': erase_to_end_of_line,
            b'm': set_graphics_mode,
            b'h': set_mode,
            b'l': reset_mode,
            b'p': set_keyboard_strings
        })

        """
        Start the Main Parsing Loop, will call back to methods above for 
        ESC Sequence Parsing for Attributes and Movement.
        """
        # Loop by index of buffer so we can also look ahead when needed.
        for index in range(len(byte_data)):

            c = byte_data[index]
            if c == '\x1b':

                # Next Byte after ESC
                index += 1
                c = byte_data[index]

                # Check for 7 Bit Control Characters not of '['
                if c != '\x5b':

                    # Also update to handle 7 bit controls.
                    more_params = False

                    # Handle extra sequence or convert to 8 bit sequences for easier parsing.

                else:
                    # Check for ? Control Characters
                    # TODO also look at better refactoring of this !
                    if byte_data[index + 1] == '7' and byte_data[index + 2] == 'h':
                        param[0] = byte_data[index + 1]
                        param[1] = byte_data[index + 2]

                        index += 2
                        self._is_line_wrapping = True
                        more_params = False

                        # Jump directly into parse method here!

                    else:
                        more_params = True

                first_param_implied = False
                current_param = 0

                while more_params:
                    at_least_one_digit = False
                    index += 1
                    digit_position = 0

                    for ch in byte_data[index]:
                        if str(ch).isdigit and digit_position < 3:
                            at_least_one_digit = True

                            # 3 digits at most (255) in a byte size decimal number * /
                            if digit_position == 0:
                                param[current_param] = ch - '0'
                            elif digit_position == 1:
                                param[current_param] *= 10
                                param[current_param] += ch - '0'
                            else:
                                param[current_param] *= 100
                                param[current_param] += ch - '0'

                            digit_position += 1
                            index += 1

                        else:
                            break

                    # // ESC[C     current_param should = 0
                    # // ESC[6C    current_param should = 1
                    # // ESC[1;1H  current_param should = 2
                    # // ESC[;79H  current_param should = 2

                    # Update Byte after index has been moved forward
                    c = byte_data[index]

                    if c != '?':  # // Skip Screen Wrap (The Draw)
                        if at_least_one_digit and c == ';':
                            current_param += 1

                        elif not at_least_one_digit and c == ';':

                            current_param += 1
                            first_param_implied = True

                        elif at_least_one_digit:

                            current_param += 1
                            more_params = False

                        else:
                            more_params = False

                # Great ESC Sequence in entirety
                ending_seq = index

                # loop and cut out full ESC Sequence to store it.
                # We only store with input key if it's parsed
                # Otherwise we skip it.
                for seq in range(ending_seq):
                    esc_sequence += byte_data[seq]

                ''' Execute ESC Parsing methods '''

                esc_control_methods[c]()

            else:
                """
                Not ESC Sequence, parsing for newline and text data.
                """
