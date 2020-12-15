# x84r
x84 BBS Software Revision

This is a side project for fun and learning Python 3.x.  It's my attempt to rewrite x84 BBS in Python 3.x with Asynchronous IO for spawning sessions and handling data IO in a single thread with callbacks

Incomplete, currently working on ANSI Parser, but can telnet into the server.
Each connection will spawn it's own session, and can type letters and data and it will echo it back properly.

Check out the main project here:  https://github.com/jquast/x84
