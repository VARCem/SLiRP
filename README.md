Welcome to **VARCem**, the Virtual Archaeological Computer EMulator.

This is the SLiRP Host Gateway module for VARCem. It is based on a much-
hacked variant of SLiRP, initially modified for use with the PCem emulator
by neozeed.

As an external module, it can be used as needed. Configuration is handled
by the calling application (VARCem), and multiple instances can be run at
the same time.

The SLiRP module can be considered a simple, virtual in-application IP
router with PAT (Port Address Translation) capabilities. Its "internal" leg
talks to the emulated network cards within the emulator, and the "external"
side use the host system's network stack to connect to the outside world,
using the host's IP address and translating back to the internal side.


Community and Support
---------------------
Information, downloads, additional modules and such can be found on our
[Website](http://www.varcem.com/). Live support and general help can
also be found on our [IRC channel](https://kiwiirc.com/client/irc.freenode.net/?nick=VARCem_Guest|?#VARCem)


LEGAL
-----
"This program is  distributed in the hope that it will be useful, but
WITHOUT   ANY  WARRANTY;  without  even   the  implied  warranty  of
MERCHANTABILITY  or FITNESS  FOR A PARTICULAR  PURPOSE."

It's free, it comes with all the sources, but it does not come with
any warranty whatsoever. You probably should not use this software to run
a business-critical piece of (old) software at work, for example.

If there is a problem with the software, please open up a GIT issue so we
can work on it, and/or talk to us on the IRC channel. We cannot promise a
fix, but will try the best we can !


BUILD STATUS
------------
The auto-builds handled by Travis-CI are [![Build Status](https://travis-ci.org/VARCem/SLiRP.svg?branch=master)](https://travis-ci.org/VARCem/SLiRP)

Last Updated: 2020/07/17
