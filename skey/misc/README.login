
The included login program is part of Wietse Venema's (wietse@wzv.win.tue.nl)
LOG_DAEMON2.0 package.  It has the already implemented S/Key code embedded
into login/login/login.c

To implement the S/Key system without using a patched login.c, replace the
S/Key user(s) system shell with the "keysh" authentication shell include
in the S/Key source directory.
