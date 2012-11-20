ovpnauth
========
I run openvpn in a chrooted environment on one of my servers, and I wanted to
use a password-based authentication system instead of issuing unique
certificates for each client. Prior to chrooting my openvpn setup, I used a
Python script that worked with `auth-user-pass-verify` and `via-env`. However,
I wanted a more light-weight approach for my chrooted setup that did not
require me to add large numbers of files to the chroot, so I wrote ovpnauth, a
small, statically linked application that works with `auth-user-pass-verify`
inside or outside of a chrooted environment.

Compiling
---------
To compile ovpnauth, you will need the libc, zlib and openssl development
headers. I have only personally compiled and tested the application on CentOS 6
and Debian Squeeze, and I have been able to install the needed libraries with
the following commands:

### CentOS 6: ###

    # Static executable
    yum install gcc make glibc-static zlib-static openssl-static

    # Dynamically linked executable
    yum install make gcc openssl-devel

### Debian Squeeze: ###

    apt-get --no-install-recommends install gcc make libc-dev libssl-dev

Once the development headers, compiler and `make` are installed, you should be
able to compile the application by running `make`. By default, a statically
linked executable is built, but a dynamic executable can be built with `make
dynamic`. The test suite script was written for GNU/Linux and has only been
tested on two distributions, so it is unlikely to be very portable. You can
skip the tests and just compile the binary with `make ovpnauth`. Tests can be
run at any time with `make tests` or by executing the `tests.sh` script with
bash.

Installation
------------
Copy the `ovpnauth` binary to a folder accessible by your openvpn user. When
running openvpn in a chrooted environment, `ovpnauth` must be placed inside the
chroot folder or a subdirectory thereof.

Edit openvpn's server config file and adjust `auth-user-pass-verify` to the
following:

    auth-user-pass-verify $OVPNAUTH_PATH via-env

Replace `$OVPNAUTH_PATH` with the path to the `ovpnauth` binary. If you're
using the chroot directive for openvpn, make sure to adjust the path treating
the chroot directory as the file system root. For example, if your server
configuration contains `chroot /home/openvpn` and you copied the binary to
`/home/openvpn/bin`, then `OVPNAUTH_PATH=/bin/ovpnauth` in the line above.

Usage
-----
The application recognizes the commands `edit`, for creating and updating user
credentials; `remove` for deleting users; and `list` for listing all of the
users.

### Add a new user ###

    [root@cloud ovpnauth]# ovpnauth edit jameseric
    Password: hunter2
    Created new user 'jameseric'.

### Change user's password ###

    [root@cloud ovpnauth]# ovpnauth edit bob
    Password: new-password
    Authentication data for 'bob' updated.

### Delete a user ###

    [root@cloud ovpnauth]# ovpnauth remove michelle
    Deleted user 'michelle'.

### List all users ###

    [root@cloud ovpnauth]# ovpnauth list
    jameseric
    bob
    paul

By default, the file `auth.db` in the current working directory is used to
store the user authentication data, but the file can be changed by setting the
`OVPNAUTH_DBPATH` environment variable to the preferred path.

Locking is implemented for operations that require the authentication database
to be updated. If an existing lock is detected, the application will wait up to
2 seconds for the lock to be freed before giving up. The duration can be
changed by setting the environment variable `OVPNAUTH_LOCK_TIMEOUT` to a whole
number representing the lock timoeout in seconds. Any existing lock files that
are older than the timeout will be unlinked under the assumption the previous
application instance was interrupted before its changes were committed.

Bugs / Known Issues
--------------------
- All password prompts currently echo the input back to the terminal.

- I am currently using a work-around for an error I encountered when compiling
  this program on my CentOS 6 server: `warning: Using 'dlopen' in statically
  linked applications requires at runtime the shared libraries from the glibc
  version used for linking`. It does not appear that any of the code `ovpnauth`
  depends on calls `dlopen`, so I redeclared `dlopen` as a void function in my
  application.

- This could be made simpler by just acting as a relay to daemon listening on
  loopback, but I learned more this way `;)`.
