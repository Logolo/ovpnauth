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

### Build Dependencies ###

To compile ovpnauth, you will need the libc, zlib and openssl development
headers in addition to `make` and `gcc`. I have only personally compiled and
tested the application on CentOS 6, Debian Squeeze and Wheezy, and I was able
to install the build dependencies with the following commands:

#### CentOS 6 ####

    # Static executable
    yum install gcc make glibc-static zlib-static openssl-static

    # Dynamically linked executable
    yum install make gcc openssl-devel

#### Debian Squeeze ####

    apt-get --no-install-recommends install gcc make libc-dev libssl-dev

#### Gentoo ####

The application reportedly compiles and passes the test suite on Gentoo, and
the following (paraphrased) instructions for compiling ovpnauth were relayed to
me by [dririan](https://github.com/dririan/):

> Most boxes should actually have what is needed. For static linking,
> USE="static" needs to be turned on for the packages, so add the following
> lines to "/etc/portage/package.use" then recompile both packages with "emerge
> -1 openssl zlib":

    dev-libs/openssl static-libs
    sys-libs/zlib static-libs

### Making The Binary ###

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
    Password:
    Retype password:
    Created new user 'jameseric'.

### Change user's password ###

    [root@cloud ovpnauth]# ovpnauth edit bob
    Password:
    Retype password:
    Authentication data for 'bob' updated.

### Delete a user ###

    [root@cloud ovpnauth]# ovpnauth remove michelle
    Deleted user 'michelle'.

### List all users ###

    [root@cloud ovpnauth]# ovpnauth list
    jameseric
    bob
    paul

Passwords can also be piped into stdin instead of being entered interactively.
If a password is piped into stdin, ovpnauth will not require that the password
be retyped.

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
- I am currently using a work-around for an error I encountered when compiling
  this program on my CentOS 6 server: `warning: Using 'dlopen' in statically
  linked applications requires at runtime the shared libraries from the glibc
  version used for linking`. It does not appear that any of the code `ovpnauth`
  depends on calls `dlopen`, so I redeclared `dlopen` as a void function in my
  application.

- This could be made simpler by just acting as a relay to daemon listening on
  loopback, but I learned more this way `;)`.
