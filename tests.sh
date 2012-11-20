#!/bin/bash
function die
{
    rm -rf "$testdir"
    if [[ "$@" ]]
    then
        cat <<< "$@" >&2
        exit 1
    fi
}

trap 'die "Caught SIGINT, exiting."' SIGINT
trap 'die "Caught SIGTERM, exiting."' SIGTERM

db="$OVPNAUTH_DBPATH"
if [[ -z "$db" ]]
then
    db="auth.db"
fi


[[ -z "$ovpnauth" ]] && ovpnauth="$PWD/ovpnauth"

if [[ "$(which valgrind)" ]] && [[ "$1" == "--valgrind" ]]
then
    echo "Running with valgrind."
    function target
    {
        valgrind --gen-suppressions=all -q --leak-check=full \
            --show-reachable=yes --log-fd=3 "$ovpnauth" "$@"
    }
else
    echo "Running without valgrind."
    function target
    {
        "$ovpnauth" "$@"
    }
fi

testdir="$PWD/.test.$$"
mkdir -p "$testdir"
cd "$testdir"

exec 3>&2
echo "Testing user creation..."
for user in user1 user2 user3
do
    target edit $user <<< "$user-password" &> /dev/null || {
        die "Unexpected non-zero exit status (edit $user)"
    }
done

if [[ ! "$(target list | sort | grep -c 'user[123]')" -eq 3 ]]
then
    die "User creation and / or enumeration failed."
fi

echo "Testing password validation..."
for user in `target list`
do
    username=$user password="$user-wrong-password" target &> /dev/null \
      && {
        die "Password validation passed unexpectedly for user '$user'."
    }

    username=$user password="$user-password" target &> /dev/null || {
        die "Password validation failed unexpectedly for user '$user'."
    }

    set $(awk -F: "/^$user:/ {print \$2\" \"\$3}" "$db")
    sum="$1"
    salt="$2"
    [[ "$(echo -n "$user-password$salt" | sha512sum | awk '{print $1}')" \
      != "$sum" ]] \
       && {
        die "Produced executable SHA sum did not appear to be correct."
    }
done

echo "Testing user modification..."
for user in `target list`
do

    target edit $user <<< "$user-password2" &> /dev/null || {
        die "Unexpected non-zero exit status (edit $user)"
    }
    modified="$modified $user"

    for user in `target list`
    do
        username=$user password="$user-wrong-password" target &> \
          /dev/null && {
            die "Password validation passed unexpectedly for user '$user'."
        }

        if [[ "$modified" =~ "$user" ]]
        then
            password="password2"
        else
            password="password"
        fi
        username=$user password="$user-$password" target &> /dev/null || {
            die "Password validation failed unexpectedly for user '$user'."
        }
    done
done

if [[ ! "$(target list | grep -c 'user[123]')" -eq 3 ]]
then
    die "User creation and / or enumeration failed."
fi

echo "Testing account deletion..."
for user in `target list`
do
    expected=$(sed "/^$user:/d" "$db" | md5sum)
    target remove $user &> /dev/null
    got=$(md5sum < "$db")

    if [[ "$expected" != "$got" ]]
    then
        echo "Deletion of user '$user' failed."
    fi

    for user in `target list`
    do
        username=$user password="$user-wrong-password" target &> \
          /dev/null && {
            die "Password validation passed unexpectedly."
        }

        username=$user password="$user-password2" target &> /dev/null || {
            die "Password validation failed unexpectedly."
        }
    done
done

echo "Testing locking..."
touch -t 197002010000 "$testdir/$db.new"
target edit user99 <<< 'xxx' &> /dev/null || die "Failed to remove stale lock"

touch "$testdir/$db.new"
touch -t 300002010000 "$testdir/$db.new"
target remove DOES_NOT_EXIST &> /dev/null && {
    die "Program unexpectedly exited successfully."
}

cd ".."
if [[ -z "$OVPNAUTH_LOCK_TIMEOUT" ]] && [[ -z "$OVPNAUTH_DBPATH" ]]
then
    echo "Repeating tests with OVPNAUTH_DBPATH set..."
    OVPNAUTH_DBPATH="$$.db" bash "$0" &> /dev/null || {
        die "Tests failed when explicitly setting OVPNAUTH_DBPATH."
    }
    OVPNAUTH_DBPATH="./$$.db" bash "$0" &> /dev/null || {
        die "Tests failed when explicitly setting OVPNAUTH_DBPATH (with slash)."
    }
fi

if [[ -z "$OVPNAUTH_LOCK_TIMEOUT" ]] && [[ -z "$OVPNAUTH_DBPATH" ]]
then
    echo "Repeating tests with OVPNAUTH_LOCK_TIMEOUT set..."
    OVPNAUTH_LOCK_TIMEOUT="2" bash "$0" &> /dev/null || {
        die "Tests failed when explicitly setting OVPNAUTH_DBPATH."
    }
fi

die && echo "All tests passed."
