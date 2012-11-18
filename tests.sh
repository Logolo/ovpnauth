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

db="$OVPNAUTH_DATABASE"
if [[ -z "$db" ]]
then
    db="users.db"
fi

[[ -z "$ovpnauth" ]] && ovpnauth="$PWD/ovpnauth"
testdir="$PWD/.test.$$"
mkdir -p "$testdir"
cd "$testdir"

echo "Testing user creation..."
for user in user1 user2 user3
do
    "$ovpnauth" edit $user <<< "$user-password" &> /dev/null || {
        die "Unexpected non-zero exit status (edit $user)"
    }
done

if [[ ! "$("$ovpnauth" list | sort | grep -c 'user[123]')" -eq 3 ]]
then
    die "User creation and / or enumeration failed."
fi

echo "Testing password validation..."
for user in `"$ovpnauth" list`
do
    username=$user password="$user-wrong-password" "$ovpnauth" &> /dev/null \
      && {
        die "Password validation passed unexpectedly for user '$user'."
    }

    username=$user password="$user-password" "$ovpnauth" &> /dev/null || {
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
for user in `"$ovpnauth" list`
do

    "$ovpnauth" edit $user <<< "$user-password2" &> /dev/null || {
        die "Unexpected non-zero exit status (edit $user)"
    }
    modified="$modified $user"

    for user in `"$ovpnauth" list`
    do
        username=$user password="$user-wrong-password" "$ovpnauth" &> \
          /dev/null && {
            die "Password validation passed unexpectedly for user '$user'."
        }

        if [[ "$modified" =~ "$user" ]]
        then
            password="password2"
        else
            password="password"
        fi
        username=$user password="$user-$password" "$ovpnauth" &> /dev/null || {
            die "Password validation failed unexpectedly for user '$user'."
        }
    done
done

if [[ ! "$("$ovpnauth" list | grep -c 'user[123]')" -eq 3 ]]
then
    die "User creation and / or enumeration failed."
fi

echo "Testing account deletion..."
for user in `"$ovpnauth" list`
do
    expected=$(sed "/^$user:/d" "$db" | md5sum)
    "$ovpnauth" remove $user &> /dev/null
    got=$(md5sum < "$db")

    if [[ "$expected" != "$got" ]]
    then
        echo "Deletion of user '$user' failed."
    fi

    for user in `"$ovpnauth" list`
    do
        username=$user password="$user-wrong-password" "$ovpnauth" &> \
          /dev/null && {
            die "Password validation passed unexpectedly."
        }

        username=$user password="$user-password2" "$ovpnauth" &> /dev/null || {
            die "Password validation failed unexpectedly."
        }
    done
done

if [[ -z "$OVPNAUTH_LOCK_ATTEMPTS" ]] && [[ -z "$OVPNAUTH_DATABASE" ]]
then
    (
    cd ".."
    echo "Repeating tests with OVPNAUTH_DATABASE set..."
    OVPNAUTH_DATABASE="$$.db" bash "$0" &> /dev/null || {
        die "Tests failed when explicitly setting OVPNAUTH_DATABASE."
    }
    OVPNAUTH_DATABASE="./$$.db" bash "$0" &> /dev/null || {
        die "Tests failed when explicitly setting OVPNAUTH_DATABASE (with slash)."
    }
    )
fi

echo "Repeating tests with OVPNAUTH_LOCK_ATTEMPTS set..."
if [[ -z "$OVPNAUTH_LOCK_ATTEMPTS" ]] && [[ -z "$OVPNAUTH_DATABASE" ]]
then
    (
    cd ".."
    OVPNAUTH_LOCK_ATTEMPTS="1" bash "$0" &> /dev/null || {
        die "Tests failed when explicitly setting OVPNAUTH_DATABASE."
    }
    )
fi

die && echo "All tests passed."
