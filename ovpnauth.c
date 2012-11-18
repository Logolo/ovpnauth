#define _POSIX_C_SOURCE 200112L
#define _BSD_SOURCE

#include <errno.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define ACTION_AUTHENTICATE 8
#define ACTION_EDIT 1
#define ACTION_LIST 4
#define ACTION_NOOP 0
#define ACTION_REMOVE 2
#define ACTION_LOCKS_DATABASE (ACTION_EDIT | ACTION_REMOVE)
#define ERRNO_DIE(msg) perror(msg); exit(1);
#define DIGEST_LENGTH SHA512_DIGEST_LENGTH
#define MAX_LINE_SIZE 4096
#define MAX_SALT_LENGTH 32
#define SALTED_HASH_LENGTH (DIGEST_LENGTH * 2 + MAX_SALT_LENGTH + 1)

void dlopen() { /* eliminates a compiler warning RHEL-based systems. */ };

char *DATABASE_PATH;
char *DATABASE_TEMP;

/*  Compute hexadecimal SHA digest of given string.
 *
 *  @param string   String from which to generate digest.
 *  @param output   Output buffer for hexadecimal digest. Must be of size
 *                  (DIGEST_LENGTH * 2 + 1)
 *
 *  @retval 0       Returned upon successful execution
 *  @retval 1       Returned when OpenSSL methods cannot be initialized
 */
int sha512(char *string, unsigned char output[DIGEST_LENGTH * 2 + 1])
{
    unsigned char hash[SHA512_DIGEST_LENGTH] = "\0";
    SHA512_CTX sha;
    if (!(SHA512_Init(&sha) && SHA512_Update(&sha, string, strlen(string)) &&
      SHA512_Final(hash, &sha))) {
        return 1;
    }

    // Convert binary digest to hexadecimal
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
    output[DIGEST_LENGTH * 2] = '\0';
    return 0;
}

/*  Concatenate a string with a given salt and generate an SHA digest of
 *  the concatenated string. If a NULL pointer is passed in for the salt, a
 *  random salt will be generated. If a salt is provided and exceed
 *  MAX_SALT_LENGTH, it will be truncated.
 *
 *  @param string   String from which to generate salted hash
 *  @param salt     Salt used for hash generation. Passing this argument in
 *                  as a NULL pointer will cause a random salt to be
 *                  generated.
 *  @param output   Output buffer for digest. This will contain the hash
 *                  and salt used for the hash joined with a ':'. The
 *                  buffer must be of size (DIGEST_LENGTH * 2 +
 *                  MAX_SALT_LENGTH + 1)
 *
 *  @returns        Returns the result of the `sha512` function
 */
int saltedhash(char *string, char *salt, char output[SALTED_HASH_LENGTH + 1])
{
    FILE *urandom;
    size_t salt_length;
    size_t string_length = strlen(string);
    unsigned char *salted_string;
    unsigned char hash[DIGEST_LENGTH * 2 + 1];
    unsigned char salt_[MAX_SALT_LENGTH + 1];

    if (salt == NULL) {
        // When no salt is given, grab data from /dev/urandom, convert it to
        // hexadecimal and use the result as our salt.
        urandom = fopen("/dev/urandom", "r");
        if (urandom == NULL) {
            ERRNO_DIE("Could not open /dev/urandom");
        }

        for(int i = 0; i < MAX_SALT_LENGTH / 2; ++i) {
            sprintf(salt_ + i * 2, "%02x", fgetc(urandom));
        }
        salt_[MAX_SALT_LENGTH] = '\0';
        salt_length = MAX_SALT_LENGTH;
        fclose(urandom);
    } else {
        strncpy(salt_, salt, MAX_SALT_LENGTH);
        salt_length = strlen(salt_);
    }

    salted_string = (char*) malloc(salt_length + string_length + 1);
    if (salted_string == NULL) {
        ERRNO_DIE("Could not allocate memory");
    }

    // hash = SHAChecksum("$string$salt_")
    strcpy(salted_string, string);
    strcat(salted_string, salt_);
    if (sha512(salted_string, hash)) {
        free(salted_string);
        return 1;
    }

    // output = "$hash:$salt_"
    strcpy(output, hash);
    output[DIGEST_LENGTH * 2] = ':';
    output[DIGEST_LENGTH * 2 + 1] = '\0';
    strcat(output, salt_);

    free(salted_string);
    return 0;
}

/* Creates a file and returns a FILE pointer. If the file already exists,
 * the function will wait briefly before attempting to create the file
 * again.
 *
 * @param path      Path to lock
 * @param mode      Access mode passed to fdopen
 * @param attempts  Maximum number of attempts to acquire access to path
 *
 * @returns         Returns a file pointer once the file is created. If
 *                  function fails, a NULL pointer is returned and errno
 *                  set accordingly.
 */
FILE *excl_open(char *path, char *mode, int attempts)
{
    int lockfd;
    unsigned long int delay = 125000;
    while (1) {
        lockfd = open(DATABASE_TEMP, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (lockfd > -1) {
            return fdopen(lockfd, mode);
        }
        if (!attempts--) {
            break;
        }
        usleep(delay);
    }
    return NULL;
}

/* Cleanup function used by `atexit` to remove temporary files.
 */
void cleanup()
{
    unlink(DATABASE_TEMP);
}

/* Wrapper for `cleanup` function to ensure program exits with a non-zero
 * status.
 */
void sig_cleanup()
{
    cleanup();
    exit(1);
}

/* Display brief help for program.
 *
 * @param argv0     Name of executable, generally the value of argv[0]
 */
void usage(char *argv0)
{
    printf(
        "Usage:\n%s edit [USERNAME]\n%s remove USERNAME\n%s list\n",
        argv0, argv0, argv0
    );
}

/* Sanitize a string according to documentation of --auth-user-pass-verify
 * in openvpn(8): "...the username string must consist only of these
 * characters: alphanumeric, underbar ('_'), dash ('-'), dot ('.'), or at
 * ('@'). The password string can consist of any printable characters
 * except for CR or LF. Any illegal characters in either the username or
 * password string will be converted to underbar ('_')." The string passed
 * into this function is modified in-place.
 *
 * @param string        Username or password to sanitize
 * @param is_username   Value indicating whether or not the given string is
 *                      to be treated as a username or password.
 *
 * @returns             Returns a pointer to the modified string
 */
char *openvpn_sanitize(char *string, int is_username)
{
    char *ptr = string;
    while (*ptr != '\0') {
        if (!is_username) {
            if (*ptr == '\r' || *ptr == '\n' || *ptr < ' ' || *ptr > '~') {
                *ptr = '_';
            }
        } else if (!((*ptr >= 'a' && *ptr <= 'z') || (*ptr >= '@' && *ptr <=
          'Z') || (*ptr >= '0' && *ptr <= '9') || *ptr == '_' || *ptr == '.' ||
          *ptr == '-')) {
            *ptr = '_';
        }

        *ptr++;
    }

    return string;
}

int main(int argc, char **argv)
{
    FILE *userdb;
    FILE *userdbtmp;
    char *envpassword;
    char *envusername;
    char *hash;
    char *salt;
    char *username;
    char line[MAX_LINE_SIZE];
    int action = ACTION_NOOP;
    unsigned char hash_with_salt[SALTED_HASH_LENGTH + 1];

    // Get path to database from OVPNAUTH_DATABASE. If the path cannot be
    // pulled from the environment, the database path defaults to "users.db".
    // The temporary database path is created prepending a "." and appending
    // ".tmp" to the database path's basename, so the temporary file for
    // "/etc/ovpn.shadow" would be "/etc/.ovpn.shadow.tmp".
    DATABASE_PATH = getenv("OVPNAUTH_DATABASE");
    if (DATABASE_PATH == NULL) {
        DATABASE_PATH = "users.db";
        DATABASE_TEMP = ".users.db.tmp";
    } else {
        DATABASE_TEMP = (char *) malloc(strlen(DATABASE_PATH) + 6);
        if (DATABASE_TEMP == NULL) {
            ERRNO_DIE("Could not allocate memory");
        }

        char *slash_ptr = strrchr(DATABASE_PATH, '/');
        if (slash_ptr == NULL) {
            DATABASE_TEMP[0] = '.';
            DATABASE_TEMP[1] = '\0';
            strcat(DATABASE_TEMP, DATABASE_PATH);
        } else {
            // Insert "." immediately after the slash.
            strncpy(DATABASE_TEMP, DATABASE_PATH, slash_ptr - DATABASE_PATH + 1);
            *(DATABASE_TEMP + (slash_ptr - DATABASE_PATH + 1)) = '.';
            *(DATABASE_TEMP + (slash_ptr - DATABASE_PATH + 2)) = '\0';
            strcat(DATABASE_TEMP, slash_ptr + 1);
        }
        strcat(DATABASE_TEMP, ".tmp");
    }

    userdb = fopen(DATABASE_PATH, "a+");
    if (userdb == NULL) {
        ERRNO_DIE("Unable to open user database");
    }

    envusername = getenv("username");
    envpassword = getenv("password");

    if ((envusername != NULL) && (envpassword != NULL)) {
        if (*envusername == '\0' || *envpassword == '\0') {
            fputs("Neither the username nor password may be empty.\n", stderr);
            return 1;
        }
        action = ACTION_AUTHENTICATE;
    } else if (argc - 1) {
        if (!strcmp(argv[1], "edit")) {
            if ((argc == 2) || (argc == 3)) {
                action = ACTION_EDIT;
            }
        } else if (!strcmp(argv[1], "remove")) {
            if (argc == 3) {
                action = ACTION_REMOVE;
            }
        } else if (!strcmp(argv[1], "list")) {
            if (argc == 2) {
                action = ACTION_LIST;
            }
        }
    }

    if (action == ACTION_NOOP) {
        usage(argv[0]);
        return 1;
    }

    if (action & ACTION_LOCKS_DATABASE) {
        char *envattempts = getenv("OVPNAUTH_LOCK_ATTEMPTS");
        int attempts = 0;
        if (envattempts != NULL) {
            attempts = atoi(envattempts);
        }

        if (!attempts || envattempts == NULL) {
            attempts = 12;
        }

        if ((userdbtmp = excl_open(DATABASE_TEMP, "w", attempts)) == NULL) {
            ERRNO_DIE("Unable to lock database");
        }

        // Make sure the lock file is removed when the process terminates
        signal(SIGTERM, sig_cleanup);
        signal(SIGINT, sig_cleanup);
        atexit(cleanup);
    }

    if (action & (ACTION_EDIT | ACTION_REMOVE)) {
        char read_buffer[128];
        if (argc > 2) {
            envusername = argv[2];
        } else {
            printf("Username: ");
            scanf("%127s", read_buffer);
            envusername = (char *) malloc(strlen(read_buffer) + 1);
            if (envusername == NULL) {
                ERRNO_DIE("Could not allocate memory");
            }
            strcpy(envusername, read_buffer);
        }

        if (action == ACTION_EDIT) {
            if (isatty(0) && isatty(1)) {
                printf("Password: ");
            }
            scanf("%127s", read_buffer);
            envpassword = (char *) malloc(strlen(read_buffer) + 1);
            if (envpassword == NULL) {
                ERRNO_DIE("Could not allocate memory");
            }
            strcpy(envpassword, read_buffer);
            if (saltedhash(envpassword, NULL, hash_with_salt)) {
                fputs("Unable to initialize OpenSSL SHA methods.\n", stderr);
                return 1;
            }
        }
    }

    if (action & (ACTION_EDIT | ACTION_AUTHENTICATE)) {
        openvpn_sanitize(envusername, 1);
        openvpn_sanitize(envpassword, 0);
    }

    char strtok_buffer[MAX_LINE_SIZE];
    int user_found = 0;
    while(fgets(line, MAX_LINE_SIZE, userdb) != NULL) {
        // Line must remain in tact, so create a copy for strtok to munch on.
        strcpy(strtok_buffer, line);

        if (action == ACTION_AUTHENTICATE) {
            username = strtok(strtok_buffer, ":\n\r");
            if ((username == NULL) || (strcmp(username, envusername))) {
                continue;
            }

            hash = strtok(NULL, ":\n\r");
            salt = strtok(NULL, ":\n\r");
            if (saltedhash(envpassword, salt, hash_with_salt)) {
                fputs("Unable to initialize OpenSSL SHA methods.\n", stderr);
                return 1;
            }

            // Truncate the generated hash_with_salt to remove the salt then
            // compare to the hash loaded from the user database.
            hash_with_salt[DIGEST_LENGTH * 2] = '\0';
            if (!strcmp(hash_with_salt, hash)) {
                printf("User '%s' authenticated successfully.\n", username);
                return 0;
            } else {
                puts("Authentication failed, password does not match.");
                return 1;
            }

        } else if (action == ACTION_LIST) {
            // Display the username for this row in the database file
            username = strtok(strtok_buffer, ":\n\r");
            if (username != NULL) {
                puts(username);
            }
            continue;

        } else if (!user_found) {
            username = strtok(strtok_buffer, ":\n\r");
            if ((username != NULL) && (!strcmp(username, envusername))) {
                if (action == ACTION_EDIT) {
                    // Write hash data for new password into new database
                    fprintf(userdbtmp, "%s:%s\n", username, hash_with_salt);
                }

                // For ACTION_REMOVE, nothing special needs to be done. We just
                // continue to make sure the user is not the new database.
                user_found = 1;
                continue;
            }
        }

        // Duplicate line in live database to new database
        fprintf(userdbtmp, "%s", line);
    }

    fclose(userdb);

    if (action == ACTION_LIST) {
        return 0;
    }

    if (!user_found) {
        if (action == ACTION_EDIT) {
            // If the user given as the target of the "edit" command was not
            // found while scanning the database, create the user in the new
            // database.
            fprintf(userdbtmp, "%s:%s\n", envusername, hash_with_salt);
            printf("Created new user '%s'.\n", envusername);
        } else {
            printf("Could not find user '%s'.\n", envusername);
            return 1;
        }
    } else {
        if (action == ACTION_EDIT) {
            printf("Authentication data for '%s' updated.\n", envusername);
        } else if (action == ACTION_REMOVE) {
            printf("Deleted user '%s'.\n", envusername);
        }
    }

    fclose(userdbtmp);

    // Atomically replace the existing database with the new database.
    if (rename(DATABASE_TEMP, DATABASE_PATH)) {
        ERRNO_DIE("Could not save changes");
    }

    return 0;
}
