#define _POSIX_C_SOURCE 200112L
#define _BSD_SOURCE

#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

#define ACTION_AUTHENTICATE 8
#define ACTION_EDIT 1
#define ACTION_LIST 4
#define ACTION_NOOP 0
#define ACTION_REMOVE 2
#define ACTION_LOCKS_DATABASE (ACTION_EDIT | ACTION_REMOVE)
#define DIGEST_LENGTH SHA512_DIGEST_LENGTH
#define ERRNO_DIE(msg) perror(msg); exit(1);
#define MAX_INPUT_CHARS 127
#define MAX_LINE_SIZE 4096
#define MAX_SALT_CHARS 32
#define QW(str) #str
#define READ_INTO(destination, chars) scanf("%" QW(chars) "s", destination);

// Length of the digest and salt joined with a colon.
#define SALTED_HASH_LENGTH (DIGEST_LENGTH * 2 + MAX_SALT_CHARS + 1)

void dlopen() { /* eliminates a compiler warning on RHEL-based systems. */ };

/* Compute hexadecimal SHA digest of given string.
 *
 * @param string    String from which to generate digest.
 * @param output    Output buffer for hexadecimal digest. Must be of size
 *                  (DIGEST_LENGTH * 2 + 1)
 *
 * @retval 0        Returned upon successful execution
 * @retval 1        Returned when OpenSSL methods cannot be initialized
 */
int sha512(char *string, char output[DIGEST_LENGTH * 2 + 1])
{
    unsigned char hash[SHA512_DIGEST_LENGTH] = "";
    SHA512_CTX sha;
    if (!(SHA512_Init(&sha) && SHA512_Update(&sha, string, strlen(string)) &&
      SHA512_Final(hash, &sha))) {
        return 1;
    }

    // Convert binary digest to hexadecimal
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        snprintf(output + i * 2, 3, "%02x", hash[i]);
    }
    return 0;
}

/* Concatenate a string with a given salt and generate an SHA digest of the
 * concatenated string. If a NULL pointer is passed in for the salt, a random
 * salt will be generated. If a salt is provided and exceed MAX_SALT_CHARS, it
 * will be truncated.
 *
 * @param string    String from which to generate salted hash
 * @param salt      Salt used for hash generation. Passing this argument in
 *                  as a NULL pointer will cause a random salt to be
 *                  generated.
 * @param output    Output buffer for digest. This will contain the hash
 *                  and salt used for the hash joined with a ':'. The
 *                  buffer must be of size (DIGEST_LENGTH * 2 +
 *                  MAX_SALT_CHARS + 1)
 *
 * @returns         Returns the result of the `sha512` function
 */
int saltedhash(char *string, char *salt, char output[SALTED_HASH_LENGTH + 1])
{
    FILE *urandom;
    char *salted_string;
    char hash[DIGEST_LENGTH * 2 + 1];
    char salt_[MAX_SALT_CHARS + 1] = "";
    size_t salt_length;
    size_t string_length = strlen(string);

    salt_[MAX_SALT_CHARS] = '\0';
    if (salt == NULL) {
        // When no salt is given, generate salt randomly with /dev/urandom or
        // srand as a fallback.
        urandom = fopen("/dev/urandom", "r");
        if (urandom != NULL) {
            for(int i = 0; i < MAX_SALT_CHARS; ++i) {
                *(salt_ + i) = fgetc(urandom) % 63 + 64;
            }
            fclose(urandom);

        } else {
            // When dev urandom cannot be loaded, hash some environment
            // variables to seed srand for salt generation.
            snprintf(hash, DIGEST_LENGTH * 2, "%i.%i.%i", (int) time(NULL),
                (int) getpid(), (int) clock());
            sha512(hash, hash);
            hash[sizeof((long int)(0)) * 2 - 1] = '\0';
            srand(strtol(hash, NULL, 16));

            for(int i = 0; i < MAX_SALT_CHARS; ++i) {
                *(salt_ + i) = rand() % 63 + 64;
            }
        }
        salt_length = MAX_SALT_CHARS;
    } else {
        strncpy(salt_, salt, MAX_SALT_CHARS);
        salt_length = strlen(salt_);
    }

    salted_string = (char*) malloc(salt_length + string_length + 1);
    if (salted_string == NULL) {
        ERRNO_DIE("Could not allocate memory");
    }

    // hash = SHAChecksum(string + salt_)
    strcpy(salted_string, string);
    strcat(salted_string, salt_);
    if (sha512(salted_string, hash)) {
        free(salted_string);
        return 1;
    }

    // output = hash + ":" + salt_
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
 * @param path          Path to lock
 * @param mode          Access mode passed to fdopen
 * @param timeout_sec   Maximum amount of time to spend attempting to open
 *                      file
 *
 * @returns             Returns a file pointer once the file is created. If
 *                      function fails, a NULL pointer is returned and
 *                      errno set accordingly.
 */
FILE *excl_open(char *path, char *mode, int timeout_sec)
{
    int lockfd;
    struct timespec clock_now;
    struct timespec clock_start;
    struct stat file_info;
    unsigned long int delay = 125000;

    clock_gettime(CLOCK_MONOTONIC, &clock_start);
    while (1) {
        lockfd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (lockfd > -1) {
            return fdopen(lockfd, mode);
        } else if (errno == EEXIST) {
            // Attempt to remove old, stale files.
            if (!stat(path, &file_info)) {
                if (time(NULL) - file_info.st_mtime > timeout_sec) {
                    if (!unlink(path)) {
                        continue;
                    }
                }
            }
        }

        // Try to open the file until "timeout_sec" seconds have passed
        clock_gettime(CLOCK_MONOTONIC, &clock_now);
        if (((clock_now.tv_sec - clock_start.tv_sec) + (clock_now.tv_nsec -
          clock_start.tv_nsec) / 1E9) > timeout_sec) {
            return NULL;
        }
        usleep(delay);
    }
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
    char *ptr = string - 1;
    while (*++ptr) {
        if (!is_username) {
            if (*ptr == '\r' || *ptr == '\n' || *ptr < ' ' || *ptr > '~') {
                *ptr = '_';
            }
        } else if (!((*ptr >= 'a' && *ptr <= 'z') || (*ptr >= '@' && *ptr <=
          'Z') || (*ptr >= '0' && *ptr <= '9') || *ptr == '_' || *ptr == '.' ||
          *ptr == '-')) {
            *ptr = '_';
        }
    }

    return string;
}

int main(int argc, char **argv)
{
    FILE *userdb;
    FILE *userdbtmp;
    char envpassword[MAX_INPUT_CHARS + 1];
    char envusername[MAX_INPUT_CHARS + 1];
    char database_path[PATH_MAX];
    char database_temp[PATH_MAX];
    char *hash;
    char *salt;
    char *username;
    char hash_with_salt[SALTED_HASH_LENGTH + 1];
    char line[MAX_LINE_SIZE];
    int action = ACTION_NOOP;

    strncpy(database_path, getenv("OVPNAUTH_DBPATH") ?: "auth.db", PATH_MAX);
    database_path[PATH_MAX - 1] = '\0';
    if ((strlen(database_path) + 5) > PATH_MAX) {
        // strlen(strcat(database_path, ".new")) > (PATH_MAX - 1)
        fputs("Database path too long.\n", stderr);
        return 1;
    }

    userdb = fopen(database_path, "a+");
    if (userdb == NULL) {
        ERRNO_DIE("Unable to open user database");
    }

    strncpy(envusername, getenv("username") ?: "", MAX_INPUT_CHARS);
    strncpy(envpassword, getenv("password") ?: "", MAX_INPUT_CHARS);

    if (*envusername && *envpassword) {
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

    if (action & (ACTION_EDIT | ACTION_REMOVE)) {
        if (argc > 2) {
            strncpy(envusername, argv[2], MAX_INPUT_CHARS);
        } else {
            printf("Username: ");
            READ_INTO(envusername, MAX_INPUT_CHARS);
        }

        if (action == ACTION_EDIT) {
            if (isatty(STDIN_FILENO)) {
                strncpy(envpassword, getpass("Password: "), MAX_INPUT_CHARS);
                if (strcmp(getpass("Retype password: "), envpassword)) {
                    puts("Passwords did not match.");
                    return 1;
                }
            } else {
                printf("Password: ");
                READ_INTO(envpassword, MAX_INPUT_CHARS);
            }

            if (saltedhash(envpassword, NULL, hash_with_salt)) {
                fputs("Unable to initialize OpenSSL SHA methods.\n", stderr);
                return 1;
            }
        }
    }

    if (action & ACTION_LOCKS_DATABASE) {
        int lock_timeout = atoi(getenv("OVPNAUTH_LOCK_TIMEOUT") ?: "2");

        strcpy(database_temp, database_path);
        strcat(database_temp, ".new");

        userdbtmp = excl_open(database_temp, "w", lock_timeout);
        if (userdbtmp == NULL) {
            ERRNO_DIE("Unable to lock database");
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
            fclose(userdbtmp);
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
    if (rename(database_temp, database_path)) {
        ERRNO_DIE("Could not save changes");
    }

    return 0;
}
