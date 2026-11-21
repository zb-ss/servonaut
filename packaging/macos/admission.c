/*
 * Acquire admission before the frozen runtime opens any bundle files.
 * The shared flock survives exec and is released by the OS on process exit.
 */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef SYSTEM_APPS
#define SYSTEM_APPS "/Applications"
#endif
#ifndef SERVONAUT_ADMISSION_WAIT_SECONDS
#define SERVONAUT_ADMISSION_WAIT_SECONDS 10
#endif
#define APPLICATION "/Servonaut.app"
#define MACOS "/Contents/MacOS/"
#define WORK_NAME "/.servonaut-desktop-update/"
#define WORKER_SUFFIX ".runtime"
#define INTERNAL_HELPER "--_macos-install-update"

static int is_entry(const char *name) {
    return strcmp(name, "servonaut") == 0 ||
           strcmp(name, "servonaut-desktop") == 0 ||
           strcmp(name, "servonaut-desktop-child") == 0;
}

static int lock_until_ready(int fd) {
    struct timespec started, now, delay = {0, 50000000L};
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
        return -1;
    while (flock(fd, LOCK_SH | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR)
            return -1;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            return -1;
        double elapsed = (double)(now.tv_sec - started.tv_sec) +
                         (double)(now.tv_nsec - started.tv_nsec) / 1000000000.0;
        if (elapsed >= SERVONAUT_ADMISSION_WAIT_SECONDS)
            return -1;
        nanosleep(&delay, NULL);
    }
    return 0;
}

static int admit(const char *parent) {
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd == -1)
        return -1;
    if (fd <= STDERR_FILENO) {
        int original = fd;
        fd = fcntl(original, F_DUPFD, STDERR_FILENO + 1);
        close(original);
        if (fd == -1)
            return -1;
    }
    if (lock_until_ready(fd) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

static int reserved(const char *path, int argc, char **argv) {
    if (strstr(path, APPLICATION ".previous" MACOS) != NULL)
        return 1;
    const char *work = strstr(path, WORK_NAME);
    if (work == NULL)
        return 0;
    return !(strcmp(work, WORK_NAME "helper" APPLICATION MACOS "servonaut") == 0 &&
             argc == 3 && strcmp(argv[1], INTERNAL_HELPER) == 0);
}

static int matches_directory(const struct stat *actual, const char *path) {
    struct stat other;
    return stat(path, &other) == 0 &&
           actual->st_dev == other.st_dev && actual->st_ino == other.st_ino;
}

static int installed_parent(const char *bundle, const char *parent) {
    const char *name = strrchr(bundle, '/');
    if (name == NULL || strcasecmp(name, APPLICATION) != 0)
        return 0;
    struct stat base, app;
    if (stat(parent, &base) != 0 || stat(bundle, &app) != 0)
        return 1;
    if (matches_directory(&base, SYSTEM_APPS))
        return 1;
    /* Use the installation owner's account, including launches through sudo. */
    struct passwd *account = getpwuid(app.st_uid);
    if (account == NULL)
        return 1;
    char user_apps[PROC_PIDPATHINFO_MAXSIZE];
    int length = snprintf(user_apps, sizeof(user_apps), "%s/Applications", account->pw_dir);
    if (length < 0 || length >= (int)sizeof(user_apps))
        return 1;
    if (matches_directory(&base, user_apps))
        return 1;
    const char *folder = strrchr(parent, '/');
    return folder != NULL && strcasecmp(folder, "/Applications") == 0;
}

static int ascend(char *path) {
    char *slash = strrchr(path, '/');
    if (slash == NULL)
        return -1;
    if (slash == path)
        slash++;
    *slash = '\0';
    return 0;
}

static int launch_error(const char *message) {
    syslog(LOG_ERR, "%s", message);
    fputs(message, stderr);
    fputc('\n', stderr);
    return 1;
}

static int boot(const char *path, const char *parent, int guarded, char **argv) {
    char worker[PROC_PIDPATHINFO_MAXSIZE];
    /* Keep the fd open across exec. An unrelated exclusive lock can delay a
     * launch but cannot require the user to stop a different account's process. */
    if (guarded && admit(parent) == -1) {
        const char *warning = "Servonaut could not obtain the update lock. Continuing to launch.";
        syslog(LOG_WARNING, "%s", warning);
        fprintf(stderr, "%s\n", warning);
    }
    if (snprintf(worker, sizeof(worker), "%s" WORKER_SUFFIX, path) >= (int)sizeof(worker))
        return launch_error("The Servonaut executable path is too long.");
    argv[0] = worker;
    execv(worker, argv);
    return launch_error("Could not start the Servonaut executable.");
}

int main(int argc, char **argv) {
    char observed[PROC_PIDPATHINFO_MAXSIZE], resolved[PROC_PIDPATHINFO_MAXSIZE];
    if (argc < 1 || proc_pidpath(getpid(), observed, sizeof(observed)) <= 0)
        return launch_error("Could not identify the Servonaut executable.");
    const char *path = realpath(observed, resolved);
    if (path == NULL)
        path = observed;
    if (reserved(path, argc, argv))
        return launch_error("Open the installed Servonaut application.");
    const char *name = strrchr(path, '/');
    if (name == NULL || !is_entry(++name))
        return launch_error("The Servonaut executable name is invalid.");
    char bundle[PROC_PIDPATHINFO_MAXSIZE], parent[PROC_PIDPATHINFO_MAXSIZE];
    strcpy(bundle, path);
    if (ascend(bundle) != 0 || ascend(bundle) != 0 || ascend(bundle) != 0)
        return launch_error("Could not find the Servonaut application bundle.");
    strcpy(parent, bundle);
    if (ascend(parent) != 0)
        return launch_error("Could not find the Servonaut application directory.");
    return boot(path, parent, installed_parent(bundle, parent), argv);
}
