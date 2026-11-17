// SPDX-License-Identifier: GPL-3.0-or-later
// PID 1 owns only the disposable reference namespace; tests run as PID 2.
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 125;
    if (getsid(0) != 1 && setsid() < 0) { perror("reference session"); return 125; }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq link = {0};
    strcpy(link.ifr_name, "lo");
    if (fd < 0 || ioctl(fd, SIOCGIFFLAGS, &link) < 0) {
        perror("reference loopback read"); return 125;
    }
    link.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &link) < 0) {
        perror("reference loopback up"); return 125;
    }
    close(fd);
    pid_t child = fork();
    if (child < 0) { perror("reference fork"); return 125; }
    if (child == 0) {
        execvp(argv[1], argv + 1);
        perror("reference exec"); _exit(125);
    }
    for (;;) {
        int status;
        pid_t reaped = waitpid(-1, &status, 0);
        if (reaped < 0 && errno == EINTR) continue;
        if (reaped < 0) { perror("reference wait"); return 125; }
        if (reaped == child)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    }
}
