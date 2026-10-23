/* SPDX-License-Identifier: MIT
 *
 * ProFast-Net XDP loader.
 *
 *   profast-xdp attach <ifname>        load, pin maps, attach in observe mode
 *   profast-xdp enforce <ifname>       flip pf_mode to default-deny
 *   profast-xdp observe <ifname>       flip pf_mode back to observe only
 *   profast-xdp allow <ifname> <port>  add a port to pf_ports
 *   profast-xdp deny-all <ifname>      clear pf_ports
 *   profast-xdp stats <ifname>         print pass/drop/bypass counters
 *   profast-xdp detach <ifname>
 *
 * The pinned map paths are the contract with the daemon: it never needs the
 * loader binary at runtime, only libbpf and the pinned maps.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>

#define PIN_DIR "/sys/fs/bpf/profast"
#define PIN_MODE PIN_DIR "/mode"
#define PIN_PORTS PIN_DIR "/ports"
#define PIN_STATS PIN_DIR "/stats"

static int set_mode(__u32 value)
{
    int fd = bpf_obj_get(PIN_MODE);
    __u32 key = 0;
    int rc;

    if (fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", PIN_MODE, strerror(errno));
        return 1;
    }
    rc = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
    close(fd);
    return rc == 0 ? 0 : 1;
}

static int set_port(__u16 port)
{
    int fd = bpf_obj_get(PIN_PORTS);
    __u8 value = 1;
    int rc;

    if (fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", PIN_PORTS, strerror(errno));
        return 1;
    }
    rc = bpf_map_update_elem(fd, &port, &value, BPF_ANY);
    close(fd);
    return rc == 0 ? 0 : 1;
}

static int clear_ports(void)
{
    int fd = bpf_obj_get(PIN_PORTS);
    __u16 key;

    if (fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", PIN_PORTS, strerror(errno));
        return 1;
    }
    /* Deleting the key returned by get_next_key(NULL) walks the map safely. */
    while (bpf_map_get_next_key(fd, NULL, &key) == 0) {
        bpf_map_delete_elem(fd, &key);
    }
    close(fd);
    return 0;
}

static int show_stats(void)
{
    int fd = bpf_obj_get(PIN_STATS);
    const char *names[3] = {"pass", "drop", "bypass"};
    __u32 key;

    if (fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", PIN_STATS, strerror(errno));
        return 1;
    }
    for (key = 0; key < 3; key++) {
        __u64 value = 0;
        if (bpf_map_lookup_elem(fd, &key, &value) == 0) {
            printf("%-8s %llu\n", names[key], (unsigned long long)value);
        }
    }
    close(fd);
    return 0;
}

static int attach(const char *ifname)
{
    struct bpf_object *object;
    struct bpf_program *program;
    int ifindex = if_nametoindex(ifname);
    int rc;

    if (ifindex == 0) {
        fprintf(stderr, "unknown interface %s\n", ifname);
        return 1;
    }

    object = bpf_object__open_file("profast_xdp.bpf.o", NULL);
    if (!object) {
        fprintf(stderr, "cannot open profast_xdp.bpf.o (build it with make)\n");
        return 1;
    }
    if (bpf_object__load(object) != 0) {
        fprintf(stderr, "the verifier rejected the program\n");
        bpf_object__close(object);
        return 1;
    }

    program = bpf_object__find_program_by_name(object, "profast_xdp_prog");
    if (!program) {
        fprintf(stderr, "program not found in object\n");
        bpf_object__close(object);
        return 1;
    }

    mkdir(PIN_DIR, 0755);
    rc = bpf_object__pin_maps(object, PIN_DIR);
    if (rc != 0 && rc != -EEXIST) {
        fprintf(stderr, "cannot pin maps under %s\n", PIN_DIR);
    }

    rc = bpf_xdp_attach(ifindex, bpf_program__fd(program), 0, NULL);
    if (rc != 0) {
        fprintf(stderr, "cannot attach to %s: %s\n", ifname, strerror(-rc));
        bpf_object__close(object);
        return 1;
    }

    printf("attached to %s (observe mode)\n", ifname);
    bpf_object__close(object);
    return 0;
}

static int detach(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "unknown interface %s\n", ifname);
        return 1;
    }
    if (bpf_xdp_detach(ifindex, 0, NULL) != 0) {
        fprintf(stderr, "no XDP program attached to %s\n", ifname);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s attach|enforce|observe|allow|deny-all|stats|detach <ifname> [port]\n",
                argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "attach") == 0) {
        return attach(argv[2]);
    }
    if (strcmp(argv[1], "detach") == 0) {
        return detach(argv[2]);
    }
    if (strcmp(argv[1], "enforce") == 0) {
        return set_mode(1);
    }
    if (strcmp(argv[1], "observe") == 0) {
        return set_mode(0);
    }
    if (strcmp(argv[1], "allow") == 0) {
        if (argc < 4) {
            fprintf(stderr, "allow needs a port\n");
            return 2;
        }
        return set_port((__u16)atoi(argv[3]));
    }
    if (strcmp(argv[1], "deny-all") == 0) {
        return clear_ports();
    }
    if (strcmp(argv[1], "stats") == 0) {
        return show_stats();
    }

    fprintf(stderr, "unknown command %s\n", argv[1]);
    return 2;
}
