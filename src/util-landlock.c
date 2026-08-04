/* Copyright (C) 2022,2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Eric Leblond <el@stamus-networks.com>
 */

#include "suricata.h"
#include "detect-engine.h"
#include "feature.h"
#include "output.h"
#include "util-byte.h"
#include "util-conf.h"
#include "util-file.h"
#include "util-landlock.h"
#include "util-mem.h"
#include "util-path.h"
#include "util-plugin.h"
#include "util-validate.h"

/* Registry of pending per-file grants populated during configuration
 * parsing. Consumed by LandlockSandboxing() before enforcement (see the
 * HAVE_LINUX_LANDLOCK_H branch below). Kept out of the LSM-specific block
 * so callers can register unconditionally. */
typedef struct SCLandlockPendingFile_ {
    char *path;
    uint32_t access;
    TAILQ_ENTRY(SCLandlockPendingFile_) next;
} SCLandlockPendingFile;

static TAILQ_HEAD(, SCLandlockPendingFile_) sc_landlock_pending_files = TAILQ_HEAD_INITIALIZER(
        sc_landlock_pending_files);

void SCLandlockForEachOutput(void *ruleset, const char *name, SCLandlockOutputFunc cb)
{
    if (name == NULL || cb == NULL)
        return;

    SCConfNode *outputs = SCConfGetNode("outputs");
    if (outputs == NULL)
        return;

    SCConfNode *conf = NULL;
    while ((conf = SCConfNodeLookupInSequence(outputs, name, conf)) != NULL) {
        const char *enabled = SCConfNodeLookupChildValue(conf, "enabled");
        if (enabled == NULL || !SCConfValIsTrue(enabled))
            continue;
        cb(ruleset, conf);
    }
}

void SCLandlockRegisterFile(const char *path, uint32_t access)
{
    if (path == NULL || access == 0)
        return;
    SCLandlockPendingFile *e = SCCalloc(1, sizeof(*e));
    if (e == NULL)
        return;
    e->path = SCStrdup(path);
    if (e->path == NULL) {
        SCFree(e);
        return;
    }
    e->access = access;
    TAILQ_INSERT_TAIL(&sc_landlock_pending_files, e, next);
}

static void SCLandlockPendingFilesFree(void)
{
    SCLandlockPendingFile *e, *tmp;
    TAILQ_FOREACH_SAFE (e, &sc_landlock_pending_files, next, tmp) {
        TAILQ_REMOVE(&sc_landlock_pending_files, e, next);
        SCFree(e->path);
        SCFree(e);
    }
}

#ifndef HAVE_LINUX_LANDLOCK_H

void LandlockSandboxing(SCInstance *suri)
{
    /* Drop any pending file registrations even when the sandbox is not
     * built in, so callers do not leak. */
    SCLandlockPendingFilesFree();
}

void SCLandlockGrantReadPath(void *ruleset, const char *path)
{
}

void SCLandlockGrantWritePath(void *ruleset, const char *path)
{
}

void SCLandlockGrantWriteReferPath(void *ruleset, const char *path)
{
}

void SCLandlockGrantWriteRemovePath(void *ruleset, const char *path)
{
}

void SCLandlockGrantSocketPath(void *ruleset, const char *path)
{
}

void SCLandlockGrantRewritePath(void *ruleset, const char *path)
{
}

void SCLandlockGrantFile(void *ruleset, const char *path, uint32_t access)
{
}

void SCLandlockGrantNetBindTCP(void *ruleset, uint16_t port)
{
}

void SCLandlockGrantNetConnectTCP(void *ruleset, uint16_t port)
{
}

#else /* HAVE_LINUX_LANDLOCK_H */

#include <linux/landlock.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
        const struct landlock_ruleset_attr *const attr, const size_t size, const __u32 flags)
{
    long r = syscall(__NR_landlock_create_ruleset, attr, size, flags);
    DEBUG_VALIDATE_BUG_ON(r > INT_MAX);
    return (int)r;
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type,
        const void *const rule_attr, const __u32 flags)
{
    long r = syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
    DEBUG_VALIDATE_BUG_ON(r > INT_MAX);
    return (int)r;
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const __u32 flags)
{
    long r = syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
    DEBUG_VALIDATE_BUG_ON(r > INT_MAX);
    return (int)r;
}
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 18)
#endif

#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif

#ifndef LANDLOCK_SCOPE_SIGNAL
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

#define _LANDLOCK_ACCESS_FS_WRITE                                                                  \
    (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |                               \
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |                        \
            LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                            \
            LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |                          \
            LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |                          \
            LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE |                               \
            LANDLOCK_ACCESS_FS_IOCTL_DEV | LANDLOCK_ACCESS_FS_RESOLVE_UNIX)

#define _LANDLOCK_ACCESS_FS_READ (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)

/* Default write grant for directories Suricata owns.
 *
 * Deliberately excludes LANDLOCK_ACCESS_FS_REMOVE_FILE and
 * LANDLOCK_ACCESS_FS_TRUNCATE: those are classic anti-forensics primitives
 * (unlinking or zeroing logs/state to erase attacker traces). Also excludes
 * LANDLOCK_ACCESS_FS_MAKE_SOCK, which only the unix command socket needs --
 * a module that merely connects to an existing socket does not.
 * Subsystems that legitimately need any of these -- filestore staging
 * cleanup, pcap ring-buffer rotation, datasets state.csv rewrite, the unix
 * command socket -- must register a scoped grant on their own directory or
 * file.
 *
 * MAKE_DIR stays in: creating a subdirectory on the fly is common enough
 * (tls-store's certs directory, any log filename holding a path, the
 * Hyperscan cache) that carving it out would only push the same grant into
 * most callers. */
#define _LANDLOCK_SURI_ACCESS_FS_WRITE                                                             \
    (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR)

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif
#define _LANDLOCK_ACCESS_NET (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)

struct landlock_ruleset {
    int fd;
    struct landlock_ruleset_attr attr;
};

static inline struct landlock_ruleset *LandlockCreateRuleset(void)
{
    struct landlock_ruleset *ruleset = SCCalloc(1, sizeof(struct landlock_ruleset));
    if (ruleset == NULL) {
        SCLogError("Can't alloc landlock ruleset");
        return NULL;
    }

    ruleset->attr.handled_access_fs =
            _LANDLOCK_ACCESS_FS_READ | _LANDLOCK_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_EXECUTE;
#ifdef HAVE_LANDLOCK_RULESET_ATTR_HANDLED_ACCESS_NET
    ruleset->attr.handled_access_net = _LANDLOCK_ACCESS_NET;
#endif

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        SCFree(ruleset);
        return NULL;
    }
    switch (abi) {
        case 1:
        case 2:
            if (SCRequiresFeature(FEATURE_OUTPUT_FILESTORE)) {
                SCLogError("Landlock disabled: need Linux 5.19+ for file store support");
                SCFree(ruleset);
                return NULL;
            } else {
                ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
            }
            __attribute__((fallthrough));
        case 3:
#ifdef HAVE_LANDLOCK_RULESET_ATTR_HANDLED_ACCESS_NET
            ruleset->attr.handled_access_net &= ~_LANDLOCK_ACCESS_NET;
#endif
            __attribute__((fallthrough));
        case 4:
            ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
            __attribute__((fallthrough));
        case 5:
#ifdef HAVE_LANDLOCK_RULESET_ATTR_SCOPED
            ruleset->attr.scoped &= ~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL);
#endif
            __attribute__((fallthrough));
        case 6 ... 8:
            /* Removes LANDLOCK_ACCESS_FS_RESOLVE_UNIX for ABI < 9 */
            ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    }

    ruleset->fd = landlock_create_ruleset(&ruleset->attr, sizeof(ruleset->attr), 0);
    if (ruleset->fd < 0) {
        SCFree(ruleset);
        SCLogError("Can't create landlock ruleset");
        return NULL;
    }
    return ruleset;
}

static inline void LandlockEnforceRuleset(struct landlock_ruleset *ruleset)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        SCLogError("Can't self restrict (prctl phase): %s", strerror(errno));
        return;
    }
    if (landlock_restrict_self(ruleset->fd, 0)) {
        SCLogError("Can't self restrict (landlock phase): %s", strerror(errno));
    }
}

static int LandlockSandboxingAddRule(
        struct landlock_ruleset *ruleset, const char *directory, uint64_t permission)
{
    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = permission & ruleset->attr.handled_access_fs,
    };

    int dir_fd = open(directory, O_PATH | O_CLOEXEC | O_DIRECTORY);
    if (dir_fd == -1) {
        /* A directory listed in the configuration that does not exist on this
         * system is not an error: there is simply nothing to grant. Default
         * paths such as the sysconfdir are missing whenever Suricata runs
         * from a build tree. Report anything else as a warning. */
        if (errno == ENOENT) {
            SCLogConfig("Skipping landlock rule for missing directory '%s'", directory);
        } else {
            SCLogWarning("Can't open '%s' for landlock rule: %s", directory, strerror(errno));
        }
        return -1;
    }
    path_beneath.parent_fd = dir_fd;

    if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
        SCLogError("Can't add write rule: %s", strerror(errno));
        close(dir_fd);
        return -1;
    }

    close(dir_fd);
    return 0;
}

void SCLandlockGrantWritePath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_SURI_ACCESS_FS_WRITE) == 0) {
        SCLogConfig("Added write permission to '%s'", directory);
    }
}

void SCLandlockGrantWriteReferPath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    /* Callers of this helper own the whole subtree (e.g. filestore staging +
     * final tree): they need to move files across subdirectories (FS_REFER)
     * and unlink staged/failed files (FS_REMOVE_FILE). REMOVE is kept out of
     * the default write grant since it's a common anti-forensics primitive,
     * so only opt-in callers that manage their own private tree get it. */
    uint64_t access = _LANDLOCK_SURI_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_REFER |
                      LANDLOCK_ACCESS_FS_REMOVE_FILE;
    if (LandlockSandboxingAddRule(ruleset, directory, access) == 0) {
        SCLogConfig("Added write+refer permission to '%s'", directory);
    }
}

void SCLandlockGrantWriteRemovePath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    uint64_t access = _LANDLOCK_SURI_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_REMOVE_FILE;
    if (LandlockSandboxingAddRule(ruleset, directory, access) == 0) {
        SCLogConfig("Added write+remove permission to '%s'", directory);
    }
}

void SCLandlockGrantSocketPath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    /* Binding a unix socket needs FS_MAKE_SOCK, and Suricata unlinks any
     * stale socket first, so FS_REMOVE_FILE too. MAKE_SOCK is out of the
     * default write grant because only the unix command socket creates one:
     * eve-log's unix_stream/unix_dgram filetypes connect() to a socket
     * somebody else made, they never bind. */
    uint64_t access = _LANDLOCK_SURI_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                      LANDLOCK_ACCESS_FS_MAKE_SOCK;
    if (LandlockSandboxingAddRule(ruleset, directory, access) == 0) {
        SCLogConfig("Added socket permission to '%s'", directory);
    }
}

void SCLandlockGrantReadPath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_ACCESS_FS_READ) == 0) {
        SCLogConfig("Added read permission to '%s'", directory);
    }
}

void SCLandlockGrantRewritePath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    /* Rewriting a state file in place means fopen(..., "w"), which needs
     * FS_TRUNCATE on top of read and write. Kept out of the plain write
     * grant since truncation is an anti-forensics primitive: callers opt in
     * for a directory they own. */
    uint64_t access =
            _LANDLOCK_ACCESS_FS_READ | _LANDLOCK_SURI_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_TRUNCATE;
    if (LandlockSandboxingAddRule(ruleset, directory, access) == 0) {
        SCLogConfig("Added read+write+truncate permission to '%s'", directory);
    }
}

void SCLandlockGrantFile(void *vruleset, const char *path, uint32_t access)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || path == NULL || access == 0)
        return;

    uint64_t permission = 0;
    if (access & SC_LANDLOCK_FILE_READ)
        permission |= LANDLOCK_ACCESS_FS_READ_FILE;
    if (access & SC_LANDLOCK_FILE_WRITE)
        permission |= LANDLOCK_ACCESS_FS_WRITE_FILE;
    if (access & SC_LANDLOCK_FILE_TRUNCATE)
        permission |= LANDLOCK_ACCESS_FS_TRUNCATE;

    permission &= ruleset->attr.handled_access_fs;
    if (permission == 0) {
        SCLogInfo("Landlock: no supported access bits for file '%s'; skipping", path);
        return;
    }

    int open_flags = O_PATH | O_CLOEXEC | O_NOFOLLOW;
    int need_create = (access & (SC_LANDLOCK_FILE_WRITE | SC_LANDLOCK_FILE_TRUNCATE)) != 0;
    if (need_create) {
        int cfd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (cfd == -1) {
            SCLogWarning("Can't create '%s' for landlock rule: %s", path, strerror(errno));
            return;
        }
        close(cfd);
    }

    int fd = open(path, open_flags);
    if (fd == -1) {
        SCLogWarning("Can't open '%s' for landlock rule: %s", path, strerror(errno));
        return;
    }

    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = permission,
        .parent_fd = fd,
    };
    if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
        SCLogWarning("Can't add file rule for '%s': %s", path, strerror(errno));
        close(fd);
        return;
    }
    close(fd);
    SCLogConfig("Added file permission (0x%x) on '%s'", access, path);
}

#ifdef HAVE_LANDLOCK_RULESET_ATTR_HANDLED_ACCESS_NET
static void LandlockGrantNetPort(
        struct landlock_ruleset *ruleset, uint16_t port, uint64_t access, const char *access_name)
{
    if (ruleset == NULL)
        return;
    if ((ruleset->attr.handled_access_net & access) == 0) {
        SCLogInfo("Landlock network access %s not available; skipping port %u", access_name, port);
        return;
    }
    struct landlock_net_port_attr net_port = {
        .allowed_access = access,
        .port = port,
    };
    if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_NET_PORT, &net_port, 0)) {
        SCLogError("Can't add net rule (%s, port %u): %s", access_name, port, strerror(errno));
        return;
    }
    SCLogConfig("Added net %s permission on port %u", access_name, port);
}
#endif

void SCLandlockGrantNetBindTCP(void *vruleset, uint16_t port)
{
#ifdef HAVE_LANDLOCK_RULESET_ATTR_HANDLED_ACCESS_NET
    LandlockGrantNetPort(
            (struct landlock_ruleset *)vruleset, port, LANDLOCK_ACCESS_NET_BIND_TCP, "bind-tcp");
#else
    (void)vruleset;
    (void)port;
#endif
}

void SCLandlockGrantNetConnectTCP(void *vruleset, uint16_t port)
{
#ifdef HAVE_LANDLOCK_RULESET_ATTR_HANDLED_ACCESS_NET
    LandlockGrantNetPort((struct landlock_ruleset *)vruleset, port, LANDLOCK_ACCESS_NET_CONNECT_TCP,
            "connect-tcp");
#else
    (void)vruleset;
    (void)port;
#endif
}

static void LandlockSandboxingApplyNetPorts(
        void *v_ruleset, const char *conf_key, void (*grant)(void *, uint16_t))
{
    struct landlock_ruleset *ruleset = v_ruleset;
    SCConfNode *ports = SCConfGetNode(conf_key);
    if (ports == NULL)
        return;
    if (!SCConfNodeIsSequence(ports)) {
        SCLogWarning(
                "Invalid %s configuration section: expected a list of port numbers.", conf_key);
        return;
    }
    SCConfNode *port_node;
    TAILQ_FOREACH (port_node, &ports->head, next) {
        if (port_node->val == NULL)
            continue;
        uint16_t port = 0;
        if (StringParseUint16(&port, 10, 0, port_node->val) < 0 || port == 0) {
            SCLogWarning("Invalid port '%s' in %s: expected a value in [1, 65535].", port_node->val,
                    conf_key);
            continue;
        }
        grant(ruleset, port);
    }
}

/** \brief Grant read access on system pseudo-filesystem paths.
 *
 *  Paths that glibc, jemalloc and Rust stdlib probe during normal startup and
 *  runtime. Granting read here avoids spurious EACCES (and audit noise) without
 *  measurably widening the sandbox: every Linux process can already read these.
 *  Paths are granted as-is when they exist; missing paths are silently skipped.
 *
 *  \param ruleset the landlock ruleset to add the read rules to
 */
static void LandlockGrantSystemReadPaths(struct landlock_ruleset *ruleset)
{
    static const char *const system_read_paths[] = {
        "/sys/devices/system/cpu",        /* sysconf(_SC_NPROCESSORS_*) */
        "/proc/stat",                     /* CPU/system statistics */
        "/proc/sys/vm/overcommit_memory", /* malloc tuning */
        "/dev/urandom",                   /* RNG seeding fallback */
    };

    for (size_t i = 0; i < sizeof(system_read_paths) / sizeof(system_read_paths[0]); i++) {
        const char *path = system_read_paths[i];
        /* Open directly instead of stat()+open() to avoid a TOCTOU race: a
         * missing or unreadable path simply fails here and is skipped. */
        int path_fd = open(path, O_PATH | O_CLOEXEC);
        if (path_fd == -1) {
            SCLogDebug("Can't open %s for landlock: %s", path, strerror(errno));
            continue;
        }
        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE & ruleset->attr.handled_access_fs,
            .parent_fd = path_fd,
        };
        if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
            SCLogDebug("Can't add system read rule for %s: %s", path, strerror(errno));
        }
        close(path_fd);
    }
}

/** \brief Grant read access on a rule file given on the command line.
 *
 *  Only absolute paths get a rule: a relative one is resolved by
 *  DetectLoadCompleteSigPathWithKey() against a configured rule path, a
 *  directory that is granted separately. No-op on a NULL path or when the
 *  file does not exist -- a missing rule file is an error Suricata reports
 *  on its own, not something to warn about here.
 */
static void LandlockGrantRuleFile(struct landlock_ruleset *ruleset, const char *path)
{
    if (path == NULL || !PathIsAbsolute(path))
        return;
    if (!SCPathExists(path))
        return;
    SCLandlockGrantFile(ruleset, path, SC_LANDLOCK_FILE_READ);
}

void LandlockSandboxing(SCInstance *suri)
{
    /* Read configuration variable and exit if no enforcement */
    int conf_status;
    if (SCConfGetBool("security.landlock.enabled", &conf_status) == 0) {
        conf_status = 0;
    }
    if (!conf_status) {
        SCLogConfig("Landlock is not enabled in configuration");
        return;
    }
    struct landlock_ruleset *ruleset = LandlockCreateRuleset();
    if (ruleset == NULL) {
        SCLogError("Kernel does not support Landlock");
        return;
    }

    LandlockGrantSystemReadPaths(ruleset);

    SCLandlockGrantWritePath(ruleset, SCConfigGetLogDirectory());
    struct stat sb;
    if (stat(ConfigGetDataDirectory(), &sb) == 0) {
        uint64_t data_dir_access = _LANDLOCK_SURI_ACCESS_FS_WRITE | _LANDLOCK_ACCESS_FS_READ;
        /* Datasets rewrite their state file with fopen("w"), which requires
         * FS_TRUNCATE on the parent directory. Grant it only when datasets
         * are configured so unrelated deployments don't get truncate on the
         * data-dir for free. Live rule reload can add new dataset save
         * files under this directory, so we grant on the whole dir up
         * front rather than per-file. */
        if (SCConfGetNode("datasets") != NULL) {
            data_dir_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        LandlockSandboxingAddRule(ruleset, ConfigGetDataDirectory(), data_dir_access);
    }
    if (DetectEngineMpmCachingEnabled() && stat(DetectEngineMpmCachingGetPath(), &sb) == 0) {
        /* MPM cache is a Suricata-private directory: HS pruning + corruption
         * cleanup remove entries there. Grant REMOVE alongside write+read. */
        LandlockSandboxingAddRule(ruleset, DetectEngineMpmCachingGetPath(),
                _LANDLOCK_SURI_ACCESS_FS_WRITE | _LANDLOCK_ACCESS_FS_READ |
                        LANDLOCK_ACCESS_FS_REMOVE_FILE);
    }
    if (suri->run_mode == RUNMODE_PCAP_FILE) {
        const char *pcap_file;
        if (SCConfGetNonNull("pcap-file.file", &pcap_file) == 1) {
            /* When delete-when-done is set, the pcap reader unlinks the
             * source pcap after processing; we then need REMOVE on the
             * containing directory in addition to read. */
            const char *delete_str = NULL;
            int delete_bool = 0;
            bool delete_when_done =
                    (SCConfGetNonNull("pcap-file.delete-when-done", &delete_str) == 1 &&
                            (strcmp(delete_str, "non-alerts") == 0 ||
                                    (SCConfGetBool("pcap-file.delete-when-done", &delete_bool) ==
                                                    1 &&
                                            delete_bool)));
            char *file_name = SCStrdup(pcap_file);
            if (file_name != NULL) {
                struct stat statbuf;
                if (stat(file_name, &statbuf) != -1) {
                    const char *dir = S_ISDIR(statbuf.st_mode) ? file_name : dirname(file_name);
                    if (delete_when_done) {
                        LandlockSandboxingAddRule(ruleset, dir,
                                _LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_REMOVE_FILE);
                    } else {
                        SCLandlockGrantReadPath(ruleset, dir);
                    }
                } else {
                    SCLogError("Can't open pcap file");
                }
                SCFree(file_name);
            }
        }
    }
    if (suri->sig_file) {
        char *file_name = SCStrdup(suri->sig_file);
        if (file_name != NULL) {
            SCLandlockGrantReadPath(ruleset, dirname(file_name));
            SCFree(file_name);
        }
    }
    /* Per-file read grants for classification.config, reference.config and
     * threshold.config. These paths may live outside any directory Suricata
     * otherwise grants (e.g. --set classification-file=/some/etc/...),
     * so a per-file rule keeps the grant minimal. When the config key is
     * unset Suricata falls back to the compiled-in CONFIG_DIR default; grant
     * that too when the file is actually present at the build-time path so
     * the fallback fopen() isn't denied. */
    const char *class_file;
    if (SCConfGetNonNull("classification-file", &class_file) == 1) {
        SCLandlockGrantFile(ruleset, class_file, SC_LANDLOCK_FILE_READ);
    } else if (SCPathExists(CONFIG_DIR "/classification.config")) {
        SCLandlockGrantFile(ruleset, CONFIG_DIR "/classification.config", SC_LANDLOCK_FILE_READ);
    }
    const char *ref_file;
    if (SCConfGetNonNull("reference-config-file", &ref_file) == 1) {
        SCLandlockGrantFile(ruleset, ref_file, SC_LANDLOCK_FILE_READ);
    } else if (SCPathExists(CONFIG_DIR "/reference.config")) {
        SCLandlockGrantFile(ruleset, CONFIG_DIR "/reference.config", SC_LANDLOCK_FILE_READ);
    }
    const char *thr_file;
    if (SCConfGetNonNull("threshold-file", &thr_file) == 1) {
        SCLandlockGrantFile(ruleset, thr_file, SC_LANDLOCK_FILE_READ);
    } else if (SCPathExists(CONFIG_DIR "/threshold.config")) {
        SCLandlockGrantFile(ruleset, CONFIG_DIR "/threshold.config", SC_LANDLOCK_FILE_READ);
    }
    if (suri->pid_filename) {
        /* PID file is written at startup and unlinked on shutdown, so REMOVE
         * is required on its containing directory. */
        char *file_name = SCStrdup(suri->pid_filename);
        if (file_name != NULL) {
            SCLandlockGrantWriteRemovePath(ruleset, dirname(file_name));
            SCFree(file_name);
        }
    }
    /* ConfUnixSocketIsEnable() only looks at unix-command.enabled, which
     * --unix-socket does not set: it selects the runmode instead. Check both
     * or the socket directory goes ungranted exactly when the socket is
     * certain to be used. */
    if (ConfUnixSocketIsEnable() || SCRunmodeGet() == RUNMODE_UNIX_SOCKET) {
        /* Binding the socket needs MAKE_SOCK, and Suricata unlinks any stale
         * socket first, so REMOVE is required on the socket directory too. */
        const char *socketname;
        if (SCConfGetNonNull("unix-command.filename", &socketname) == 1) {
            if (PathIsAbsolute(socketname)) {
                char *file_name = SCStrdup(socketname);
                if (file_name != NULL) {
                    SCLandlockGrantSocketPath(ruleset, dirname(file_name));
                    SCFree(file_name);
                }
            } else {
                SCLandlockGrantSocketPath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
            }
        } else {
            SCLandlockGrantSocketPath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
        }
    }
    if (!suri->sig_file_exclusive) {
        const char *rule_path;
        if (SCConfGetNonNull("default-rule-path", &rule_path) == 1 && rule_path) {
            SCLandlockGrantReadPath(ruleset, rule_path);
        }
    }
    /* The firewall rule file (--firewall-rules-exclusive) is loaded from the
     * path as provided, so an absolute one may sit outside every directory
     * granted above -- unlike sig_file, whose directory is granted earlier.
     * Grant it per-file to keep the rule minimal. A relative path is resolved
     * against firewall.rule-path, already covered by the directory grants. */
    LandlockGrantRuleFile(ruleset, suri->firewall_rule_file);

    SCConfNode *read_dirs = SCConfGetNode("security.landlock.directories.read");
    if (read_dirs) {
        if (!SCConfNodeIsSequence(read_dirs)) {
            SCLogWarning("Invalid security.landlock.directories.read configuration section: "
                         "expected a list of directory names.");
        } else {
            SCConfNode *directory;
            TAILQ_FOREACH (directory, &read_dirs->head, next) {
                SCLandlockGrantReadPath(ruleset, directory->val);
            }
        }
    }
    SCConfNode *write_dirs = SCConfGetNode("security.landlock.directories.write");
    if (write_dirs) {
        if (!SCConfNodeIsSequence(write_dirs)) {
            SCLogWarning("Invalid security.landlock.directories.write configuration section: "
                         "expected a list of directory names.");
        } else {
            SCConfNode *directory;
            TAILQ_FOREACH (directory, &write_dirs->head, next) {
                SCLandlockGrantWritePath(ruleset, directory->val);
            }
        }
    }
    SCConfNode *rewrite_dirs = SCConfGetNode("security.landlock.directories.rewrite");
    if (rewrite_dirs) {
        if (!SCConfNodeIsSequence(rewrite_dirs)) {
            SCLogWarning("Invalid security.landlock.directories.rewrite configuration section: "
                         "expected a list of directory names.");
        } else {
            SCConfNode *directory;
            TAILQ_FOREACH (directory, &rewrite_dirs->head, next) {
                SCLandlockGrantRewritePath(ruleset, directory->val);
            }
        }
    }

    LandlockSandboxingApplyNetPorts(
            ruleset, "security.landlock.network.connect.tcp", SCLandlockGrantNetConnectTCP);
    LandlockSandboxingApplyNetPorts(
            ruleset, "security.landlock.network.bind.tcp", SCLandlockGrantNetBindTCP);

    /* Apply per-file grants registered by core subsystems during
     * configuration parsing (typically SC_LANDLOCK_FILE_TRUNCATE for
     * profiling outputs with "append: no"). */
    SCLandlockPendingFile *pending;
    TAILQ_FOREACH (pending, &sc_landlock_pending_files, next) {
        SCLandlockGrantFile(ruleset, pending->path, pending->access);
    }

    /* Let plugins declare their landlock needs. */
#ifdef HAVE_PLUGINS
    int enabled = 1;
    int ret = SCConfGetBool("security.landlock.plugin-setup", &enabled);
    if (ret == 0 || enabled == 1) {
        SCPluginsLandlockEnable(ruleset);
    } else {
        SCLogInfo("Landlock sandboxing function of plugins will not be called");
    }
#endif

    /* Let registered output modules declare theirs. */
    OutputModule *output_module;
    TAILQ_FOREACH (output_module, &output_modules, entries) {
        if (output_module->LandlockEnable != NULL) {
            output_module->LandlockEnable(ruleset);
        }
    }

    LandlockEnforceRuleset(ruleset);
    SCFree(ruleset);
    SCLandlockPendingFilesFree();

    SCLogInfo("Sandboxing via landlock is active");
}

#endif /* HAVE_LINUX_LANDLOCK_H */
