/* Copyright (C) 2022-2026 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_LANDLOCK_H
#define SURICATA_UTIL_LANDLOCK_H

#include "suricata.h"

/** Callback signature for plugins, output modules and EVE filetypes that
 *  need to declare additional landlock permissions before the sandbox is
 *  enforced. Implementations must only use the SCLandlockGrant* helpers. */
typedef void (*SCLandlockEnableFunc)(void *ruleset);

/** Callback invoked by SCLandlockForEachOutput() for one output instance.
 *  \a conf is the node named after the output (e.g. the "eve-log" node), not
 *  the enclosing sequence entry. */
typedef void (*SCLandlockOutputFunc)(void *ruleset, SCConfNode *conf);

/** Run \a cb for every enabled instance of the \a name output.
 *
 *  "outputs" is a YAML sequence, so an output lives at outputs.<n>.<name>
 *  and a direct SCConfGetNode("outputs.<name>") never matches -- a mistake
 *  that silently disables a module's whole landlock declaration. Every
 *  LandlockEnable implementation should go through this helper rather than
 *  walking the sequence itself.
 *
 *  Instances whose "enabled" key is absent or not true are skipped, so \a cb
 *  only ever sees outputs that will actually run. */
void SCLandlockForEachOutput(void *ruleset, const char *name, SCLandlockOutputFunc cb);

void SCLandlockGrantReadPath(void *ruleset, const char *path);
void SCLandlockGrantWritePath(void *ruleset, const char *path);

/** Same as SCLandlockGrantWritePath but also grants
 *  LANDLOCK_ACCESS_FS_REFER on the directory, enabling rename() between
 *  subdirectories rooted at this path. Intended for modules such as
 *  file-store that need to move files from a staging directory into the
 *  final tree. Should be used only on directories fully owned by the
 *  caller. */
void SCLandlockGrantWriteReferPath(void *ruleset, const char *path);

/** Per-file access flags for SCLandlockGrantFile(). Combine as needed. */
#define SC_LANDLOCK_FILE_READ     (1U << 0)
#define SC_LANDLOCK_FILE_WRITE    (1U << 1)
#define SC_LANDLOCK_FILE_TRUNCATE (1U << 2)

/** Grant a minimal per-file landlock rule (read/write/truncate).
 *
 *  The target file is created (0644, O_NOFOLLOW) if missing when a write
 *  flag is requested, so landlock can attach the rule to a real inode.
 *  Intended for use from plugins, output modules and core subsystems that
 *  need per-file access -- notably truncate-on-open (mode "w") on a single
 *  file without opening truncate up on the whole parent directory. No-op
 *  when landlock is not compiled in or the running kernel does not support
 *  it. */
void SCLandlockGrantFile(void *ruleset, const char *path, uint32_t access);

/** Register a per-file landlock grant to be applied when the sandbox is
 *  set up. Intended for callers that resolve their file paths at
 *  configuration-parse time -- before the landlock ruleset exists.
 *
 *  \a path is duplicated internally. \a access uses the SC_LANDLOCK_FILE_*
 *  flags. The pending entry is consumed by LandlockSandboxing(), which
 *  calls SCLandlockGrantFile() for each registration. Safe to call
 *  regardless of whether landlock is enabled at runtime -- unused
 *  registrations are freed at the end of LandlockSandboxing(). */
void SCLandlockRegisterFile(const char *path, uint32_t access);

/** Grant TCP bind permission on the given port. Silently no-op when running
 *  on a kernel where landlock network support is not available. */
void SCLandlockGrantNetBindTCP(void *ruleset, uint16_t port);

/** Grant TCP connect permission on the given port. Silently no-op when
 *  running on a kernel where landlock network support is not available. */
void SCLandlockGrantNetConnectTCP(void *ruleset, uint16_t port);

void LandlockSandboxing(SCInstance *suri);

#endif /* SURICATA_UTIL_LANDLOCK_H */
