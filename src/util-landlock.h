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

void SCLandlockGrantReadPath(void *ruleset, const char *path);
void SCLandlockGrantWritePath(void *ruleset, const char *path);

/** Grant TCP bind permission on the given port. Silently no-op when running
 *  on a kernel where landlock network support is not available. */
void SCLandlockGrantNetBindTCP(void *ruleset, uint16_t port);

/** Grant TCP connect permission on the given port. Silently no-op when
 *  running on a kernel where landlock network support is not available. */
void SCLandlockGrantNetConnectTCP(void *ruleset, uint16_t port);

void LandlockSandboxing(SCInstance *suri);

#endif /* SURICATA_UTIL_LANDLOCK_H */
