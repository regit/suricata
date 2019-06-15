/* Copyright (C) 2019 Open Information Security Foundation
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

#ifndef __SOURCE_AFXDP_H__
#define __SOURCE_AFXDP_H__

#define AFP_IFACE_NAME_LENGTH 48

typedef struct AFXDPIfaceConfig_
{
    char iface[AFP_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;
    const char *xdp_filter_file;
    int xdp_filter_fd;
    uint8_t xdp_mode;
    /* misc use flags including ring mode */
    unsigned int flags;

#ifdef HAVE_PACKET_EBPF
    struct ebpf_timeout_config ebpf_t_config;
#endif
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} AFXDPIfaceConfig;

typedef struct AFXDPPacketVars_
{
    int v4_map_fd;
    int v6_map_fd;
    unsigned int nr_cpus;
} AFXDPPacketVars;

void TmModuleReceiveAFXDPRegister(void);
void TmModuleDecodeAFXDPRegister(void);

#endif /* __SOURCE_AFXDP_H__ */
