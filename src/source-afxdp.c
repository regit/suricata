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
 *
 *  AF_XDP capture support
 */

#define PCAP_DONT_INCLUDE_PCAP_BPF_H 1
#define SC_PCAP_DONT_INCLUDE_PCAP_H 1
#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "tm-queuehandlers.h"
#include "tmqh-packetpool.h"

#include "runmodes.h"
#include "util-error.h"
#include "util-device.h"

#include <net/if.h>
#include <linux/if_link.h>

#ifndef HAVE_AFXDP
/** Handle the case where no AFXDP support is compiled in.
 *
 */

TmEcode NoAFXDPSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveAFXDPRegister (void)
{
    tmm_modules[TMM_RECEIVEAFXDP].name = "ReceiveAFXDP";
    tmm_modules[TMM_RECEIVEAFXDP].ThreadInit = NoAFXDPSupportExit;
}

void TmModuleDecodeAFXDPRegister (void)
{
    tmm_modules[TMM_DECODEAFXDP].name = "DecodeAFXDP";
    tmm_modules[TMM_DECODEAFXDP].ThreadInit = NoAFXDPSupportExit;
}

TmEcode NoAFXDPSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_AFXDP_NOSUPPORT,"Error creating thread %s: you do not have support for AF_XDP "
           "enabled please recompile with it", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have AFXDP support */

#include "source-afxdp.h"
#include <bpf/xsk.h>

TmEcode ReceiveAFXDPThreadInit(ThreadVars *, const void *, void **);
TmEcode ReceiveAFXDPThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveAFXDPLoop(ThreadVars *, void *, void *);
void ReceiveAFXDPThreadExitStats(ThreadVars *, void *);

TmEcode DecodeAFXDPThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeAFXDPThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodeAFXDP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

static int runmode_workers;

#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE  64

enum {
    AFP_READ_OK,
    AFP_READ_FAILURE,
    /** Error during treatment by other functions of Suricata */
    AFP_SURI_FAILURE,
    AFP_KERNEL_DROP,
};

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    unsigned long rx_npkts;
    unsigned long tx_npkts;
    unsigned long prev_rx_npkts;
    unsigned long prev_tx_npkts;
    uint32_t outstanding_tx;
    uint32_t prog_id;
};

/* Structure to hold thread specific variables */
typedef struct AFXDPThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;

    struct xsk_socket_info *xsk;
    struct xsk_umem_info *xsk_umem;
    void *bufs;

    LiveDevice *livedev;
    int flags;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
} AFXDPThreadVars;

/**
 * \brief Registration function for ReceiveAFXDP
 */
void TmModuleReceiveAFXDPRegister (void)
{
    tmm_modules[TMM_RECEIVEAFXDP].name = "ReceiveAFXDP";
    tmm_modules[TMM_RECEIVEAFXDP].ThreadInit = ReceiveAFXDPThreadInit;
    tmm_modules[TMM_RECEIVEAFXDP].Func = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].PktAcqLoop = ReceiveAFXDPLoop;
    tmm_modules[TMM_RECEIVEAFXDP].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].ThreadExitPrintStats = ReceiveAFXDPThreadExitStats;
    tmm_modules[TMM_RECEIVEAFXDP].ThreadDeinit = ReceiveAFXDPThreadDeinit;
    tmm_modules[TMM_RECEIVEAFXDP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration function for DecodeAFXDP
 */
void TmModuleDecodeAFXDPRegister (void)
{
    tmm_modules[TMM_DECODEAFXDP].name = "DecodeAFXDP";
    tmm_modules[TMM_DECODEAFXDP].ThreadInit = DecodeAFXDPThreadInit;
    tmm_modules[TMM_DECODEAFXDP].Func = DecodeAFXDP;
    tmm_modules[TMM_DECODEAFXDP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEAFXDP].ThreadDeinit = DecodeAFXDPThreadDeinit;
    tmm_modules[TMM_DECODEAFXDP].RegisterTests = NULL;
    tmm_modules[TMM_DECODEAFXDP].flags = TM_FLAG_DECODE_TM;
}

static struct xsk_umem_info *XSKConfigureUmem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem) {
        SCLogError(SC_ERR_MEM_ALLOC, "AF_XDP memory allocation failed: %s (%d)",
                   strerror(errno), errno);
        return NULL;
    }

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
            NULL);
    if (ret) {
        SCLogError(SC_ERR_MEM_ALLOC,
                   "AF_XDP memory allocation failed: libbpf error %d",
                   -ret);
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

static struct xsk_socket_info *XSKConfigureSocket(const char *iface, int queue, struct xsk_umem_info *umem)
{
    struct xsk_socket_config cfg;
    struct xsk_socket_info *xsk;
    int ret;
    uint32_t idx;
    int i;

    xsk = calloc(1, sizeof(*xsk));
    if (!xsk) {
        SCLogError(SC_ERR_MEM_ALLOC, "AF_XDP memory allocation failed: %s (%d)",
                   strerror(errno), errno);
        return NULL;
    }

    xsk->umem = umem;
    cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = XDP_FLAGS_SKB_MODE|XDP_FLAGS_UPDATE_IF_NOEXIST; // FIXME opt_xdp_flags;
    cfg.bind_flags = XDP_COPY; // FIXME opt_xdp_bind_flags;
    ret = xsk_socket__create(&xsk->xsk, iface, queue, umem->umem,
            &xsk->rx, &xsk->tx, &cfg);
    if (ret) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "AF_XDP socket creation failed: libbpf error %d",
                   -ret);
        SCFree(xsk);
        return NULL;

    }

    unsigned int ifindex = if_nametoindex(iface);
    ret = bpf_get_link_xdp_id(ifindex, &xsk->prog_id, 0); // FIXME opt_xdp_flags);
    if (ret) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "AF_XDP XDP setup failed: libbpf error %d",
                   -ret);
        SCFree(xsk);
        return NULL;
    }

    ret = xsk_ring_prod__reserve(&xsk->umem->fq,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
            &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "AF_XDP XDP setup failed: libbpf error %d",
                   -ret);
        SCFree(xsk);
        return NULL;
    }
    for (i = 0;
            i < XSK_RING_PROD__DEFAULT_NUM_DESCS *
            XSK_UMEM__DEFAULT_FRAME_SIZE;
            i += XSK_UMEM__DEFAULT_FRAME_SIZE) {
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = i;
    }
    xsk_ring_prod__submit(&xsk->umem->fq,
            XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk;
}


/**
 * \brief Receives packet from a nflog group via libnetfilter_log
 * This is a setup function for recieving packets via libnetfilter_log.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the group passed from the user
 * \param data pointer gets populated with AFXDPThreadVars
 * \retvalTM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on error
 */
TmEcode ReceiveAFXDPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    AFXDPIfaceConfig *afxdpconfig = (AFXDPIfaceConfig *)initdata;
    int ret;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    AFXDPThreadVars *ntv = SCMalloc(sizeof(AFXDPThreadVars));
    if (unlikely(ntv == NULL)) {
        afxdpconfig->DerefFunc(afxdpconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ntv, 0, sizeof(AFXDPThreadVars));

    ntv->tv = tv;

    ntv->bufs = NULL;
    ret = posix_memalign(&ntv->bufs, getpagesize(), /* PAGE_SIZE aligned */
            NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE); /* FIXME num frames should be config */
    if (ret) {
        SCLogError(SC_ERR_MEM_ALLOC, "AF XDP ring allocation error");
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCLogNotice("bufs: %p", ntv->bufs);

    ntv->xsk_umem = XSKConfigureUmem(ntv->bufs,
                                     NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
    if (ntv->xsk_umem == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "AF XDP memory allocation");
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* FIXME replace 0 by RSS queue number */
    ntv->xsk = XSKConfigureSocket(afxdpconfig->iface, 0, ntv->xsk_umem);
    if (ntv->xsk == NULL) {
        SCFree(ntv->bufs);
        SCFree(ntv->xsk_umem);
        SCFree(ntv);
        SCLogError(SC_ERR_INVALID_ARGUMENT, "AF XDP socket creation");
        SCReturnInt(TM_ECODE_FAILED);
    }
#ifdef PACKET_STATISTICS
    ntv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
                                                       ntv->tv);
    ntv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
                                                     ntv->tv);
#endif

    char *active_runmode = RunmodeGetActive();
    if (active_runmode && !strcmp("workers", active_runmode))
        runmode_workers = 1;
    else
        runmode_workers = 0;

    *data = (void *)ntv;

    afxdpconfig->DerefFunc(afxdpconfig);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief DeInit function unbind group and close nflog's handle
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NFLogThreadVars
 * \retval TM_ECODE_OK is always returned
 */
TmEcode ReceiveAFXDPThreadDeinit(ThreadVars *tv, void *data)
{
    AFXDPThreadVars *ntv = (AFXDPThreadVars *)data;

    /* TODO close socket */
    SCFree(ntv->xsk_umem);
    SCFree(ntv->xsk);
    SCLogNotice("bufs: %p", ntv->bufs);
    SCFree(ntv->bufs);
    SCFree(ntv);

    SCReturnInt(TM_ECODE_OK);
}

static inline int AFXDPRead(AFXDPThreadVars *ptv, uint8_t *pdata, uint32_t plen, uint64_t addr)
{
    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnInt(AFP_SURI_FAILURE);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);
#if 0
    if (ptv->flags & AFP_XDPBYPASS) {
        p->BypassPacketsFlow = AFPXDPBypassCallback;
#ifdef HAVE_PACKET_EBPF
        p->afp_v.v4_map_fd = ptv->v4_map_fd;
        p->afp_v.v6_map_fd = ptv->v6_map_fd;
        p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
#endif
    }
#endif

    ptv->pkts++;
    p->livedev = ptv->livedev;
    p->datalink = LINKTYPE_ETHERNET;

    if (PacketSetData(p, pdata, plen) == -1) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_SURI_FAILURE);
    }

    /* TODO get timestamp from hardware */
    gettimeofday(&p->ts, NULL);

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_SURI_FAILURE);
    }

    SCReturnInt(AFP_READ_OK);
}

/**
 * \brief Recieves packets from a group via libnetfilter_log.
 *
 *  This function recieves packets from a group and passes
 *  the packet on to the nflog callback function.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFXDPThreadVars
 * \param slot slot containing task information
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode ReceiveAFXDPLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    AFXDPThreadVars *ntv = (AFXDPThreadVars *)data;
    int ret = -1;
    int rcvd, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int nfds = 1;
    struct pollfd fds[nfds + 1];
    int timeout = 1000;

    ntv->slot = ((TmSlot *) slot)->slot_next;

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(ntv->xsk->xsk);
    fds[0].events = POLLOUT;

    while (1) {
        if (suricata_ctl_flags != 0)
            break;

        ret = poll(fds, nfds, timeout);
        if (ret <= 0)
            continue;

        rcvd = xsk_ring_cons__peek(&ntv->xsk->rx, BATCH_SIZE, &idx_rx);
        if (!rcvd)
            continue;

        ret = xsk_ring_prod__reserve(&ntv->xsk->umem->fq, rcvd, &idx_fq);
        while (ret != rcvd) {
            if (ret < 0)
                SCReturnInt(-ret);
            ret = xsk_ring_prod__reserve(&ntv->xsk->umem->fq, rcvd, &idx_fq);
        }

        for (i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&ntv->xsk->rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&ntv->xsk->rx, idx_rx++)->len;
            uint8_t *pkt = xsk_umem__get_data(ntv->xsk->umem->buffer, addr);

            AFXDPRead(ntv, pkt, len, addr);
            /* FIXME to be moved if we have something else than workers and single mode
             * this return the data to the ring */
            *xsk_ring_prod__fill_addr(&ntv->xsk->umem->fq, idx_fq++) = addr;
        }

        xsk_ring_prod__submit(&ntv->xsk->umem->fq, rcvd);
        xsk_ring_cons__release(&ntv->xsk->rx, rcvd);
        ntv->xsk->rx_npkts += rcvd;

        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFXDPThreadVars
 */
void ReceiveAFXDPThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    AFXDPThreadVars *ntv = (AFXDPThreadVars *)data;

    SCLogNotice("(%s) Pkts %" PRIu32 ", Bytes %" PRIu64 "",
                 tv->name, ntv->pkts, ntv->bytes);
}


/**
 * \brief Decode IPv4/v6 packets.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into AFXDPThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 *
 * \retval TM_ECODE_OK is always returned
 */
TmEcode DecodeAFXDP(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    DecodeUpdatePacketCounters(tv, dtv, p);

    /* Assume for now we are ethernet */
    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This an Init function for DecodeAFXDP
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to initilization data.
 * \param data pointer that gets cast into AFXDPThreadVars
 * \retval TM_ECODE_OK is returned on success
 * \retval TM_ECODE_FAILED is returned on error
 */
TmEcode DecodeAFXDPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeAFXDPThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* AFXDP */
