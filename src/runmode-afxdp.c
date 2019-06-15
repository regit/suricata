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
#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-afxdp.h"

#include "util-debug.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-misc.h"
#include "util-atomic.h"
#include "util-ebpf.h"
#include "util-ioctl.h"

#include "source-afxdp.h"

static const char *default_mode = NULL;

const char *RunModeIdsAfxdpGetDefaultMode(void)
{
    return default_mode;
}

void RunModeIdsAfxdpRegister(void)
{
    default_mode = "workers";
    RunModeRegisterNewRunMode(RUNMODE_AFXDP, "autofp",
                              "Multi threaded afxdp mode",
                              RunModeIdsAfxdpAutoFp);
    RunModeRegisterNewRunMode(RUNMODE_AFXDP, "single",
                              "Single threaded afxdp mode",
                              RunModeIdsAfxdpSingle);
    RunModeRegisterNewRunMode(RUNMODE_AFXDP, "workers",
                              "Workers afxdp mode",
                              RunModeIdsAfxdpWorkers);
    return;
}

#ifdef HAVE_AFXDP
static void AfxdpDerefConfig(void *conf)
{
    AFXDPIfaceConfig *pfp = (AFXDPIfaceConfig *)conf;
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 0) {
        SCFree(pfp);
    }
}

static void *ParseAfxdpConfig(const char *iface)
{
    ConfNode *afxdp_node;
    AFXDPIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    int boolval;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    const char *threadsstr = NULL;
    const char *ebpf_file = NULL;

    if (unlikely(aconf == NULL))
        return NULL;

    if (iface == NULL) {
        SCFree(aconf);
        return NULL;
    }


    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->DerefFunc = AfxdpDerefConfig;
    aconf->threads = 0;
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);

    /* Find initial node */
    afxdp_node = ConfGetNode("af-xdp");
    if (afxdp_node == NULL) {
        SCLogInfo("unable to find af-packet config using default values");
        goto finalize;
    }

    if_root = ConfFindDeviceConfig(afxdp_node, iface);
    if_default = ConfFindDeviceConfig(afxdp_node, "default");

    if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        aconf->threads = 0;
    } else {
        if (threadsstr != NULL) {
            if (strcmp(threadsstr, "auto") == 0) {
                aconf->threads = 0;
            } else {
                aconf->threads = atoi(threadsstr);
            }
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "xdp-filter-file", &ebpf_file) != 1) {
        aconf->xdp_filter_file = NULL;
    } else {
#ifdef HAVE_PACKET_XDP
        int conf_val = 0;
        aconf->ebpf_t_config.mode = AFP_MODE_XDP_BYPASS;
        aconf->ebpf_t_config.flags |= EBPF_XDP_CODE;
        aconf->xdp_filter_file = ebpf_file;
        ConfGetChildValueBoolWithDefault(if_root, if_default, "bypass", &conf_val);
        if (conf_val) {
            SCLogConfig("Using bypass kernel functionality for AF_PACKET (iface %s)",
                    aconf->iface);
            aconf->flags |= AFP_XDPBYPASS;
            /* if maps are pinned we need to read them at start */
            if (aconf->ebpf_t_config.flags & EBPF_PINNED_MAPS) {
                RunModeEnablesBypassManager();
                struct ebpf_timeout_config *ebt = SCCalloc(1, sizeof(struct ebpf_timeout_config));
                if (ebt == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Flow bypass alloc error");
                } else {
                    memcpy(ebt, &(aconf->ebpf_t_config), sizeof(struct ebpf_timeout_config));
                    BypassedFlowManagerRegisterCheckFunc(NULL,
                            EBPFCheckBypassedFlowCreate,
                            (void *)ebt);
                }
            }
            BypassedFlowManagerRegisterUpdateFunc(EBPFUpdateFlow, NULL);
        }
#else
        SCLogWarning(SC_ERR_UNIMPLEMENTED, "XDP filter set but XDP support is not built-in");
#endif
#ifdef HAVE_PACKET_XDP
        const char *xdp_mode;
        if (ConfGetChildValueWithDefault(if_root, if_default, "xdp-mode", &xdp_mode) != 1) {
            aconf->xdp_mode = XDP_FLAGS_SKB_MODE;
        } else {
            if (!strcmp(xdp_mode, "soft")) {
                aconf->xdp_mode = XDP_FLAGS_SKB_MODE;
            } else if (!strcmp(xdp_mode, "driver")) {
                aconf->xdp_mode = XDP_FLAGS_DRV_MODE;
            } else if (!strcmp(xdp_mode, "hw")) {
                aconf->xdp_mode = XDP_FLAGS_HW_MODE;
                aconf->ebpf_t_config.flags |= EBPF_XDP_HW_MODE;
            } else {
                SCLogWarning(SC_ERR_INVALID_VALUE,
                             "Invalid xdp-mode value: '%s'", xdp_mode);
            }
        }

        boolval = true;
        if (ConfGetChildValueBoolWithDefault(if_root, if_default, "use-percpu-hash", (int *)&boolval) == 1) {
            if (boolval == false) {
                SCLogConfig("Not using percpu hash on iface %s",
                        aconf->iface);
                aconf->ebpf_t_config.cpus_count = 1;
            }
        }
#endif
    }

    /* One shot loading of the eBPF file */
    if (aconf->xdp_filter_file) {
#ifdef HAVE_PACKET_XDP
        int ret = EBPFLoadFile(aconf->iface, aconf->xdp_filter_file, "xdp",
                               &aconf->xdp_filter_fd,
                               &aconf->ebpf_t_config);
        switch (ret) {
            case 1:
                SCLogInfo("Loaded pinned maps from sysfs");
                break;
            case -1:
                SCLogWarning(SC_ERR_INVALID_VALUE,
                             "Error when loading XDP filter file");
                break;
            case 0:
                ret = EBPFSetupXDP(aconf->iface, aconf->xdp_filter_fd, aconf->xdp_mode);
                if (ret != 0) {
                    SCLogWarning(SC_ERR_INVALID_VALUE,
                            "Error when setting up XDP");
                } else {
                    /* Try to get the xdp-cpu-redirect key */
                    const char *cpuset;
                    if (ConfGetChildValueWithDefault(if_root, if_default,
                                "xdp-cpu-redirect", &cpuset) == 1) {
                        SCLogConfig("Setting up CPU map XDP");
                        ConfNode *node = ConfGetChildWithDefault(if_root, if_default, "xdp-cpu-redirect");
                        if (node == NULL) {
                            SCLogError(SC_ERR_INVALID_VALUE,
                                       "Previously found node has disappeared");
                        } else {
                            EBPFBuildCPUSet(node, aconf->iface);
                        }
                    } else {
                        /* It will just set CPU count to 0 */
                        EBPFBuildCPUSet(NULL, aconf->iface);
                    }
                }
        }
#else
        SCLogError(SC_ERR_UNIMPLEMENTED, "XDP support is not built-in");
#endif
    }


finalize:
    /* if the number of threads is not 1, we need to first check if fanout
     * functions on this system. */
    if (aconf->threads != 1) {
        if (AFPIsFanoutSupported() == 0) {
            if (aconf->threads != 0) {
                SCLogNotice("fanout not supported on this system, falling "
                        "back to 1 capture thread");
            }
            aconf->threads = 1;
        }
    }
    /* try to automagically set the proper number of threads */
    if (aconf->threads == 0) {
        int rss_queues = GetIfaceRSSQueuesNum(iface);
        if (rss_queues > 0) {
            aconf->threads = rss_queues;
            SCLogPerf("%d RSS queues, so using %u threads", rss_queues, aconf->threads);
        }

        if (aconf->threads) {
            SCLogPerf("Using %d AF_PACKET threads for interface %s",
                    aconf->threads, iface);
        }
    }
    if (aconf->threads <= 0) {
        aconf->threads = 1;
    }
    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    int ltype = AFPGetLinkType(iface);
    switch (ltype) {
        case LINKTYPE_ETHERNET:
            /* af-packet can handle csum offloading */
            if (LiveGetOffload() == 0) {
                if (GetIfaceOffloading(iface, 0, 1) == 1) {
                    SCLogWarning(SC_ERR_AFP_CREATE,
                            "Using AF_PACKET with offloading activated leads to capture problems");
                }
            } else {
                DisableIfaceOffloading(LiveGetDevice(iface), 0, 1);
            }
            break;
        case -1:
        default:
            break;
    }

    char *active_runmode = RunmodeGetActive();
    if (active_runmode && !strcmp("workers", active_runmode)) {
        aconf->flags |= AFP_ZERO_COPY;
    } else {
        /* If we are using copy mode we need a lock */
        aconf->flags |= AFP_SOCK_PROTECT;
    }

    /* If we are in RING mode, then we can use ZERO copy
     * by using the data release mechanism */
    if (aconf->flags & AFP_RING_MODE) {
        aconf->flags |= AFP_ZERO_COPY;
    }

    if (aconf->flags & AFP_ZERO_COPY) {
        SCLogConfig("%s: enabling zero copy mode by using data release call", iface);
    }

    return aconf;
}

static int AfxdpConfigGeThreadsCount(void *conf)
{
    AFXDPIfaceConfig *afp = (AFXDPIfaceConfig *)conf;
    return afp->threads;
}
#endif

int RunModeIdsAfxdpAutoFp(void)
{
    SCEnter();

#ifdef HAVE_AFXDP
    int ret = 0;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    ret = RunModeSetLiveCaptureAutoFp(ParseAfxdpConfig,
                                      AfxdpConfigGeThreadsCount,
                                      "ReceiveAFXDP",
                                      "DecodeAFXDP",
                                      thread_name_autofp,
                                      live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsAfxdpAutoFp initialised");
#endif /* HAVE_AFXDP */

    SCReturnInt(0);
}

int RunModeIdsAfxdpSingle(void)
{
    SCEnter();

#ifdef HAVE_AFXDP
    int ret = 0;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    ret = RunModeSetLiveCaptureSingle(ParseAfxdpConfig,
                                      AfxdpConfigGeThreadsCount,
                                      "ReceiveAFXDP",
                                      "DecodeAFXDP",
                                      thread_name_single,
                                      live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsAfxdpSingle initialised");
#endif /* HAVE_AFXDP */

    SCReturnInt(0);
}

int RunModeIdsAfxdpWorkers(void)
{
    SCEnter();

#ifdef HAVE_AFXDP
    int ret = 0;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    ret = RunModeSetLiveCaptureWorkers(ParseAfxdpConfig,
                                       AfxdpConfigGeThreadsCount,
                                       "ReceiveAFXDP",
                                       "DecodeAFXDP",
                                       thread_name_workers,
                                       live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsAfxdpWorkers initialised");
#endif /* HAVE_AFXDP */

    SCReturnInt(0);
}
