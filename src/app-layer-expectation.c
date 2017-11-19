/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#include "suricata-common.h"
#include "debug.h"

#include "ippair-storage.h"
#include "flow-storage.h"

#include "app-layer-expectation.h"

#include "util-print.h"

static int g_expectation_id = -1;
static int g_expectation_data_id = -1;

SC_ATOMIC_DECLARE(uint32_t, expectation_count);

#define EXPECTATION_TIMEOUT 30

typedef struct Expectation_ {
    struct timeval ts;
    Port sp;
    Port dp;
    AppProto alproto;
    int direction;
    void *data;
    struct Expectation_ *next;
} Expectation;

static void ExpectationListFree(void *e)
{
    Expectation *exp = (Expectation *)e;
    Expectation *lexp;
    while (exp) {
        lexp = exp->next;
        if (exp->data)
            SCFree(exp->data);
        SCFree(exp);
        exp = lexp;
    }
}

static void ExpectationDataFree(void *e)
{
    if (e)
        SCFree(e);
}

uint64_t ExpectationGetCounter(void)
{
    uint64_t x = SC_ATOMIC_GET(expectation_count);
    return x;
}

void AppLayerExpectationSetup(void)
{
    g_expectation_id = IPPairStorageRegister("expectation", sizeof(void *), NULL, ExpectationListFree);
    g_expectation_data_id = FlowStorageRegister("expectation", sizeof(void *), NULL, ExpectationDataFree);
    SC_ATOMIC_INIT(expectation_count);
}

static inline int GetFlowAddresses(Flow *f, Address *ip_src, Address *ip_dst)
{
    memset(ip_src, 0, sizeof(*ip_src));
    memset(ip_dst, 0, sizeof(*ip_dst));
    if (FLOW_IS_IPV4(f)) {
        FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, ip_src);
        FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, ip_dst);
    } else if (FLOW_IS_IPV6(f)) {
        FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, ip_src);
        FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, ip_dst);
    } else {
        return -1;
    }
    return 0;
}

static Expectation *AppLayerExpectationGet(Flow *f, int direction, IPPair **ipp)
{
    Address ip_src, ip_dst;
    if (GetFlowAddresses(f, &ip_src, &ip_dst) == -1)
        return NULL;
    *ipp = IPPairLookupIPPairFromHash(&ip_src, &ip_dst);
    if (*ipp == NULL) {
        return NULL;
    }

    return IPPairGetStorageById(*ipp, g_expectation_id);
}

int AppLayerExpectationCreate(Flow *f, int direction, Port src, Port dst, AppProto alproto, void *data)
{
    Expectation *iexp = NULL;
    IPPair *ipp;

    Expectation *exp = SCCalloc(1, sizeof(*exp));
    if (exp == NULL)
        return -1;

    exp->sp = src;
    exp->dp = dst;
    exp->alproto = alproto;
    exp->ts = f->lastts;
    exp->data = data;
    exp->direction = direction;

    iexp = AppLayerExpectationGet(f, direction, &ipp);
    if (iexp == NULL)
        goto error;
    exp->next = iexp;
    IPPairSetStorageById(ipp, g_expectation_id, exp);

    SC_ATOMIC_ADD(expectation_count, 1);
    IPPairUnlock(ipp);
    return 0;

error:
    if (exp != NULL)
        SCFree(exp);
    return -1;
}

int AppLayerExpectationGetDataId(void)
{
    return g_expectation_data_id;
}

static Expectation * RemoveExpectationAndGetNext(IPPair *ipp,
                                Expectation *pexp, Expectation *exp,
                                Expectation *lexp)
{
    (void) IPPairDecrUsecnt(ipp);
    SC_ATOMIC_SUB(expectation_count, 1);
    if (pexp == NULL) {
        IPPairSetStorageById(ipp, g_expectation_id, lexp);
    } else {
        pexp->next = lexp;
    }
    if (exp->data)
        SCFree(exp->data);
    SCFree(exp);
    return lexp;
}

AppProto AppLayerExpectationHandle(Flow *f, int direction)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    IPPair *ipp = NULL;
    Expectation *lexp = NULL;
    Expectation *pexp = NULL;

    int x = SC_ATOMIC_GET(expectation_count);
    if (x == 0) {
        return ALPROTO_UNKNOWN;
    }

    Expectation *exp = AppLayerExpectationGet(f, direction, &ipp);
    time_t ctime = f->lastts.tv_sec;

    if (exp == NULL)
        goto out;

    pexp = NULL;
    while (exp) {
        lexp = exp->next;
        if ( (exp->direction & direction) &&
             ((exp->sp == 0) || (exp->sp == f->sp)) &&
             ((exp->dp == 0) || (exp->dp == f->dp))) {
            alproto = exp->alproto;
            if (FlowSetStorageById(f, g_expectation_data_id, exp->data) != 0) {
                SCLogDebug("Unable to set flow storage");
            }
            exp->data = NULL;
            exp = RemoveExpectationAndGetNext(ipp, pexp, exp, lexp);
            continue;
        }
        /* Cleaning remove old entries */
        if (exp && (ctime > exp->ts.tv_sec + EXPECTATION_TIMEOUT)) {
            exp = RemoveExpectationAndGetNext(ipp, pexp, exp, lexp);
            continue;
        }
        pexp = exp;
        exp = lexp;
    }

out:
    if (ipp)
        IPPairRelease(ipp);
    return alproto;
}
