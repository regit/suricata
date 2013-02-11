/* Copyright (C) 2007-2012 Open Information Security Foundation
- *
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
 * \author Roliers Jean-Paul <popof.fpn@gmail.co>
 * \author Eric Leblond <eric@regit.org>
 *
 * Implements tls logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "log-tlslog-json.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"


#define DEFAULT_LOG_FILENAME "tls-json.log"

#define MODULE_NAME "LogTlsJsonLog"

#define OUTPUT_BUFFER_SIZE 65535
#define CERT_ENC_BUFFER_SIZE 2048

#define LOG_TLS_DEFAULT     0
#define LOG_TLS_EXTENDED    1


#ifndef HAVE_LIBJANSSON

TmEcode NoJanssonSupportExit(ThreadVars *, void *, void **);

void TmModuleLogTlsJsonLogRegister (void) {
    tmm_modules[TMM_LOGTLSJSONLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadInit = NoJanssonSupportExit;
    tmm_modules[TMM_LOGTLSJSONLOG].Func = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadDeinit = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].cap_flags = 0;
}
void TmModuleLogTlsJsonLogIPv4Register (void) {
    tmm_modules[TMM_LOGTLSJSONLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadInit = NoJanssonSupportExit;
    tmm_modules[TMM_LOGTLSJSONLOG].Func = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadDeinit = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].cap_flags = 0;
}
void TmModuleLogTlsJsonLogIPv6Register (void) {
    tmm_modules[TMM_LOGTLSJSONLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadInit = NoJanssonSupportExit;
    tmm_modules[TMM_LOGTLSJSONLOG].Func = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadDeinit = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].cap_flags = 0;
}
TmEcode NoJanssonSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NFQ_NOSUPPORT,"Error creating thread %s: you do not have support for jansson format "
           "enabled please recompile with --enable-jansson", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have JANSSON support */
#include <jansson.h>

static char tls_logfile_base_dir[PATH_MAX] = "/tmp";
SC_ATOMIC_DECLARE(unsigned int, cert_id);


TmEcode LogTlsJsonLog(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsJsonLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsJsonLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsJsonLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogTlsJsonLogThreadDeinit(ThreadVars *, void *);
void LogTlsJsonLogExitPrintStats(ThreadVars *, void *);
static void LogTlsJsonLogDeInitCtx(OutputCtx *);

void TmModuleLogTlsJsonLogRegister(void)
{
    tmm_modules[TMM_LOGTLSJSONLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadInit = LogTlsJsonLogThreadInit;
    tmm_modules[TMM_LOGTLSJSONLOG].Func = LogTlsJsonLog;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadExitPrintStats = LogTlsJsonLogExitPrintStats;
    tmm_modules[TMM_LOGTLSJSONLOG].ThreadDeinit = LogTlsJsonLogThreadDeinit;
    tmm_modules[TMM_LOGTLSJSONLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTLSJSONLOG].cap_flags = 0;

    /* enable the logger for the app layer */
    tmm_modules[TMM_LOGTLSJSONLOG].index = AppLayerRegisterLogger(ALPROTO_TLS);

    if(tmm_modules[TMM_LOGTLSJSONLOG].index != -1)
        OutputRegisterModule(MODULE_NAME, "tls-json-log", LogTlsJsonLogInitCtx);
    else
        SCLogError(SC_ERR_COUNTER_EXCEEDED,"Number of logger TLS exceeded");
    SC_ATOMIC_INIT(cert_id);
}

void TmModuleLogTlsJsonLogIPv4Register(void)
{
    tmm_modules[TMM_LOGTLSJSONLOG4].name = "LogTlsJsonLogIPv4";
    tmm_modules[TMM_LOGTLSJSONLOG4].ThreadInit = LogTlsJsonLogThreadInit;
    tmm_modules[TMM_LOGTLSJSONLOG4].Func = LogTlsJsonLogIPv4;
    tmm_modules[TMM_LOGTLSJSONLOG4].ThreadExitPrintStats = LogTlsJsonLogExitPrintStats;
    tmm_modules[TMM_LOGTLSJSONLOG4].ThreadDeinit = LogTlsJsonLogThreadDeinit;
    tmm_modules[TMM_LOGTLSJSONLOG4].RegisterTests = NULL;
}

void TmModuleLogTlsJsonLogIPv6Register(void)
{
    tmm_modules[TMM_LOGTLSJSONLOG6].name = "LogTlsJsonLogIPv6";
    tmm_modules[TMM_LOGTLSJSONLOG6].ThreadInit = LogTlsJsonLogThreadInit;
    tmm_modules[TMM_LOGTLSJSONLOG6].Func = LogTlsJsonLogIPv6;
    tmm_modules[TMM_LOGTLSJSONLOG6].ThreadExitPrintStats = LogTlsJsonLogExitPrintStats;
    tmm_modules[TMM_LOGTLSJSONLOG6].ThreadDeinit = LogTlsJsonLogThreadDeinit;
    tmm_modules[TMM_LOGTLSJSONLOG6].RegisterTests = NULL;
}

typedef struct LogTlsJsonFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogTlsJsonFileCtx;


typedef struct LogTlsJsonLogThread_ {
    LogTlsJsonFileCtx *tlslog_ctx;

    /** LogTlsJsonFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t tls_cnt;

    MemBuffer *buffer;
    uint8_t*   enc_buf;
    size_t     enc_buf_len;
} LogTlsJsonLogThread;

static void CreateTimeString(const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *) localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static void LogTlsJsonLogExtended(LogTlsJsonLogThread *aft, SSLState * state,json_t * json_base )
{
    json_t * json_cert = json_object();
    if (state->server_connp.cert0_fingerprint != NULL) {
        json_object_set_new(json_cert, "tls.fingerprint", json_string(state->server_connp.cert0_fingerprint));
    }
    switch (state->server_connp.version) {
        case TLS_VERSION_UNKNOWN:
            json_object_set_new(json_cert, "tls.version", json_string("UNDETERMINED"));
            break;
        case SSL_VERSION_2:
            json_object_set_new(json_cert, "tls.version", json_string("SSLv2"));
            break;
        case SSL_VERSION_3:
            json_object_set_new(json_cert, "tls.version", json_string("SSLv3"));
            break;
        case TLS_VERSION_10:
            json_object_set_new(json_cert, "tls.version", json_string("TLSv1"));
            break;
        case TLS_VERSION_11:
            json_object_set_new(json_cert, "tls.version", json_string("TLS 1.1"));
            break;
        case TLS_VERSION_12:
            json_object_set_new(json_cert, "tls.version", json_string("TLS 1.2"));
            break;
        default:
            json_object_set_new(json_cert, "tls.version", json_integer(state->server_connp.version));
            break;
    }
    json_object_set_new(json_base,"Extended",json_cert);
}

static int GetIPInformations(Packet *p, char* srcip, size_t srcip_len,
                             Port* sp, char* dstip, size_t dstip_len,
                             Port* dp, int ipproto)
{
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->sp;
        *dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->dp;
        *dp = p->sp;
    }
    return 1;
}

static TmEcode LogTlsJsonLogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq, int ipproto)
{

    SCEnter();
    LogTlsJsonLogThread *aft = (LogTlsJsonLogThread *) data;
    LogTlsJsonFileCtx *hlog = aft->tlslog_ctx;

    char timebuf[64];

    /* no flow, no tls state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have TLS state or not */
    FLOWLOCK_WRLOCK(p->flow);
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_TLS)
        goto end;

    SSLState *ssl_state = (SSLState *) AppLayerGetProtoStateFromPacket(p);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto end;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL || ssl_state->server_connp.cert0_subject == NULL)
        goto end;

    int r = AppLayerTransactionGetLoggedId(p->flow,
                                          tmm_modules[TMM_LOGTLSJSONLOG].index);

    if (r != 0) {
        goto end;
    }

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    #define PRINT_BUF_LEN 46
    char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];
    Port sp, dp;
    if (!GetIPInformations(p, srcip, PRINT_BUF_LEN,
                           &sp, dstip, PRINT_BUF_LEN, &dp, ipproto)) {
        goto end;
    }

    /* reset */
    MemBufferReset(aft->buffer);
    json_t * json_log = json_object();
    json_object_set_new(json_log, "time", json_string(timebuf));
    json_object_set_new(json_log, "source ip", json_string(srcip));
    json_object_set_new(json_log, "source port", json_integer(sp));
    json_object_set_new(json_log, "destination ip", json_string(dstip));
    json_object_set_new(json_log, "destination port", json_integer(dp));
    json_object_set_new(json_log, "TLS Subject", json_string(ssl_state->server_connp.cert0_subject));
    json_object_set_new(json_log, "TLS IssuerDN", json_string(ssl_state->server_connp.cert0_issuerdn));

    /*char * json_log_dumps =  json_dumps(json_log, JSON_INDENT(0));
    MemBufferWriteString(aft->buffer, json_log_dumps);
    SCFree(json_log_dumps);*/

    AppLayerTransactionUpdateLoggedId(p->flow,
                                      tmm_modules[TMM_LOGTLSJSONLOG].index);

    /*if (hlog->flags & LOG_TLS_EXTENDED) {
        LogTlsJsonLogExtended(aft, ssl_state);
    } else {
        MemBufferWriteString(aft->buffer, "\n");
    }*/

    if(hlog->flags & LOG_TLS_EXTENDED)
        LogTlsJsonLogExtended(aft,ssl_state, json_log);

    char * json_log_dumps =  json_dumps(json_log, JSON_INDENT(0));
    MemBufferWriteString(aft->buffer, json_log_dumps);
    MemBufferWriteString(aft->buffer, "\n");
    SCFree(json_log_dumps);

    aft->tls_cnt ++;

    SCMutexLock(&hlog->file_ctx->fp_mutex);
    MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
    fflush(hlog->file_ctx->fp);
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogTlsJsonLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogTlsJsonLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogTlsJsonLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogTlsJsonLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogTlsJsonLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        SCReturnInt(LogTlsJsonLogIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogTlsJsonLogIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogTlsJsonLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogTlsJsonLogThread *aft = SCMalloc(sizeof(LogTlsJsonLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogTlsJsonLogThread));

    if (initdata == NULL) {
        SCLogDebug( "Error getting context for TLSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->enc_buf = SCMalloc(CERT_ENC_BUFFER_SIZE);
    if (aft->enc_buf == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    aft->enc_buf_len = CERT_ENC_BUFFER_SIZE;
    memset(aft->enc_buf, 0, aft->enc_buf_len);

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->tlslog_ctx = ((OutputCtx *) initdata)->data;

    *data = (void *) aft;
    return TM_ECODE_OK;
}

TmEcode LogTlsJsonLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTlsJsonLogThread *aft = (LogTlsJsonLogThread *) data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogTlsJsonLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogTlsJsonLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogTlsJsonLogThread *aft = (LogTlsJsonLogThread *) data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("TLS logger logged %" PRIu32 " requests", aft->tls_cnt);
}

/** \brief Create a new tls log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogTlsJsonLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "LogTlsJsonLogInitCtx: Couldn't "
        "create new file_ctx");
        return NULL;
    }

    char *s_default_log_dir = NULL;
    if (ConfGet("default-log-dir", &s_default_log_dir) != 1)
        s_default_log_dir = DEFAULT_LOG_DIR;

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        goto filectx_error;
    }

    LogTlsJsonFileCtx *tlslog_ctx = SCCalloc(1, sizeof(LogTlsJsonFileCtx));
    if (unlikely(tlslog_ctx == NULL))
        goto filectx_error;
    tlslog_ctx->file_ctx = file_ctx;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    if (extended == NULL) {
        tlslog_ctx->flags |= LOG_TLS_DEFAULT;
    } else {
        if (ConfValIsTrue(extended)) {
            tlslog_ctx->flags |= LOG_TLS_EXTENDED;
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        goto tlslog_error;
    output_ctx->data = tlslog_ctx;
    output_ctx->DeInit = LogTlsJsonLogDeInitCtx;

    SCLogDebug("TLS log output initialized");

    return output_ctx;

tlslog_error:
    if (tlslog_ctx != NULL)
        SCFree(tlslog_ctx);
filectx_error:
    LogFileFreeCtx(file_ctx);
    return NULL;
}

static void LogTlsJsonLogDeInitCtx(OutputCtx *output_ctx)
{
    LogTlsJsonFileCtx *tlslog_ctx = (LogTlsJsonFileCtx *) output_ctx->data;
    LogFileFreeCtx(tlslog_ctx->file_ctx);
    SCFree(tlslog_ctx);
    SCFree(output_ctx);
}

#endif
