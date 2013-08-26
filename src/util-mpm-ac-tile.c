/* Copyright (C) 2013 Open Information Security Foundation
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
 * \author Ken Steele <suricata@tilera.com>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 *         Aho-corasick MPM optimized for the Tilera Tile-Gx architecture.
 *
 *         Efficient String Matching: An Aid to Bibliographic Search
 *         Alfred V. Aho and Margaret J. Corasick
 *
 *         - Started with util-mpm-ac.c:
 *             - Uses the delta table for calculating transitions,
 *               instead of having separate goto and failure
 *               transitions.
 *             - If we cross 2 ** 16 states, we use 4 bytes in the
 *               transition table to hold each state, otherwise we use
 *               2 bytes.
 *             - This version of the MPM is heavy on memory, but it
 *               performs well.  If you can fit the ruleset with this
 *               mpm on your box without hitting swap, this is the MPM
 *               to go for.
 *
 *         - Added these optimizations:
 *             - Compress the input alphabet from 256 characters down
 *               to the actual characters used in the patterns, plus
 *               one character for all the unused characters.
 *             - Reduce the size of the delta table so that each state
 *               is the smallest power of two that is larger than the
 *               size of the compressed alphabet.
 *             - Specialized the search function based on state count
 *               (small for 8-bit large for 16-bit) and the size of
 *               the alphabet, so that it is constant inside the
 *               function for better optimization.
 *
 * \todo - Do a proper analyis of our existing MPMs and suggest a good
 *         one based on the pattern distribution and the expected
 *         traffic(say http).

 *       - Tried out loop unrolling without any perf increase.  Need to dig
 *         deeper.
 *       - Irrespective of whether we cross 2 ** 16 states or
 *         not,shift to using uint32_t for state type, so that we can
 *         integrate it's status as a final state or not in the
 *         topmost byte.  We are already doing it if state_count is >
 *         2 ** 16.
 *       - Test case-senstive patterns if they have any ascii chars.
 *         If they don't treat them as nocase.
 *       - Carry out other optimizations we are working on: hashes.
 *       - Reorder the compressed alphabet to put the most common characters
 *           first.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"

#include "conf.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-memcmp.h"
#include "util-mpm-ac-tile.h"

/* There are Tilera Tile-Gx specific optimizations in this code. */
#ifdef __tile__

void SCACTileInitCtx(MpmCtx *);
void SCACTileInitThreadCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void SCACTileDestroyCtx(MpmCtx *);
void SCACTileDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCACTileAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                         uint32_t, uint32_t, uint8_t);
int SCACTileAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                         uint32_t, uint32_t, uint8_t);
int SCACTilePreparePatterns(MpmCtx *mpm_ctx);
uint32_t SCACTileSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *pmq, uint8_t *buf, 
                        uint16_t buflen);
void SCACTilePrintInfo(MpmCtx *mpm_ctx);
void SCACTilePrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void SCACTileRegisterTests(void);

uint32_t SCACTileSearchLarge(SCACTileCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                             PatternMatcherQueue *pmq, 
                             uint8_t *buf, uint16_t buflen);
uint32_t SCACTileSearchSmall256(SCACTileCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                                PatternMatcherQueue *pmq, 
                                uint8_t *buf, uint16_t buflen);
uint32_t SCACTileSearchSmall128(SCACTileCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                                PatternMatcherQueue *pmq, 
                                uint8_t *buf, uint16_t buflen);
uint32_t SCACTileSearchSmall64(SCACTileCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PatternMatcherQueue *pmq, 
                               uint8_t *buf, uint16_t buflen);
uint32_t SCACTileSearchSmall32(SCACTileCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PatternMatcherQueue *pmq, 
                               uint8_t *buf, uint16_t buflen);
uint32_t SCACTileSearchSmall16(SCACTileCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PatternMatcherQueue *pmq, 
                               uint8_t *buf, uint16_t buflen);


/* a placeholder to denote a failure transition in the goto table */
#define SC_AC_TILE_FAIL (-1)
/* size of the hash table used to speed up pattern insertions initially */
#define INIT_HASH_SIZE 65536

#define STATE_QUEUE_CONTAINER_SIZE 65536

/**
 * \brief Helper structure used by AC during state table creation
 */
typedef struct StateQueue_ {
    int32_t store[STATE_QUEUE_CONTAINER_SIZE];
    int top;
    int bot;
} StateQueue;

/**
 * \internal
 * \brief Initialize the AC context with user specified conf parameters.  We
 *        aren't retrieving anything for AC conf now, but we will certainly
 *        need it, when we customize AC.
 */
static void SCACTileGetConfig()
{
    return;
}

/**
 * \internal
 * \brief Compares 2 patterns.  We use it for the hashing process during the
 *        the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param p      Pointer to the first pattern(SCACTilePattern).
 * \param pat    Pointer to the second pattern(raw pattern array).
 * \param patlen Pattern length.
 * \param flags  Flags.  We don't need this.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline int SCACTileCmpPattern(SCACTilePattern *p, uint8_t *pat, 
                                     uint16_t patlen, char flags)
{
    if (p->len != patlen)
        return 0;

    if (p->flags != flags)
        return 0;

    if (memcmp(p->cs, pat, patlen) != 0)
        return 0;

    return 1;
}

/**
 * \internal
 * \brief Creates a hash of the pattern.  We use it for the hashing process
 *        during the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline uint32_t SCACTileInitHashRaw(uint8_t *pat, uint16_t patlen)
{
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % INIT_HASH_SIZE);
}

/**
 * \internal
 * \brief Looks up a pattern.  We use it for the hashing process during the
 *        the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param ctx    Pointer to the AC ctx.
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 * \param flags  Flags.  We don't need this.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline SCACTilePattern *SCACTileInitHashLookup(SCACTileCtx *ctx, 
                                                      uint8_t *pat,
                                                      uint16_t patlen, 
                                                      char flags,
                                                      uint32_t pid)
{
    uint32_t hash = SCACTileInitHashRaw(pat, patlen);

    if (ctx->init_hash == NULL || ctx->init_hash[hash] == NULL) {
        return NULL;
    }

    SCACTilePattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        //if (SCACTileCmpPattern(t, pat, patlen, flags) == 1)
        if (t->flags == flags && t->id == pid)
            return t;
    }

    return NULL;
}

/**
 * \internal
 * \brief Allocs a new pattern instance.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval p Pointer to the newly created pattern.
 */
static inline SCACTilePattern *SCACTileAllocPattern(MpmCtx *mpm_ctx)
{
    SCACTilePattern *p = SCMalloc(sizeof(SCACTilePattern));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(SCACTilePattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACTilePattern);

    return p;
}

/**
 * \internal
 * \brief Used to free SCACTilePattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the SCACTilePattern instance to be freed.
 * \param free    Free the above pointer or not.
 */
static inline void SCACTileFreePattern(MpmCtx *mpm_ctx, SCACTilePattern *p)
{
    if (p != NULL && p->cs != NULL && p->cs != p->ci) {
        SCFree(p->cs);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->ci != NULL) {
        SCFree(p->ci);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->original_pat != NULL) {
        SCFree(p->original_pat);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL) {
        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(SCACTilePattern);
    }
    return;
}

/**
 * \internal
 * \brief Does a memcpy of the input string to lowercase.
 *
 * \param d   Pointer to the target area for memcpy.
 * \param s   Pointer to the src string for memcpy.
 * \param len len of the string sent in s.
 */
static inline void memcpy_tolower(uint8_t *d, uint8_t *s, uint16_t len)
{
    uint16_t i;
    for (i = 0; i < len; i++)
        d[i] = u8_tolower(s[i]);

    return;
}

static inline uint32_t SCACTileInitHash(SCACTilePattern *p)
{
    uint32_t hash = p->len * p->original_pat[0];
    if (p->len > 1)
        hash += p->original_pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int SCACTileInitHashAdd(SCACTileCtx *ctx, SCACTilePattern *p)
{
    uint32_t hash = SCACTileInitHash(p);

    if (ctx->init_hash == NULL) {
        return 0;
    }

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    SCACTilePattern *tt = NULL;
    SCACTilePattern *t = ctx->init_hash[hash];

    /* get the list tail */
    do {
        tt = t;
        t = t->next;
    } while (t != NULL);

    tt->next = p;

    return 0;
}


/**
 * \internal
 * \brief Count the occurences of each character in the pattern and
 * accumulate into a histogram. Really only used to detect unused
 * characters, so could just set to 1 instead of counting.
 */
static inline void SCACTileHistogramAlphabet(SCACTileCtx *ctx, 
                                             SCACTilePattern *p)
{
    for (int i = 0; i < p->len; i++) {
        ctx->alpha_hist[p->ci[i]]++;
    }
}

/* Use Alpahbet Histogram to create compressed alphabet.
 */
static inline void SCACTileInitTranslateTable(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;

    /* Count the number of ASCII values actually appearing in any
     * pattern.  Create compressed mapping table with unused
     * characters mapping to zero.
     */
    for (int i = 0; i < 256; i++) {
        /* Move all upper case counts to lower case */
        if (i >= 'A' && i <= 'Z') {
            ctx->alpha_hist[i - 'A' + 'a'] += ctx->alpha_hist[i];
            ctx->alpha_hist[i] = 0;
        }
        if (ctx->alpha_hist[i]) {
            ctx->alphabet_size++;
            ctx->translate_table[i] = ctx->alphabet_size;
        } else 
            ctx->translate_table[i] = 0;
    }
    /* Fix up translation table for uppercase */
    for (int i = 'A'; i <= 'Z'; i++)
        ctx->translate_table[i] = ctx->translate_table[i - 'A' + 'a'];

    SCLogDebug("  Alphabet size %d", ctx->alphabet_size);

    /* Round alphabet size up to next power-of-two and translate
     * Uppercase to lowercase. Leave one extra space For the
     * unused-chararacters = 0 mapping. */
    if (ctx->alphabet_size + 1 <= 16) {
        ctx->alphabet_size = 16;
    } else if (ctx->alphabet_size + 1 <= 64) {
        ctx->alphabet_size = 64;
    } else if (ctx->alphabet_size + 1 <= 128) {
        ctx->alphabet_size = 128;
    } else 
        ctx->alphabet_size = 256;
}

/**
 * \internal
 * \brief Add a pattern to the mpm-ac context.
 *
 * \param mpm_ctx Mpm context.
 * \param pat     Pointer to the pattern.
 * \param patlen  Length of the pattern.
 * \param pid     Pattern id
 * \param sid     Signature id (internal id).
 * \param flags   Pattern's MPM_PATTERN_* flags.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SCACTileAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                              uint16_t offset, uint16_t depth, uint32_t pid,
                              uint32_t sid, uint8_t flags)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;

    SCLogDebug("Adding pattern for ctx %p, patlen %"PRIu16" and pid %" PRIu32,
               ctx, patlen, pid);

    if (patlen == 0) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "pattern length 0");
        return 0;
    }

    /* check if we have already inserted this pattern */
    SCACTilePattern *p = SCACTileInitHashLookup(ctx, pat, patlen, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = SCACTileAllocPattern(mpm_ctx);

        p->len = patlen;
        p->flags = flags;
        p->id = pid;

        p->original_pat = SCMalloc(patlen);
        if (p->original_pat == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy(p->original_pat, pat, patlen);

        p->ci = SCMalloc(patlen);
        if (p->ci == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        /* setup the case sensitive part of the pattern */
        if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
            /* nocase means no difference between cs and ci */
            p->cs = p->ci;
        } else {
            if (memcmp(p->ci, pat, p->len) == 0) {
                /* no diff between cs and ci: pat is lowercase */
                p->cs = p->ci;
            } else {
                p->cs = SCMalloc(patlen);
                if (p->cs == NULL)
                    goto error;
                mpm_ctx->memory_cnt++;
                mpm_ctx->memory_size += patlen;
                memcpy(p->cs, pat, patlen);
            }
        }

        /* put in the pattern hash */
        SCACTileInitHashAdd(ctx, p);
        /* Count alphabet usages */
        SCACTileHistogramAlphabet(ctx, p);

        //if (mpm_ctx->pattern_cnt == 65535) {
        //    SCLogError(SC_ERR_AHO_CORASICK, "Max search words reached.  Can't "
        //               "insert anymore.  Exiting");
        //    exit(EXIT_FAILURE);
        //}
        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->maxlen < patlen)
            mpm_ctx->maxlen = patlen;

        if (mpm_ctx->minlen == 0) {
            mpm_ctx->minlen = patlen;
        } else {
            if (mpm_ctx->minlen > patlen)
                mpm_ctx->minlen = patlen;
        }

        /* we need the max pat id */
        if (pid > ctx->max_pat_id)
            ctx->max_pat_id = pid;
    }

    return 0;

error:
    SCACTileFreePattern(mpm_ctx, p);
    return -1;
}

/**
 * \internal
 * \brief Initialize a new state in the goto and output tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval The state id, of the newly created state.
 */
static inline int SCACTileInitNewState(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    int aa = 0;
    int size = 0;

    /* reallocate space in the goto table to include a new state */
    size = (ctx->state_count + 1) * sizeof(int32_t) * 256;
    ctx->goto_table = SCRealloc(ctx->goto_table, size);
    if (ctx->goto_table == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    /* set all transitions for the newly assigned state as FAIL transitions */
    for (aa = 0; aa < ctx->alphabet_size; aa++) {
        ctx->goto_table[ctx->state_count][aa] = SC_AC_TILE_FAIL;
    }

    /* reallocate space in the output table for the new state */
    size = (ctx->state_count + 1) * sizeof(SCACTileOutputTable);
    ctx->output_table = SCRealloc(ctx->output_table, size);
    if (ctx->output_table == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->output_table + ctx->state_count, 0, 
           sizeof(SCACTileOutputTable));

    return ctx->state_count++;
}

/**
 * \internal
 * \brief Adds a pid to the output table for a state.
 *
 * \param state   The state to whose output table we should add the pid.
 * \param pid     The pattern id to add.
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACTileSetOutputState(int32_t state, uint32_t pid, MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    SCACTileOutputTable *output_state = &ctx->output_table[state];
    uint32_t i = 0;

    for (i = 0; i < output_state->no_of_entries; i++) {
        if (output_state->pids[i] == pid)
            return;
    }

    output_state->no_of_entries++;
    output_state->pids = SCRealloc(output_state->pids,
                                   output_state->no_of_entries * sizeof(uint32_t));
    if (output_state->pids == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    output_state->pids[output_state->no_of_entries - 1] = pid;

    return;
}

/**
 * \brief Helper function used by SCACTileCreateGotoTable.  Adds a
 *        pattern to the goto table.
 *
 * \param pattern     Pointer to the pattern.
 * \param pattern_len Pattern length.
 * \param pid         The pattern id, that corresponds to this pattern.  We
 *                    need it to updated the output table for this pattern.
 * \param mpm_ctx     Pointer to the mpm context.
 */
static inline void SCACTileEnter(uint8_t *pattern, uint16_t pattern_len, 
                                 uint32_t pid, MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    int32_t state = 0;
    int32_t newstate = 0;
    int i = 0;
    int p = 0;
    int tc;

    /* walk down the trie till we have a match for the pattern prefix */
    state = 0;
    for (i = 0; i < pattern_len; i++) {
        tc = ctx->translate_table[pattern[i]];
        if (ctx->goto_table[state][tc] != SC_AC_TILE_FAIL) {
            state = ctx->goto_table[state][tc];
        } else {
            break;
        }
    }

    /* add the non-matching pattern suffix to the trie, from the last state
     * we left off */
    for (p = i; p < pattern_len; p++) {
        newstate = SCACTileInitNewState(mpm_ctx);
        tc = ctx->translate_table[pattern[p]];
        ctx->goto_table[state][tc] = newstate;
        state = newstate;
    }

    /* add this pattern id, to the output table of the last state, where the
     * pattern ends in the trie */
    SCACTileSetOutputState(state, pid, mpm_ctx);

    return;
}

/**
 * \internal
 * \brief Create the goto table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACTileCreateGotoTable(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    uint32_t i = 0;

    /* add each pattern to create the goto table */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        SCACTileEnter(ctx->parray[i]->ci, ctx->parray[i]->len,
                      ctx->parray[i]->id, mpm_ctx);
    }

    int aa = 0;
    for (aa = 0; aa < ctx->alphabet_size; aa++) {
        if (ctx->goto_table[0][aa] == SC_AC_TILE_FAIL) {
            ctx->goto_table[0][aa] = 0;
        }
    }

    return;
}

static inline int SCACTileStateQueueIsEmpty(StateQueue *q)
{
    if (q->top == q->bot)
        return 1;
    else
        return 0;
}

static inline void SCACTileEnqueue(StateQueue *q, int32_t state)
{
    int i = 0;

    /*if we already have this */
    for (i = q->bot; i < q->top; i++) {
        if (q->store[i] == state)
            return;
    }

    q->store[q->top++] = state;

    if (q->top == STATE_QUEUE_CONTAINER_SIZE)
        q->top = 0;

    if (q->top == q->bot) {
        SCLogCritical(SC_ERR_AHO_CORASICK, "Just ran out of space in the queue.  "
                      "Fatal Error.  Exiting.  Please file a bug report on this");
        exit(EXIT_FAILURE);
    }

    return;
}

static inline int32_t SCACTileDequeue(StateQueue *q)
{
    if (q->bot == STATE_QUEUE_CONTAINER_SIZE)
        q->bot = 0;

    if (q->bot == q->top) {
        SCLogCritical(SC_ERR_AHO_CORASICK, "StateQueue behaving weirdly.  "
                      "Fatal Error.  Exiting.  Please file a bug report on this");
        exit(EXIT_FAILURE);
    }

    return q->store[q->bot++];
}

/**
 * \internal
 * \brief Club the output data from 2 states and store it in the 1st state.
 *        dst_state_data = {dst_state_data} UNION {src_state_data}
 *
 * \param dst_state First state(also the destination) for the union operation.
 * \param src_state Second state for the union operation.
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACTileClubOutputStates(int32_t dst_state, int32_t src_state,
                                            MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    uint32_t i = 0;
    uint32_t j = 0;

    SCACTileOutputTable *output_dst_state = &ctx->output_table[dst_state];
    SCACTileOutputTable *output_src_state = &ctx->output_table[src_state];

    for (i = 0; i < output_src_state->no_of_entries; i++) {
        for (j = 0; j < output_dst_state->no_of_entries; j++) {
            if (output_src_state->pids[i] == output_dst_state->pids[j]) {
                break;
            }
        }
        if (j == output_dst_state->no_of_entries) {
            output_dst_state->no_of_entries++;

            output_dst_state->pids = SCRealloc(output_dst_state->pids,
                                               (output_dst_state->no_of_entries *
                                                sizeof(uint32_t)) );
            if (output_dst_state->pids == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }

            output_dst_state->pids[output_dst_state->no_of_entries - 1] =
                output_src_state->pids[i];
        }
    }

    return;
}

/**
 * \internal
 * \brief Create the failure table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACTileCreateFailureTable(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    int aa = 0;
    int32_t state = 0;
    int32_t r_state = 0;

    StateQueue q;
    memset(&q, 0, sizeof(StateQueue));

    /* Allocate space for the failure table.  A failure entry in the table for
     * every state(SCACTileCtx->state_count) */
    ctx->failure_table = SCMalloc(ctx->state_count * sizeof(int32_t));
    if (ctx->failure_table == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->failure_table, 0, ctx->state_count * sizeof(int32_t));

    /* Add the failure transitions for the 0th state, and add every non-fail
     * transition from the 0th state to the queue for further processing
     * of failure states */
    for (aa = 0; aa < ctx->alphabet_size; aa++) {
        int32_t temp_state = ctx->goto_table[0][aa];
        if (temp_state != 0) {
            SCACTileEnqueue(&q, temp_state);
            ctx->failure_table[temp_state] = 0;
        }
    }

    while (!SCACTileStateQueueIsEmpty(&q)) {
        /* pick up every state from the queue and add failure transitions */
        r_state = SCACTileDequeue(&q);
        for (aa = 0; aa < ctx->alphabet_size; aa++) {
            int32_t temp_state = ctx->goto_table[r_state][aa];
            if (temp_state == SC_AC_TILE_FAIL)
                continue;
            SCACTileEnqueue(&q, temp_state);
            state = ctx->failure_table[r_state];

            while(ctx->goto_table[state][aa] == SC_AC_TILE_FAIL)
                state = ctx->failure_table[state];
            ctx->failure_table[temp_state] = ctx->goto_table[state][aa];
            SCACTileClubOutputStates(temp_state, ctx->failure_table[temp_state],
                                     mpm_ctx);
        }
    }

    return;
}

#define NEXT_STATE(table,x,y) ((table) + (x) * ctx->alphabet_size + (y))
/**
 * \internal
 * \brief Create the delta table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACTileCreateDeltaTable(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    int aa = 0;
    int32_t r_state = 0;

    if (ctx->state_count < 32767) {
        int alpha_size = ctx->alphabet_size;
        switch(alpha_size) {
        case 16:
                ctx->search = SCACTileSearchSmall16;
                break;
        case 32:
                ctx->search = SCACTileSearchSmall32;
                break;
        case 64:
                ctx->search = SCACTileSearchSmall64;
                break;
        case 128:
                ctx->search = SCACTileSearchSmall128;
                break;
        default:
                ctx->search = SCACTileSearchSmall256;
        }
        int size = ctx->state_count * sizeof(SC_AC_TILE_STATE_TYPE_U16) * alpha_size;
        SC_AC_TILE_STATE_TYPE_U16 *state_table = SCMalloc(size);
        if (state_table == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(state_table, 0, size);
        ctx->state_table_u16 = state_table;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += size;

        SCLogInfo("Delta Table size %d,  16-bit states: %d", 
                  size, ctx->state_count);

        StateQueue q;
        memset(&q, 0, sizeof(StateQueue));

        for (aa = 0; aa < ctx->alphabet_size; aa++) {
            SC_AC_TILE_STATE_TYPE_U16 temp_state = ctx->goto_table[0][aa];
            *NEXT_STATE(state_table, 0, aa) = temp_state;
            if (temp_state != 0)
                SCACTileEnqueue(&q, temp_state);
        }

        while (!SCACTileStateQueueIsEmpty(&q)) {
            r_state = SCACTileDequeue(&q);

            for (aa = 0; aa < alpha_size; aa++) {
                int32_t temp_state = ctx->goto_table[r_state][aa];
                if (temp_state != SC_AC_TILE_FAIL) {
                    SCACTileEnqueue(&q, temp_state);
                    *NEXT_STATE(state_table, r_state, aa) = temp_state;
                } else {
                    uint16_t f_state = ctx->failure_table[r_state];
                    *NEXT_STATE(state_table, r_state, aa) =
                        *NEXT_STATE(state_table, f_state, aa);
                }
            }
        }
    } else {
        /* create space for the state table.  We could have used the existing goto
         * table, but since we have it set to hold 32 bit state values, we will create
         * a new state table here of type SC_AC_TILE_STATE_TYPE(current set to uint16_t) */
        ctx->search = SCACTileSearchLarge;
        int size = ctx->state_count * sizeof(SC_AC_TILE_STATE_TYPE_U32) * 256;
        ctx->state_table_u32 = SCMalloc(size);
        if (ctx->state_table_u32 == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->state_table_u32, 0, size);

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += size;

        SCLogInfo("Delta Table size %u, 32-bit states: %u", size, ctx->state_count);

        StateQueue q;
        memset(&q, 0, sizeof(StateQueue));

        for (aa = 0; aa < ctx->alphabet_size; aa++) {
            SC_AC_TILE_STATE_TYPE_U32 temp_state = ctx->goto_table[0][aa];
            ctx->state_table_u32[0][aa] = temp_state;
            if (temp_state != 0)
                SCACTileEnqueue(&q, temp_state);
        }

        while (!SCACTileStateQueueIsEmpty(&q)) {
            r_state = SCACTileDequeue(&q);

            for (aa = 0; aa < ctx->alphabet_size; aa++) {
                int32_t temp_state = ctx->goto_table[r_state][aa];
                if (temp_state != SC_AC_TILE_FAIL) {
                    SCACTileEnqueue(&q, temp_state);
                    ctx->state_table_u32[r_state][aa] = temp_state;
                } else {
                    ctx->state_table_u32[r_state][aa] =
                        ctx->state_table_u32[ctx->failure_table[r_state]][aa];
                }
            }
        }
    }

    return;
}

static inline void SCACTileClubOutputStatePresenceWithDeltaTable(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    int aa = 0;
    uint32_t state = 0;
    uint32_t temp_state = 0;

    if (ctx->state_count < 32767) {
        for (state = 0; state < ctx->state_count; state++) {
            for (aa = 0; aa < ctx->alphabet_size; aa++) {
                temp_state = *NEXT_STATE(ctx->state_table_u16, state & 0x7FFF, aa);
                if (ctx->output_table[temp_state & 0x7FFF].no_of_entries != 0)
                        *NEXT_STATE(ctx->state_table_u16, state & 0x7FFF, aa) |= (1 << 15);
            }
        }
    }

    if (!(ctx->state_count < 32767)) {
        for (state = 0; state < ctx->state_count; state++) {
            for (aa = 0; aa < ctx->alphabet_size; aa++) {
                temp_state = ctx->state_table_u32[state & 0x00FFFFFF][aa];
                if (ctx->output_table[temp_state & 0x00FFFFFF].no_of_entries != 0)
                    ctx->state_table_u32[state & 0x00FFFFFF][aa] |= (1 << 24);
            }
        }
    }

    return;
}

static inline void SCACTileInsertCaseSensitiveEntriesForPatterns(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    uint32_t state = 0;
    uint32_t k = 0;

    for (state = 0; state < ctx->state_count; state++) {
        if (ctx->output_table[state].no_of_entries == 0)
            continue;

        for (k = 0; k < ctx->output_table[state].no_of_entries; k++) {
            if (ctx->pid_pat_list[ctx->output_table[state].pids[k]].cs != NULL) {
                ctx->output_table[state].pids[k] &= 0x0000FFFF;
                ctx->output_table[state].pids[k] |= 1 << 16;
            }
        }
    }

    return;
}

#if 0
static void SCACTilePrintDeltaTable(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    int i = 0, j = 0;

    printf("##############Delta Table##############\n");
    for (i = 0; i < ctx->state_count; i++) {
        printf("%d: \n", i);
        for (j = 0; j < ctx->alphabet_size; j++) {
            if (SCACTileGetDelta(i, j, mpm_ctx) != 0) {
                printf("  %c -> %d\n", j, SCACTileGetDelta(i, j, mpm_ctx));
            }
        }
    }

    return;
}
#endif

/**
 * \brief Process the patterns and prepare the state table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACTilePrepareStateTable(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;

    /* Create Alphabet compression and Lower Case translation table. */
    SCACTileInitTranslateTable(mpm_ctx);

    /* create the 0th state in the goto table and output_table */
    SCACTileInitNewState(mpm_ctx);

    /* create the goto table */
    SCACTileCreateGotoTable(mpm_ctx);
    /* create the failure table */
    SCACTileCreateFailureTable(mpm_ctx);
    /* create the final state(delta) table */
    SCACTileCreateDeltaTable(mpm_ctx);
    /* club the output state presence with delta transition entries */
    SCACTileClubOutputStatePresenceWithDeltaTable(mpm_ctx);

    /* club nocase entries */
    SCACTileInsertCaseSensitiveEntriesForPatterns(mpm_ctx);

#if 0
    SCACTilePrintDeltaTable(mpm_ctx);
#endif

    /* we don't need these anymore */
    SCFree(ctx->goto_table);
    ctx->goto_table = NULL;
    SCFree(ctx->failure_table);
    ctx->failure_table = NULL;

    return;
}

/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
int SCACTilePreparePatterns(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;

    if (mpm_ctx->pattern_cnt == 0 || ctx->init_hash == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }

    /* alloc the pattern array */
    ctx->parray = (SCACTilePattern **)SCMalloc(mpm_ctx->pattern_cnt *
                                           sizeof(SCACTilePattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(SCACTilePattern *));
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(SCACTilePattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < INIT_HASH_SIZE; i++) {
        SCACTilePattern *node = ctx->init_hash[i], *nnode = NULL;
        while(node != NULL) {
            nnode = node->next;
            node->next = NULL;
            ctx->parray[p++] = node;
            node = nnode;
        }
    }

    /* we no longer need the hash, so free it's memory */
    SCFree(ctx->init_hash);
    ctx->init_hash = NULL;

    /* handle no case patterns */
    ctx->pid_pat_list = SCMalloc((ctx->max_pat_id + 1)* sizeof(SCACTilePatternList));
    if (ctx->pid_pat_list == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->pid_pat_list, 0, (ctx->max_pat_id + 1) * sizeof(SCACTilePatternList));

    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (ctx->parray[i]->flags & MPM_PATTERN_FLAG_NOCASE) {
            if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 0)
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 1;
            else if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 1)
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 1;
            else
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 3;
        } else {
            ctx->pid_pat_list[ctx->parray[i]->id].cs = SCMalloc(ctx->parray[i]->len);
            if (ctx->pid_pat_list[ctx->parray[i]->id].cs == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            memcpy(ctx->pid_pat_list[ctx->parray[i]->id].cs,
                   ctx->parray[i]->original_pat, ctx->parray[i]->len);
            ctx->pid_pat_list[ctx->parray[i]->id].patlen = ctx->parray[i]->len;
          
            if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 0)
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 2;
            else if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 2)
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 2;
            else
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 3;
        }
    }
    
    /* prepare the state table required by AC */
    SCACTilePrepareStateTable(mpm_ctx);
    
    /* free all the stored patterns.  Should save us a good 100-200 mbs */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (ctx->parray[i] != NULL) {
            SCACTileFreePattern(mpm_ctx, ctx->parray[i]);
        }
    }
    SCFree(ctx->parray);
    ctx->parray = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACTilePattern *));

    return 0;

error:
    return -1;
}

/**
 * \brief Init the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * \param matchsize      We don't need this.
 */
void SCACTileInitThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, 
                           uint32_t matchsize)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    mpm_thread_ctx->ctx = SCMalloc(sizeof(SCACTileThreadCtx));
    if (mpm_thread_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_thread_ctx->ctx, 0, sizeof(SCACTileThreadCtx));
    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(SCACTileThreadCtx);

    return;
}

/**
 * \brief Initialize the AC context.
 *
 * \param mpm_ctx       Mpm context.
 */
void SCACTileInitCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->ctx != NULL)
        return;

    mpm_ctx->ctx = SCMalloc(sizeof(SCACTileCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_ctx->ctx, 0, sizeof(SCACTileCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACTileCtx);

    /* initialize the hash we use to speed up pattern insertions */
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    ctx->init_hash = SCMalloc(sizeof(SCACTilePattern *) * INIT_HASH_SIZE);
    if (ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(ctx->init_hash, 0, sizeof(SCACTilePattern *) * INIT_HASH_SIZE);

    /* get conf values for AC from our yaml file.  We have no conf values for
     * now.  We will certainly need this, as we develop the algo */
    SCACTileGetConfig();

    SCReturn;
}

/**
 * \brief Destroy the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCACTileDestroyThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    SCACTilePrintSearchStats(mpm_thread_ctx);

    if (mpm_thread_ctx->ctx != NULL) {
        SCFree(mpm_thread_ctx->ctx);
        mpm_thread_ctx->ctx = NULL;
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(SCACTileThreadCtx);
    }

    return;
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
void SCACTileDestroyCtx(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash != NULL) {
        SCFree(ctx->init_hash);
        ctx->init_hash = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (INIT_HASH_SIZE * sizeof(SCACTilePattern *));
    }

    if (ctx->parray != NULL) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->parray[i] != NULL) {
                SCACTileFreePattern(mpm_ctx, ctx->parray[i]);
            }
        }

        SCFree(ctx->parray);
        ctx->parray = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACTilePattern *));
    }

    if (ctx->state_table_u16 != NULL) {
        SCFree(ctx->state_table_u16);
        ctx->state_table_u16 = NULL;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 sizeof(SC_AC_TILE_STATE_TYPE_U16) * ctx->alphabet_size);
    } else if (ctx->state_table_u32 != NULL) {
        /* Not currently reducing the table row size for smaller alphabet sizes from 256.
         * That would require specializing SCACTileSearchLarge by alphabet size. */
        SCFree(ctx->state_table_u32);
        ctx->state_table_u32 = NULL;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 sizeof(SC_AC_TILE_STATE_TYPE_U32) * 256);
    }

    if (ctx->output_table != NULL) {
        uint32_t state_count;
        for (state_count = 0; state_count < ctx->state_count; state_count++) {
            if (ctx->output_table[state_count].pids != NULL) {
                SCFree(ctx->output_table[state_count].pids);
            }
        }
        SCFree(ctx->output_table);
    }

    if (ctx->pid_pat_list != NULL) {
        int i;
        for (i = 0; i < (ctx->max_pat_id + 1); i++) {
            if (ctx->pid_pat_list[i].cs != NULL)
                SCFree(ctx->pid_pat_list[i].cs);
        }
        SCFree(ctx->pid_pat_list);
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCACTileCtx);

    return;
}

/*
 * Heavily optimized pattern matching routine for TILE-Gx.
 */

#define STYPE int16_t
#define SCHECK(x) ((x) < 0)
// Hint to compiler to expect L2 hit latency for Load int16_t
#define SLOAD(x) __insn_ld2s_L2((int16_t* restrict)(x))
#define BTYPE int32_t
// Extract byte N=0,1,2,3 from x
#define BYTE0(x) __insn_bfextu(x, 0, 7)
#define BYTE1(x) __insn_bfextu(x, 8, 15)
#define BYTE2(x) __insn_bfextu(x, 16, 23)
#define BYTE3(x) __insn_bfextu(x, 24, 31)

int CheckMatch(SCACTileCtx *ctx, PatternMatcherQueue *pmq, 
               uint8_t *buf, uint16_t buflen, 
               STYPE state, int i, int matches)
{
    SCACTilePatternList *pid_pat_list = ctx->pid_pat_list;
    uint8_t *buf_offset = buf + i + 1; // Lift out of loop
    uint32_t no_of_entries = ctx->output_table[state & 0x7FFF].no_of_entries;
    uint32_t *pids = ctx->output_table[state & 0x7FFF].pids;
    uint8_t *bitarray = pmq->pattern_id_bitarray;
    uint32_t k;

    /* Where to start storing new patterns */
    uint32_t *orig_pattern = pmq->pattern_id_array + pmq->pattern_id_array_cnt;
    uint32_t *new_pattern = orig_pattern;

    for (k = 0; k < no_of_entries; k++) {
        uint16_t lower_pid = pids[k] & 0x0000FFFF;
        if (pids[k] & 0xFFFF0000) {
            uint16_t patlen = pid_pat_list[lower_pid].patlen;
            if (SCMemcmp(pid_pat_list[lower_pid].cs, buf_offset - patlen, patlen) != 0) {
                /* inside loop */
                if (pid_pat_list[lower_pid].case_state != 3) {
                    continue;
                }
            }
        }
        if (bitarray[(lower_pid) / 8] & (1 << ((lower_pid) % 8))) {
            ;
        } else {
            bitarray[(lower_pid) / 8] |= (1 << ((lower_pid) % 8));
            *new_pattern++ = lower_pid;
        }
        matches++;
    }
    /* Only update the pattern count if a new pattern was added. 
     * No need to compute it or dirty that cache data for no change.
     */
    if (new_pattern != orig_pattern)
        pmq->pattern_id_array_cnt = new_pattern - orig_pattern;

    return matches;
}

/**
 * \brief The aho corasick search function.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * \param pmq            Pointer to the Pattern Matcher Queue to hold
 *                       search matches.
 * \param buf            Buffer to be searched.
 * \param buflen         Buffer length.
 *
 * \retval matches Match count.
 */
uint32_t SCACTileSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;
    if (buflen == 0)
        return 0;

    /* Context specific matching function. */
    return ctx->search(ctx, mpm_thread_ctx, pmq, buf, buflen);
}
    
/* This function handles (ctx->state_count >= 32767) */
uint32_t SCACTileSearchLarge(SCACTileCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                             PatternMatcherQueue *pmq, 
                             uint8_t *buf, uint16_t buflen)
{
    int i = 0;
    int matches = 0;

    SCACTilePatternList *pid_pat_list = ctx->pid_pat_list;

    uint8_t* restrict xlate = ctx->translate_table;
    register SC_AC_TILE_STATE_TYPE_U32 state = 0;
    SC_AC_TILE_STATE_TYPE_U32 (*state_table_u32)[256] = ctx->state_table_u32;
    for (i = 0; i < buflen; i++) {
        state = state_table_u32[state & 0x00FFFFFF][xlate[buf[i]]];
        if (state & 0xFF000000) {
            uint32_t no_of_entries = ctx->output_table[state & 0x00FFFFFF].no_of_entries;
            uint32_t *pids = ctx->output_table[state & 0x00FFFFFF].pids;
            uint32_t k;
            for (k = 0; k < no_of_entries; k++) {
                if (pids[k] & 0xFFFF0000) {
                    if (SCMemcmp(pid_pat_list[pids[k] & 0x0000FFFF].cs,
                                 buf + i - pid_pat_list[pids[k] & 0x0000FFFF].patlen + 1,
                                 pid_pat_list[pids[k] & 0x0000FFFF].patlen) != 0) {
                            /* inside loop */
                            if (pid_pat_list[pids[k] & 0x0000FFFF].case_state != 3) {
                                continue;
                            }
                    }
                    if (pmq->pattern_id_bitarray[(pids[k] & 0x0000FFFF) / 8] & 
                        (1 << ((pids[k] & 0x0000FFFF) % 8))) {
                        ;
                    } else {
                        pmq->pattern_id_bitarray[(pids[k] & 0x0000FFFF) / 8] |= 
                          (1 << ((pids[k] & 0x0000FFFF) % 8));
                        pmq->pattern_id_array[pmq->pattern_id_array_cnt++] = 
                          pids[k] & 0x0000FFFF;
                    }
                    matches++;
                } else {
                    if (pmq->pattern_id_bitarray[pids[k] / 8] & (1 << (pids[k] % 8))) {
                        ;
                    } else {
                        pmq->pattern_id_bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));
                        pmq->pattern_id_array[pmq->pattern_id_array_cnt++] = pids[k];
                    }
                    matches++;
                }
            }
        }
    } /* for (i = 0; i < buflen; i++) */

    return matches;
}

/* Search with Alphabet size of 256 */
#define FUNC_NAME SCACTileSearchSmall256
// y = 2 * 256 * (x & 0x7FFF)
#define SINDEX(y,x) __insn_bfins(y, x, 9, 23)
#include "util-mpm-ac-tile-small.c"

/* Search with Alphabet size of 128 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall128
#define SINDEX(y,x) __insn_bfins(y, x, 8, 22)
#include "util-mpm-ac-tile-small.c"

/* Search with Alphabet size of 64 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall64
#define SINDEX(y,x) __insn_bfins(y, x, 7, 21)
#include "util-mpm-ac-tile-small.c"

/* Search with Alphabet size of 32 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall32
#define SINDEX(y,x) __insn_bfins(y, x, 6, 20)
#include "util-mpm-ac-tile-small.c"

/* Search with Alphabet size of 16 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall16
#define SINDEX(y,x) __insn_bfins(y, x, 5, 19)
#include "util-mpm-ac-tile-small.c"


/**
 * \brief Add a case insensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patnen  The pattern length.
 * \param offset  Ignored.
 * \param depth   Ignored.
 * \param pid     The pattern id.
 * \param sid     Ignored.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCACTileAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                         uint16_t offset, uint16_t depth, uint32_t pid,
                         uint32_t sid, uint8_t flags)
{
  flags |= MPM_PATTERN_FLAG_NOCASE;
  return SCACTileAddPattern(mpm_ctx, pat, patlen, offset, depth, 
                            pid, sid, flags);
}

/**
 * \brief Add a case sensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patnen  The pattern length.
 * \param offset  Ignored.
 * \param depth   Ignored.
 * \param pid     The pattern id.
 * \param sid     Ignored.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCACTileAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                         uint16_t offset, uint16_t depth, uint32_t pid,
                         uint32_t sid, uint8_t flags)
{
  return SCACTileAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

void SCACTilePrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{

#ifdef SC_AC_TILE_COUNTERS
    SCACTileThreadCtx *ctx = (SCACTileThreadCtx *)mpm_thread_ctx->ctx;
    printf("AC Thread Search stats (ctx %p)\n", ctx);
    printf("Total calls: %" PRIu32 "\n", ctx->total_calls);
    printf("Total matches: %" PRIu64 "\n", ctx->total_matches);
#endif /* SC_AC_TILE_COUNTERS */

    return;
}

void SCACTilePrintInfo(MpmCtx *mpm_ctx)
{
    SCACTileCtx *ctx = (SCACTileCtx *)mpm_ctx->ctx;

    printf("MPM AC Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeof:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  SCACTileCtx:         %" PRIuMAX "\n", (uintmax_t)sizeof(SCACTileCtx));
    printf("  SCACTilePattern      %" PRIuMAX "\n", (uintmax_t)sizeof(SCACTilePattern));
    printf("  SCACTilePattern     %" PRIuMAX "\n", (uintmax_t)sizeof(SCACTilePattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Total states in the state table:    %" PRIu32 "\n", ctx->state_count);
    printf("\n");

    return;
}

/************************** Mpm Registration ***************************/

/**
 * \brief Register the aho-corasick mpm for Tilera Tile-Gx processor.
 */
void MpmACTileRegister(void)
{
    mpm_table[MPM_AC_TILE].name = "ac-tile";
    mpm_table[MPM_AC_TILE].max_pattern_length = 0;

    mpm_table[MPM_AC_TILE].InitCtx = SCACTileInitCtx;
    mpm_table[MPM_AC_TILE].InitThreadCtx = SCACTileInitThreadCtx;
    mpm_table[MPM_AC_TILE].DestroyCtx = SCACTileDestroyCtx;
    mpm_table[MPM_AC_TILE].DestroyThreadCtx = SCACTileDestroyThreadCtx;
    mpm_table[MPM_AC_TILE].AddPattern = SCACTileAddPatternCS;
    mpm_table[MPM_AC_TILE].AddPatternNocase = SCACTileAddPatternCI;
    mpm_table[MPM_AC_TILE].Prepare = SCACTilePreparePatterns;
    mpm_table[MPM_AC_TILE].Search = SCACTileSearch;
    mpm_table[MPM_AC_TILE].Cleanup = NULL;
    mpm_table[MPM_AC_TILE].PrintCtx = SCACTilePrintInfo;
    mpm_table[MPM_AC_TILE].PrintThreadCtx = SCACTilePrintSearchStats;
    mpm_table[MPM_AC_TILE].RegisterUnittests = SCACTileRegisterTests;

    return;
}


/*************************************Unittests********************************/

#ifdef UNITTESTS

static int SCACTileTest01(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));
    
    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest02(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest03(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcd";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest07(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* should match 30 times */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* 26 */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* 21 */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* 1 */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                     30, 0, 0, 5, 0, 0);
    PmqSetup(&pmq, 0, 6);
    /* total matches: 135 */

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    if (SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq, 0, 5);

    if (SCACTilePreparePatterns(&mpm_ctx) == -1)
        goto end;

    result = 1;

    char *buf = "he";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 1);
    buf = "she";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 2);
    buf = "his";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 1);
    buf = "hers";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 2);

 end:
    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 0, 2);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCD";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDE";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDEF";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABC";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABC";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzAB";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzAB";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcde""fghij""klmno""pqrst""uvwxy""z";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcde""fghij""klmno""pqrst""uvwxy""z";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest20(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 0, 2);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest26(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACTileAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 0, 2);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "works";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "tone";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest28(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_TILE);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    SCACTileAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACTilePreparePatterns(&mpm_ctx);

    char *buf = "tONE";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

#endif /* UNITTESTS */

void SCACTileRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCACTileTest01", SCACTileTest01, 1);
    UtRegisterTest("SCACTileTest02", SCACTileTest02, 1);
    UtRegisterTest("SCACTileTest03", SCACTileTest03, 1);
    UtRegisterTest("SCACTileTest04", SCACTileTest04, 1);
    UtRegisterTest("SCACTileTest05", SCACTileTest05, 1);
    UtRegisterTest("SCACTileTest06", SCACTileTest06, 1);
    UtRegisterTest("SCACTileTest07", SCACTileTest07, 1);
    UtRegisterTest("SCACTileTest08", SCACTileTest08, 1);
    UtRegisterTest("SCACTileTest09", SCACTileTest09, 1);
    UtRegisterTest("SCACTileTest10", SCACTileTest10, 1);
    UtRegisterTest("SCACTileTest11", SCACTileTest11, 1);
    UtRegisterTest("SCACTileTest12", SCACTileTest12, 1);
    UtRegisterTest("SCACTileTest13", SCACTileTest13, 1);
    UtRegisterTest("SCACTileTest14", SCACTileTest14, 1);
    UtRegisterTest("SCACTileTest15", SCACTileTest15, 1);
    UtRegisterTest("SCACTileTest16", SCACTileTest16, 1);
    UtRegisterTest("SCACTileTest17", SCACTileTest17, 1);
    UtRegisterTest("SCACTileTest18", SCACTileTest18, 1);
    UtRegisterTest("SCACTileTest19", SCACTileTest19, 1);
    UtRegisterTest("SCACTileTest20", SCACTileTest20, 1);
    UtRegisterTest("SCACTileTest21", SCACTileTest21, 1);
    UtRegisterTest("SCACTileTest22", SCACTileTest22, 1);
    UtRegisterTest("SCACTileTest23", SCACTileTest23, 1);
    UtRegisterTest("SCACTileTest24", SCACTileTest24, 1);
    UtRegisterTest("SCACTileTest25", SCACTileTest25, 1);
    UtRegisterTest("SCACTileTest26", SCACTileTest26, 1);
    UtRegisterTest("SCACTileTest27", SCACTileTest27, 1);
    UtRegisterTest("SCACTileTest28", SCACTileTest28, 1);
#endif

    return;
}

#endif /* __tile__ */
