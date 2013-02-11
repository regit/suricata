/* Copyright (C) 2007-2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
#ifndef __LOG_TLS_JSONLOG_H__
#define __LOG_LSL_JSON_OG_H__

void TmModuleLogTlsJsonLogRegister (void);
void TmModuleLogTlsJsonLogIPv4Register (void);
void TmModuleLogTlsJsonLogIPv6Register (void);
OutputCtx *LogTlsJsonLogInitCtx(ConfNode *);

#endif /* __LOG_JSONTLSLOG_H__ */

