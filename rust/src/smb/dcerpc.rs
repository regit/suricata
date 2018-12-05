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

// written by Victor Julien
extern crate libc;

use nom::IResult;
use log::*;

use smb::smb::*;
use smb::smb2::*;
use smb::dcerpc_records::*;
use smb::events::*;

pub const DCERPC_TYPE_REQUEST:              u8 = 0;
pub const DCERPC_TYPE_PING:                 u8 = 1;
pub const DCERPC_TYPE_RESPONSE:             u8 = 2;
pub const DCERPC_TYPE_FAULT:                u8 = 3;
pub const DCERPC_TYPE_WORKING:              u8 = 4;
pub const DCERPC_TYPE_NOCALL:               u8 = 5;
pub const DCERPC_TYPE_REJECT:               u8 = 6;
pub const DCERPC_TYPE_ACK:                  u8 = 7;
pub const DCERPC_TYPE_CL_CANCEL:            u8 = 8;
pub const DCERPC_TYPE_FACK:                 u8 = 9;
pub const DCERPC_TYPE_CANCEL_ACK:           u8 = 10;
pub const DCERPC_TYPE_BIND:                 u8 = 11;
pub const DCERPC_TYPE_BINDACK:              u8 = 12;
pub const DCERPC_TYPE_BINDNAK:              u8 = 13;
pub const DCERPC_TYPE_ALTER_CONTEXT:        u8 = 14;
pub const DCERPC_TYPE_ALTER_CONTEXT_RESP:   u8 = 15;
pub const DCERPC_TYPE_AUTH3:                u8 = 16;
pub const DCERPC_TYPE_SHUTDOWN:             u8 = 17;
pub const DCERPC_TYPE_CO_CANCEL:            u8 = 18;
pub const DCERPC_TYPE_ORPHANED:             u8 = 19;
pub const DCERPC_TYPE_RTS:                  u8 = 20;

pub fn dcerpc_type_string(t: u8) -> String {
    match t {
        DCERPC_TYPE_REQUEST             => "REQUEST",
        DCERPC_TYPE_PING                => "PING",
        DCERPC_TYPE_RESPONSE            => "RESPONSE",
        DCERPC_TYPE_FAULT               => "FAULT",
        DCERPC_TYPE_WORKING             => "WORKING",
        DCERPC_TYPE_NOCALL              => "NOCALL",
        DCERPC_TYPE_REJECT              => "REJECT",
        DCERPC_TYPE_ACK                 => "ACK",
        DCERPC_TYPE_CL_CANCEL           => "CL_CANCEL",
        DCERPC_TYPE_FACK                => "FACK",
        DCERPC_TYPE_CANCEL_ACK          => "CANCEL_ACK",
        DCERPC_TYPE_BIND                => "BIND",
        DCERPC_TYPE_BINDACK             => "BINDACK",
        DCERPC_TYPE_BINDNAK             => "BINDNAK",
        DCERPC_TYPE_ALTER_CONTEXT       => "ALTER_CONTEXT",
        DCERPC_TYPE_ALTER_CONTEXT_RESP  => "ALTER_CONTEXT_RESP",
        DCERPC_TYPE_AUTH3               => "AUTH3",
        DCERPC_TYPE_SHUTDOWN            => "SHUTDOWN",
        DCERPC_TYPE_CO_CANCEL           => "CO_CANCEL",
        DCERPC_TYPE_ORPHANED            => "ORPHANED",
        DCERPC_TYPE_RTS                 => "RTS",
        _ => { return (t).to_string(); },
    }.to_string()
}

pub fn dcerpc_uid_mapping(uid: String) -> String {
    match uid.as_ref() {
		"367abb81-9844-35f1-ad32-98f038001003" => "svcctl",
		"86d35949-83c9-4044-b424-db363231fd0c" => "ITaskSchedulerService",
		"378e52b0-c0a9-11cf-822d-00aa0051e40f" => "sasec",
		"1ff70682-0a51-30e8-076d-740be8cee98b" => "atsvc",
		"0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53" => "idletask",
		"906b0ce0-c70b-1067-b317-00dd010662da" => "IXnRemote",
		"ae33069b-a2a8-46ee-a235-ddfd339be281" => "IRPCRemoteObject",
		"0b6edbfa-4a24-4fc6-8a23-942b1eca65d1" => "IRPCAsyncNotify",
		"afa8bd80-7d8a-11c9-bef4-08002b102989" => "mgmt",
		"f5cc59b4-4264-101a-8c59-08002b2f8426" => "FrsRpc",
		"000001a0-0000-0000-c000-000000000046" => "IRemoteSCMActivator",
		"00000143-0000-0000-c000-000000000046" => "IRemUnknown2",
		"12345778-1234-abcd-ef00-0123456789ab" => "lsarpc",
		"76f03f96-cdfd-44fc-a22c-64950a001209" => "IRemoteWinspool",
		"12345678-1234-abcd-ef00-01234567cffb" => "netlogon",
		"e3514235-4b06-11d1-ab04-00c04fc2dcd2" => "drsuapi",
		"5261574a-4572-206e-b268-6b199213b4e4" => "AsyncEMSMDB",
		"4d9f4ab8-7d1c-11cf-861e-0020af6e7c57" => "IActivation",
		"99fcfec4-5260-101b-bbcb-00aa0021347a" => "IObjectExporter",
		"e1af8308-5d1f-11c9-91a4-08002b14a0fa" => "epmapper",
		"12345778-1234-abcd-ef00-0123456789ac" => "samr",
		"4b324fc8-1670-01d3-1278-5a47bf6ee188" => "srvsvc",
		"45f52c28-7f9f-101a-b52b-08002b2efabe" => "winspipe",
		"6bffd098-a112-3610-9833-46c3f87e345a" => "wkssvc",
		"3919286a-b10c-11d0-9ba8-00c04fd92ef5" => "dssetup",
		"12345678-1234-abcd-ef00-0123456789ab" => "spoolss",

		// Exchange
		"1544f5e0-613c-11d1-93df-00c04fd7bd09" => "exchange_rfr",
		"f5cc5a18-4264-101a-8c59-08002b2f8426" => "nspi",
		"a4f1db00-ca47-1067-b31f-00dd010662da" => "exchange_mapi",

		// IWbem
		"9556dc99-828c-11cf-a37e-00aa003240c7" => "IWbemServices",
		"f309ad18-d86a-11d0-a075-00c04fb68820" => "IWbemLevel1Login",
		"d4781cd6-e5d3-44df-ad94-930efe48a887" => "IWbemLoginClientID",
		"44aca674-e8fc-11d0-a07c-00c04fb68820" => "IWbemContext interface",
		"674b6698-ee92-11d0-ad71-00c04fd8fdff" => "IWbemContext unmarshaler",
		"dc12a681-737f-11cf-884d-00aa004b2e24" => "IWbemClassObject interface",
		"4590f812-1d3a-11d0-891f-00aa004b2e24" => "IWbemClassObject unmarshaler",
		"9a653086-174f-11d2-b5f9-00104b703efd" => "IWbemClassObject interface",
		"c49e32c6-bc8b-11d2-85d4-00105a1f8304" => "IWbemBackupRestoreEx interface",
		"7c857801-7381-11cf-884d-00aa004b2e24" => "IWbemObjectSink interface",
		"027947e1-d731-11ce-a357-000000000001" => "IEnumWbemClassObject interface",
		"44aca675-e8fc-11d0-a07c-00c04fb68820" => "IWbemCallResult interface",
		"c49e32c7-bc8b-11d2-85d4-00105a1f8304" => "IWbemBackupRestore interface",
		"a359dec5-e813-4834-8a2a-ba7f1d777d76" => "IWbemBackupRestoreEx interface",
		"f1e9c5b2-f59b-11d2-b362-00105a1f8177" => "IWbemRemoteRefresher interface",
		"2c9273e0-1dc3-11d3-b364-00105a1f8177" => "IWbemRefreshingServices interface",
		"423ec01e-2e35-11d2-b604-00104b703efd" => "IWbemWCOSmartEnum interface",
		"1c1c45ee-4395-11d2-b60b-00104b703efd" => "IWbemFetchSmartEnum interface",
		"541679AB-2E5F-11d3-B34E-00104BCC4B4A" => "IWbemLoginHelper interface",
		"51c82175-844e-4750-b0d8-ec255555bc06" => "KMS",
		"50abc2a4-574d-40b3-9d66-ee4fd5fba076" => "dnsserver",
		"3faf4738-3a21-4307-b46c-fdda9bb8c0d5" => "AudioSrv",
		"c386ca3e-9061-4a72-821e-498d83be188f" => "AudioRpc",
		"6bffd098-a112-3610-9833-012892020162" => "browser",
		"91ae6020-9e3c-11cf-8d7c-00aa00c091be" => "ICertPassage",
		"c8cb7687-e6d3-11d2-a958-00c04f682e16" => "DAV RPC SERVICE",
		"82273fdc-e32a-18c3-3f78-827929dc23ea" => "eventlog",
		"3d267954-eeb7-11d1-b94e-00c04fa3080d" => "HydraLsPipe",
		"894de0c0-0d55-11d3-a322-00c04fa321a1" => "InitShutdown",
		"d95afe70-a6d5-4259-822e-2c84da1ddb0d" => "WindowsShutdown",
		"8d0ffe72-d252-11d0-bf8f-00c04fd9126b" => "IKeySvc",
		"68b58241-c259-4f03-a2e5-a2651dcbc930" => "IKeySvc2",
		"0d72a7d4-6148-11d1-b4aa-00c04fb66ea0" => "ICertProtect",
		"f50aac00-c7f3-428e-a022-a6b71bfb9d43" => "ICatDBSvc",
		"338cd001-2244-31f1-aaaa-900038001003" => "winreg",
		"3dde7c30-165d-11d1-ab8f-00805f14db40" => "BackupKey", 
		"3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5" => "RpcSrvDHCPC",
		"3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6" => "dhcpcsvc6",
		"2f59a331-bf7d-48cb-9ec5-7c090d76e8b8" => "lcrpc",
		"5ca4a760-ebb1-11cf-8611-00a0245420ed" => "winstation_rpc",
		"12b81e99-f207-4a4c-85d3-77b42f76fd14" => "ISeclogon",
		"d6d70ef0-0e3b-11cb-acc3-08002b1d29c3" => "NsiS",
		"d3fbb514-0e3b-11cb-8fad-08002b1d29c3" => "NsiC",
		"d6d70ef0-0e3b-11cb-acc3-08002b1d29c4" => "NsiM",
		"17fdd703-1827-4e34-79d4-24a55c53bb37" => "msgsvc",
		"5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc" => "msgsvcsend",
		"8d9f4e40-a03d-11ce-8f69-08003e30051b" => "pnp",
		"57674cd0-5200-11ce-a897-08002b2e9c6d" => "lls_license",
		"342cfd40-3c6c-11ce-a893-08002b2e9c6d" => "llsrpc",
		"4fc742e0-4a10-11cf-8273-00aa004ae673" => "netdfs",
		"83da7c00-e84f-11d2-9807-00c04f8ec850" => "sfcapi",
		"2f5f3220-c126-1076-b549-074d078619da" => "nddeapi",
        _ => { return ("Unknown").to_string(); },
    }.to_string()
}

impl SMBCommonHdr {
    /// helper for DCERPC tx tracking. Check if we need
    /// to use the msg_id/multiplex_id in TX tracking.
    ///
    pub fn to_dcerpc(&self, vercmd: &SMBVerCmdStat) -> SMBCommonHdr {
        // only use the msg id for IOCTL, not for READ/WRITE
        // as there request/response are different transactions
        let mut use_msg_id = self.msg_id;
        match vercmd.get_version() {
            2 => {
                let (_, cmd2) = vercmd.get_smb2_cmd();
                let x = match cmd2 as u16 {
                    SMB2_COMMAND_READ => { 0 },
                    SMB2_COMMAND_WRITE => { 0 },
                    SMB2_COMMAND_IOCTL => { self.msg_id },
                    _ => { self.msg_id },
                };
                use_msg_id = x;
            },
            1 => {
                SCLogDebug!("FIXME TODO");
                //let (_, cmd1) = vercmd.get_smb1_cmd();
                //if cmd1 != SMB1_COMMAND_IOCTL {
                use_msg_id = 0;
                //}
            },
            _ => { },
        }
        SMBCommonHdr {
            ssn_id: self.ssn_id,
            tree_id: self.tree_id,
            msg_id: use_msg_id,
            rec_type: SMBHDR_TYPE_DCERPCTX,
        }
    }
}

#[derive(Debug)]
pub struct DCERPCIface {
    pub uuid: Vec<u8>,
    pub ver: u16,
    pub ver_min: u16,
    pub ack_result: u16,
    pub ack_reason: u16,
    pub acked: bool,
}

impl DCERPCIface {
    pub fn new(uuid: Vec<u8>, ver: u16, ver_min: u16) -> DCERPCIface {
        DCERPCIface {
            uuid: uuid,
            ver:ver,
            ver_min:ver_min,
            ack_result:0,
            ack_reason:0,
            acked:false,
        }
    }
}

pub fn dcerpc_uuid_to_string(i: &DCERPCIface) -> String {
    let output = format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            i.uuid[0],  i.uuid[1],  i.uuid[2],  i.uuid[3],
            i.uuid[4],  i.uuid[5],  i.uuid[6],  i.uuid[7],
            i.uuid[8],  i.uuid[9],  i.uuid[10], i.uuid[11],
            i.uuid[12], i.uuid[13], i.uuid[14], i.uuid[15]);
    return output;
}


#[derive(Debug)]
pub struct SMBTransactionDCERPC {
    pub opnum: u16,
    pub req_cmd: u8,
    pub req_set: bool,
    pub res_cmd: u8,
    pub res_set: bool,
    pub call_id: u32,
    pub frag_cnt_ts: u16,
    pub frag_cnt_tc: u16,
    pub stub_data_ts: Vec<u8>,
    pub stub_data_tc: Vec<u8>,
}

impl SMBTransactionDCERPC {
    fn new_request(req: u8, call_id: u32) -> SMBTransactionDCERPC {
        return SMBTransactionDCERPC {
            opnum: 0,
            req_cmd: req,
            req_set: true,
            res_cmd: 0,
            res_set: false,
            call_id: call_id,
            frag_cnt_ts: 0,
            frag_cnt_tc: 0,
            stub_data_ts:Vec::new(),
            stub_data_tc:Vec::new(),
        }
    }
    fn new_response(call_id: u32) -> SMBTransactionDCERPC {
        return SMBTransactionDCERPC {
            opnum: 0,
            req_cmd: 0,
            req_set: false,
            res_cmd: 0,
            res_set: false,
            call_id: call_id,
            frag_cnt_ts: 0,
            frag_cnt_tc: 0,
            stub_data_ts:Vec::new(),
            stub_data_tc:Vec::new(),
        }
    }
    pub fn set_result(&mut self, res: u8) {
        self.res_set = true;
        self.res_cmd = res;
    }
}

impl SMBState {
    fn new_dcerpc_tx(&mut self, hdr: SMBCommonHdr, vercmd: SMBVerCmdStat, cmd: u8, call_id: u32)
        -> (&mut SMBTransaction)
    {
        let mut tx = self.new_tx();
        tx.hdr = hdr;
        tx.vercmd = vercmd;
        tx.type_data = Some(SMBTransactionTypeData::DCERPC(
                    SMBTransactionDCERPC::new_request(cmd, call_id)));

        SCLogDebug!("SMB: TX DCERPC created: ID {} hdr {:?}", tx.id, tx.hdr);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    fn new_dcerpc_tx_for_response(&mut self, hdr: SMBCommonHdr, vercmd: SMBVerCmdStat, call_id: u32)
        -> (&mut SMBTransaction)
    {
        let mut tx = self.new_tx();
        tx.hdr = hdr;
        tx.vercmd = vercmd;
        tx.type_data = Some(SMBTransactionTypeData::DCERPC(
                    SMBTransactionDCERPC::new_response(call_id)));

        SCLogDebug!("SMB: TX DCERPC created: ID {} hdr {:?}", tx.id, tx.hdr);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    fn get_dcerpc_tx(&mut self, hdr: &SMBCommonHdr, vercmd: &SMBVerCmdStat, call_id: u32)
        -> Option<&mut SMBTransaction>
    {
        let dce_hdr = hdr.to_dcerpc(vercmd);

        SCLogDebug!("looking for {:?}", dce_hdr);
        for tx in &mut self.transactions {
            let found = dce_hdr == tx.hdr.to_dcerpc(vercmd) &&
                match tx.type_data {
                Some(SMBTransactionTypeData::DCERPC(ref x)) => {
                    x.call_id == call_id
                },
                _ => { false },
            };
            if found {
                return Some(tx);
            }
        }
        return None;
    }
}

/// Handle DCERPC request data from a WRITE, IOCTL or TRANS record.
/// return bool indicating whether an tx has been created/updated.
///
pub fn smb_write_dcerpc_record<'b>(state: &mut SMBState,
        vercmd: SMBVerCmdStat,
        hdr: SMBCommonHdr,
        data: &'b [u8]) -> bool
{
    let mut bind_ifaces : Option<Vec<DCERPCIface>> = None;

    SCLogDebug!("called for {} bytes of data", data.len());
    match parse_dcerpc_record(data) {
        IResult::Done(_, dcer) => {
            SCLogDebug!("DCERPC: version {}.{} write data {} => {:?}",
                    dcer.version_major, dcer.version_minor, dcer.data.len(), dcer);

            /* if this isn't the first frag, simply update the existing
             * tx with the additional stub data */
            if dcer.packet_type == DCERPC_TYPE_REQUEST && dcer.first_frag == false {
                SCLogDebug!("NOT the first frag. Need to find an existing TX");
                match parse_dcerpc_request_record(dcer.data, dcer.frag_len, dcer.little_endian) {
                    IResult::Done(_, recr) => {
                        let found = match state.get_dcerpc_tx(&hdr, &vercmd, dcer.call_id) {
                            Some(tx) => {
                                SCLogDebug!("previous CMD {} found at tx {} => {:?}",
                                        dcer.packet_type, tx.id, tx);
                                if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                                    SCLogDebug!("additional frag of size {}", recr.data.len());
                                    tdn.stub_data_ts.extend_from_slice(&recr.data);
                                    tdn.frag_cnt_ts += 1;
                                    SCLogDebug!("stub_data now {}", tdn.stub_data_ts.len());
                                }
                                if dcer.last_frag {
                                    SCLogDebug!("last frag set, so request side of DCERPC closed");
                                    tx.request_done = true;
                                } else {
                                    SCLogDebug!("NOT last frag, so request side of DCERPC remains open");
                                }
                                true
                            },
                            None => {
                                SCLogDebug!("NO previous CMD {} found", dcer.packet_type);
                                false
                            },
                        };
                        return found;
                    },
                    _ => {
                        state.set_event(SMBEvent::MalformedData);
                        return false;
                    },
                }
            }

            let tx = state.new_dcerpc_tx(hdr, vercmd, dcer.packet_type, dcer.call_id);
            match dcer.packet_type {
                DCERPC_TYPE_REQUEST => {
                    match parse_dcerpc_request_record(dcer.data, dcer.frag_len, dcer.little_endian) {
                        IResult::Done(_, recr) => {
                            SCLogDebug!("DCERPC: REQUEST {:?}", recr);
                            if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                                SCLogDebug!("first frag size {}", recr.data.len());
                                tdn.stub_data_ts.extend_from_slice(&recr.data);
                                tdn.opnum = recr.opnum;
                                tdn.frag_cnt_ts += 1;
                                SCLogDebug!("DCERPC: REQUEST opnum {} stub data len {}",
                                        tdn.opnum, tdn.stub_data_ts.len());
                            }
                            if dcer.last_frag {
                                tx.request_done = true;
                            } else {
                                SCLogDebug!("NOT last frag, so request side of DCERPC remains open");
                            }
                        },
                        _ => {
                            tx.set_event(SMBEvent::MalformedData);
                        },
                    }
                },
                DCERPC_TYPE_BIND => {
                    let brec = if dcer.little_endian == true {
                        parse_dcerpc_bind_record(dcer.data)
                    } else {
                        parse_dcerpc_bind_record_big(dcer.data)
                    };
                    match brec {
                        IResult::Done(_, bindr) => {
                            SCLogDebug!("SMB DCERPC {:?} BIND {:?}", dcer, bindr);

                            if bindr.ifaces.len() > 0 {
                                let mut ifaces: Vec<DCERPCIface> = Vec::new();
                                for i in bindr.ifaces {
                                    let x = if dcer.little_endian == true {
                                        vec![i.iface[3],  i.iface[2],  i.iface[1],  i.iface[0],
                                             i.iface[5],  i.iface[4],  i.iface[7],  i.iface[6],
                                             i.iface[8],  i.iface[9],  i.iface[10], i.iface[11],
                                             i.iface[12], i.iface[13], i.iface[14], i.iface[15]]
                                    } else {
                                        i.iface.to_vec()
                                    };
                                    let d = DCERPCIface::new(x,i.ver,i.ver_min);
                                    SCLogDebug!("UUID {} version {}/{} bytes {:?}",
                                            dcerpc_uuid_to_string(&d),
                                            i.ver, i.ver_min,i.iface);
                                    ifaces.push(d);
                                }
                                bind_ifaces = Some(ifaces);
                            }
                            tx.request_done = true;
                        },
                        _ => {
                            tx.set_event(SMBEvent::MalformedData);
                        },
                    }
                }
                21...255 => {
                    tx.set_event(SMBEvent::MalformedData);
                },
                _ => { }, // valid type w/o special processing
            }
        },
        _ => {
            state.set_event(SMBEvent::MalformedData);
        },
    }

    state.dcerpc_ifaces = bind_ifaces; // TODO store per ssn
    return true;
}

/// Update TX for bind ack. Needs to update both tx and state.
///
fn smb_dcerpc_response_bindack(
        state: &mut SMBState,
        vercmd: SMBVerCmdStat,
        hdr: SMBCommonHdr,
        dcer: &DceRpcRecord,
        ntstatus: u32)
{
    match parse_dcerpc_bindack_record(dcer.data) {
        IResult::Done(_, bindackr) => {
            SCLogDebug!("SMB READ BINDACK {:?}", bindackr);

            let found = match state.get_dcerpc_tx(&hdr, &vercmd, dcer.call_id) {
                Some(tx) => {
                    if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                        tdn.set_result(DCERPC_TYPE_BINDACK);
                    }
                    tx.vercmd.set_ntstatus(ntstatus);
                    tx.response_done = true;
                    true
                },
                None => false,
            };
            if found {
                match state.dcerpc_ifaces {
                    Some(ref mut ifaces) => {
                        let mut i = 0;
                        for r in bindackr.results {
                            if i >= ifaces.len() {
                                // TODO set event: more acks that requests
                                break;
                            }
                            ifaces[i].ack_result = r.ack_result;
                            ifaces[i].acked = true;
                            i = i + 1;
                        }
                    },
                    _ => {},
                }
            }
        },
        _ => {
            state.set_event(SMBEvent::MalformedData);
        },
    }
}

fn smb_read_dcerpc_record_error(state: &mut SMBState,
        hdr: SMBCommonHdr, vercmd: SMBVerCmdStat, ntstatus: u32)
    -> bool
{
    let ver = vercmd.get_version();
    let cmd = if ver == 2 {
        let (_, c) = vercmd.get_smb2_cmd();
        c
    } else {
        let (_, c) = vercmd.get_smb1_cmd();
        c as u16
    };

    let found = match state.get_generic_tx(ver, cmd, &hdr) {
        Some(tx) => {
            SCLogDebug!("found");
            tx.set_status(ntstatus, false);
            tx.response_done = true;
            true
        },
        None => {
            SCLogDebug!("NOT found");
            false
        },
    };
    return found;
}

fn dcerpc_response_handle<'b>(tx: &mut SMBTransaction,
        vercmd: SMBVerCmdStat,
        dcer: &DceRpcRecord)
{
    let (_, ntstatus) = vercmd.get_ntstatus();
    match dcer.packet_type {
        DCERPC_TYPE_RESPONSE => {
            match parse_dcerpc_response_record(dcer.data, dcer.frag_len) {
                IResult::Done(_, respr) => {
                    SCLogDebug!("SMBv1 READ RESPONSE {:?}", respr);
                    if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                        SCLogDebug!("CMD 11 found at tx {}", tx.id);
                        tdn.set_result(DCERPC_TYPE_RESPONSE);
                        tdn.stub_data_tc.extend_from_slice(&respr.data);
                        tdn.frag_cnt_tc += 1;
                    }
                    tx.vercmd.set_ntstatus(ntstatus);
                    tx.response_done = dcer.last_frag;
                },
                _ => {
                    tx.set_event(SMBEvent::MalformedData);
                },
            }
        },
        DCERPC_TYPE_BINDACK => {
            // handled elsewhere
        },
        21...255 => {
            if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                tdn.set_result(dcer.packet_type);
            }
            tx.vercmd.set_ntstatus(ntstatus);
            tx.response_done = true;
            tx.set_event(SMBEvent::MalformedData);
        }
        _ => { // valid type w/o special processing
            if let Some(SMBTransactionTypeData::DCERPC(ref mut tdn)) = tx.type_data {
                tdn.set_result(dcer.packet_type);
            }
            tx.vercmd.set_ntstatus(ntstatus);
            tx.response_done = true;
        },
    }
}

/// Handle DCERPC reply record. Called for READ, TRANS, IOCTL
///
pub fn smb_read_dcerpc_record<'b>(state: &mut SMBState,
        vercmd: SMBVerCmdStat,
        hdr: SMBCommonHdr,
        guid: &[u8],
        indata: &'b [u8]) -> bool
{
    let (_, ntstatus) = vercmd.get_ntstatus();

    if ntstatus != SMB_NTSTATUS_SUCCESS && ntstatus != SMB_NTSTATUS_BUFFER_OVERFLOW {
        return smb_read_dcerpc_record_error(state, hdr, vercmd, ntstatus);
    }

    SCLogDebug!("lets first see if we have prior data");
    // msg_id 0 as this data crosses cmd/reply pairs
    let ehdr = SMBHashKeyHdrGuid::new(SMBCommonHdr::new(SMBHDR_TYPE_TRANS_FRAG,
            hdr.ssn_id as u64, hdr.tree_id as u32, 0 as u64), guid.to_vec());
    let mut prevdata = match state.ssnguid2vec_map.remove(&ehdr) {
        Some(s) => s,
        None => Vec::new(),
    };
    SCLogDebug!("indata {} prevdata {}", indata.len(), prevdata.len());
    prevdata.extend_from_slice(&indata);
    let data = prevdata;

    let mut malformed = false;

    if data.len() == 0 {
        SCLogDebug!("weird: no DCERPC data"); // TODO
        // TODO set event?
        return false;

    } else {
        match parse_dcerpc_record(&data) {
            IResult::Done(_, dcer) => {
                SCLogDebug!("DCERPC: version {}.{} read data {} => {:?}",
                        dcer.version_major, dcer.version_minor, dcer.data.len(), dcer);

                if ntstatus == SMB_NTSTATUS_BUFFER_OVERFLOW && data.len() < dcer.frag_len as usize {
                    SCLogDebug!("short record {} < {}: storing partial data in state",
                            data.len(), dcer.frag_len);
                    state.ssnguid2vec_map.insert(ehdr, data.to_vec());
                    return true; // TODO review
                }

                if dcer.packet_type == DCERPC_TYPE_BINDACK {
                    smb_dcerpc_response_bindack(state, vercmd, hdr, &dcer, ntstatus);
                    return true;
                }

                let found = match state.get_dcerpc_tx(&hdr, &vercmd, dcer.call_id) {
                    Some(tx) => {
                        dcerpc_response_handle(tx, vercmd.clone(), &dcer);
                        true
                    },
                    None => {
                        SCLogDebug!("no tx");
                        false
                    },
                };
                if !found {
                    // pick up DCERPC tx even if we missed the request
                    let tx = state.new_dcerpc_tx_for_response(hdr, vercmd.clone(), dcer.call_id);
                    dcerpc_response_handle(tx, vercmd, &dcer);
                }
            },
            _ => {
                malformed = true;
            },
        }
    }

    if malformed {
        state.set_event(SMBEvent::MalformedData);
    }

    return true;
}

/// Try to find out if the input data looks like DCERPC
pub fn smb_dcerpc_probe<'b>(data: &[u8]) -> bool
{
    match parse_dcerpc_record(data) {
        IResult::Done(_, recr) => {
            SCLogDebug!("SMB: could be DCERPC {:?}", recr);
            if recr.version_major == 5 && recr.version_minor < 3 &&
               recr.frag_len > 0 && recr.packet_type <= 20
            {
                SCLogDebug!("SMB: looks like we have dcerpc");
                return true;
            }
        },
        _ => { },
    }
    return false;
}
