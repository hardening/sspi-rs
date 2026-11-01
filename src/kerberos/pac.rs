//! The Privilege Attribute Certificate ([MS-PAC]) the KDC of an Active Directory domain puts in
//! the tickets: the SIDs of the user and of its groups, and more about the logon.
//!
//! The PAC is in the authorization data of the ticket, as an `AD-WIN2K-PAC` element inside an
//! `AD-IF-RELEVANT` one. It is as trustworthy as the ticket, which only the KDC and the service
//! could encrypt; its signatures are not checked here (the KDC one needs the KDC).
//!
//! [MS-PAC]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/

use std::fmt;

use picky_krb::data_types::AuthorizationData;

use crate::{Error, ErrorKind, Result};

/// `AD-IF-RELEVANT` ([RFC 4120] 5.2.6.1)
pub const AD_IF_RELEVANT: u8 = 1;
/// `AD-WIN2K-PAC` ([MS-PAC] 2.4)
pub const AD_WIN2K_PAC: u8 = 128;

/// PAC_INFO_BUFFER types ([MS-PAC] 2.4)
pub mod buffer_type {
    pub const LOGON_INFO: u32 = 1;
    pub const CREDENTIALS_INFO: u32 = 2;
    pub const SERVER_CHECKSUM: u32 = 6;
    pub const KDC_CHECKSUM: u32 = 7;
    pub const CLIENT_INFO: u32 = 10;
    pub const CONSTRAINED_DELEGATION_INFO: u32 = 11;
    pub const UPN_DNS_INFO: u32 = 12;
    pub const CLIENT_CLAIMS: u32 = 13;
    pub const DEVICE_INFO: u32 = 14;
    pub const DEVICE_CLAIMS: u32 = 15;
    pub const TICKET_CHECKSUM: u32 = 16;
    pub const ATTRIBUTES_INFO: u32 = 17;
    pub const REQUESTOR: u32 = 18;
    pub const FULL_CHECKSUM: u32 = 19;
}

/// `UPN_DNS_INFO` flags
pub mod upn_dns_flags {
    /// the user has no UPN: the UPN is built from the account name and the DNS domain
    pub const UPN_CONSTRUCTED: u32 = 1;
    /// the SAM name and the SID are present
    pub const EXTENDED: u32 = 2;
}

/// A security identifier, `S-1-5-21-…` ([MS-DTYP] 2.4.2).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    pub revision: u8,
    /// 48 bits
    pub authority: u64,
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// This SID followed by a relative identifier: a domain SID and the RID of a group of it.
    pub fn with_rid(&self, rid: u32) -> Sid {
        let mut sid = self.clone();
        sid.sub_authorities.push(rid);
        sid
    }

    /// The binary form (`SID` structure, as in `UPN_DNS_INFO` or `PAC_REQUESTOR`).
    pub fn from_bytes(data: &[u8]) -> Result<Sid> {
        let mut r = Reader::new(data);
        let sid = r.raw_sid()?;
        Ok(sid)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // [MS-DTYP] 2.4.2.1: hexadecimal when the authority doesn't fit in 32 bits
        if self.authority >> 32 == 0 {
            write!(f, "S-{}-{}", self.revision, self.authority)?;
        } else {
            write!(f, "S-{}-0x{:012X}", self.revision, self.authority)?;
        }
        for s in &self.sub_authorities {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// `SE_GROUP_*` attributes of a group membership ([MS-PAC] 2.2.1).
pub mod group_attributes {
    pub const MANDATORY: u32 = 0x0000_0001;
    pub const ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
    pub const ENABLED: u32 = 0x0000_0004;
    pub const OWNER: u32 = 0x0000_0008;
    pub const RESOURCE: u32 = 0x2000_0000;
}

/// A group of the user, with its `SE_GROUP_*` attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMembership {
    pub sid: Sid,
    pub attributes: u32,
}

/// `KERB_VALIDATION_INFO` ([MS-PAC] 2.5): the logon information, as the domain controller gives it
/// to a Windows server. Times are FILETIMEs (100 ns since 1601), `0x7fff_ffff_ffff_ffff` for never.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogonInfo {
    pub logon_time: u64,
    pub logoff_time: u64,
    pub kick_off_time: u64,
    pub password_last_set: u64,
    pub password_can_change: u64,
    pub password_must_change: u64,
    /// the account name (sAMAccountName)
    pub effective_name: String,
    pub full_name: String,
    pub logon_script: String,
    pub profile_path: String,
    pub home_directory: String,
    pub home_directory_drive: String,
    pub logon_count: u16,
    pub bad_password_count: u16,
    /// RID of the user in `logon_domain_id`
    pub user_id: u32,
    pub primary_group_id: u32,
    /// RIDs in `logon_domain_id`, with their attributes
    pub group_ids: Vec<(u32, u32)>,
    /// `LOGON_EXTRA_SIDS` (0x20), `LOGON_RESOURCE_GROUPS` (0x200)...
    pub user_flags: u32,
    pub logon_server: String,
    /// NetBIOS name of the domain of the user
    pub logon_domain_name: String,
    pub logon_domain_id: Option<Sid>,
    /// `USER_*` flags of the account ([MS-SAMR] 2.2.1.12)
    pub user_account_control: u32,
    pub sub_auth_status: u32,
    pub last_successful_i_logon: u64,
    pub last_failed_i_logon: u64,
    pub failed_i_logon_count: u32,
    /// SIDs of other domains (universal groups of a forest, SID history, well-known SIDs such as
    /// "authentication authority asserted identity")
    pub extra_sids: Vec<GroupMembership>,
    pub resource_group_domain_sid: Option<Sid>,
    /// RIDs in `resource_group_domain_sid` (domain local groups of the domain of the service)
    pub resource_group_ids: Vec<(u32, u32)>,
}

impl LogonInfo {
    /// `S-…-<user_id>`
    pub fn user_sid(&self) -> Option<Sid> {
        self.logon_domain_id.as_ref().map(|d| d.with_rid(self.user_id))
    }

    /// `S-…-<primary_group_id>`
    pub fn primary_group_sid(&self) -> Option<Sid> {
        self.logon_domain_id.as_ref().map(|d| d.with_rid(self.primary_group_id))
    }

    /// Every group: those of the domain of the user, the extra SIDs, the resource groups.
    pub fn group_sids(&self) -> Vec<GroupMembership> {
        let mut out = Vec::new();
        if let Some(domain) = &self.logon_domain_id {
            out.extend(self.group_ids.iter().map(|(rid, attributes)| GroupMembership {
                sid: domain.with_rid(*rid),
                attributes: *attributes,
            }));
        }
        out.extend(self.extra_sids.iter().cloned());
        if let Some(domain) = &self.resource_group_domain_sid {
            out.extend(self.resource_group_ids.iter().map(|(rid, attributes)| GroupMembership {
                sid: domain.with_rid(*rid),
                attributes: *attributes,
            }));
        }
        out
    }
}

/// `PAC_CLIENT_INFO` ([MS-PAC] 2.7): the client name and the authentication time of the TGT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientInfo {
    pub client_id: u64,
    pub name: String,
}

/// `UPN_DNS_INFO` ([MS-PAC] 2.10)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpnDnsInfo {
    pub upn: String,
    pub dns_domain_name: String,
    /// [`upn_dns_flags`]
    pub flags: u32,
    /// with [`upn_dns_flags::EXTENDED`]
    pub sam_name: Option<String>,
    /// with [`upn_dns_flags::EXTENDED`]
    pub sid: Option<Sid>,
}

/// A buffer of the PAC, as it is.
#[derive(Clone, PartialEq, Eq)]
pub struct PacBuffer {
    pub buffer_type: u32,
    pub data: Vec<u8>,
}

impl fmt::Debug for PacBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PacBuffer({}, {} bytes)", self.buffer_type, self.data.len())
    }
}

/// A decoded PAC. The buffers not decoded (checksums, claims, device info...) are in `buffers`,
/// with all the others.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pac {
    pub logon_info: Option<LogonInfo>,
    pub client_info: Option<ClientInfo>,
    pub upn_dns_info: Option<UpnDnsInfo>,
    /// `PAC_REQUESTOR` ([MS-PAC] 2.15): the SID of the client the TGT was requested for
    pub requestor: Option<Sid>,
    /// `PAC_ATTRIBUTES_INFO` ([MS-PAC] 2.14): `PAC_WAS_REQUESTED` (1), `PAC_WAS_GIVEN_IMPLICITLY` (2)
    pub attributes: Option<u32>,
    pub buffers: Vec<PacBuffer>,
}

fn invalid(what: impl fmt::Display) -> Error {
    Error::new(ErrorKind::InvalidToken, format!("PAC: {what}"))
}

/// Little-endian reader; NDR alignment is relative to the start of `data`.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| invalid("truncated"))?;
        let b = &self.data[self.pos..end];
        self.pos = end;
        Ok(b)
    }

    fn align(&mut self, n: usize) -> Result<()> {
        let pad = (n - self.pos % n) % n;
        self.bytes(pad).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().expect("2 bytes")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().expect("4 bytes")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().expect("8 bytes")))
    }

    /// FILETIME: two DWORDs, low first
    fn filetime(&mut self) -> Result<u64> {
        let low = u64::from(self.u32()?);
        let high = u64::from(self.u32()?);
        Ok(high << 32 | low)
    }

    fn utf16(&mut self, bytes: usize) -> Result<String> {
        if !bytes.is_multiple_of(2) {
            return Err(invalid("odd UTF-16 length"));
        }
        let units: Vec<u16> = self
            .bytes(bytes)?
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16"))
    }

    /// The SID structure: revision, count, 48 bit authority (big endian), sub-authorities.
    fn raw_sid(&mut self) -> Result<Sid> {
        let revision = self.u8()?;
        let count = usize::from(self.u8()?);
        let authority = self.bytes(6)?.iter().fold(0u64, |a, b| a << 8 | u64::from(*b));
        let sub_authorities = (0..count).map(|_| self.u32()).collect::<Result<_>>()?;
        Ok(Sid {
            revision,
            authority,
            sub_authorities,
        })
    }

    /// NDR: a conformance count, bounded so that a forged one can't allocate much.
    fn count(&mut self) -> Result<usize> {
        let n = usize::try_from(self.u32()?).map_err(|_| invalid("count"))?;
        if n > self.data.len() {
            return Err(invalid("count larger than the buffer"));
        }
        Ok(n)
    }

    /// NDR: the deferred conformant varying array of an `RPC_UNICODE_STRING`.
    fn ndr_string(&mut self, length: u16) -> Result<String> {
        self.align(4)?;
        let _max = self.u32()?;
        let offset = self.u32()?;
        let actual = self.count()?;
        if offset != 0 || actual * 2 < usize::from(length) {
            return Err(invalid("unexpected string layout"));
        }
        let s = self.utf16(actual * 2)?;
        // `length` is in bytes, without a terminating null
        Ok(s.chars().take(usize::from(length) / 2).collect())
    }

    /// NDR: an `RPC_SID`, a conformant structure.
    fn ndr_sid(&mut self) -> Result<Sid> {
        self.align(4)?;
        let count = self.count()?;
        let sid = self.raw_sid()?;
        if sid.sub_authorities.len() != count {
            return Err(invalid("SID sub-authority count"));
        }
        Ok(sid)
    }

    /// NDR: an array of `GROUP_MEMBERSHIP`.
    fn ndr_groups(&mut self, expected: u32) -> Result<Vec<(u32, u32)>> {
        self.align(4)?;
        let n = self.count()?;
        if u32::try_from(n).ok() != Some(expected) {
            return Err(invalid("group count"));
        }
        (0..n).map(|_| Ok((self.u32()?, self.u32()?))).collect()
    }
}

/// An `RPC_UNICODE_STRING` before its deferred buffer is read.
struct NdrString {
    length: u16,
    pointer: u32,
}

impl Reader<'_> {
    fn ndr_string_header(&mut self) -> Result<NdrString> {
        let length = self.u16()?;
        let _maximum_length = self.u16()?;
        let pointer = self.u32()?;
        Ok(NdrString { length, pointer })
    }

    fn deferred_string(&mut self, s: &NdrString) -> Result<String> {
        if s.pointer == 0 {
            return Ok(String::new());
        }
        self.ndr_string(s.length)
    }
}

/// `KERB_VALIDATION_INFO`, serialized with the type serialization version 1 of [MS-RPCE] 2.2.6.
fn decode_logon_info(data: &[u8]) -> Result<LogonInfo> {
    let mut r = Reader::new(data);
    // common header: version 1, little endian, 8 bytes, filler
    let (version, endianness, header_len) = (r.u8()?, r.u8()?, r.u16()?);
    if version != 1 || endianness != 0x10 || header_len != 8 {
        return Err(invalid("not a little endian NDR type serialization"));
    }
    r.u32()?;
    // private header: length of the serialized object, filler
    r.u32()?;
    r.u32()?;
    // the referent of the top level pointer
    if r.u32()? == 0 {
        return Err(invalid("null logon information"));
    }

    let mut info = LogonInfo {
        logon_time: r.filetime()?,
        logoff_time: r.filetime()?,
        kick_off_time: r.filetime()?,
        password_last_set: r.filetime()?,
        password_can_change: r.filetime()?,
        password_must_change: r.filetime()?,
        ..LogonInfo::default()
    };
    let effective_name = r.ndr_string_header()?;
    let full_name = r.ndr_string_header()?;
    let logon_script = r.ndr_string_header()?;
    let profile_path = r.ndr_string_header()?;
    let home_directory = r.ndr_string_header()?;
    let home_directory_drive = r.ndr_string_header()?;
    info.logon_count = r.u16()?;
    info.bad_password_count = r.u16()?;
    info.user_id = r.u32()?;
    info.primary_group_id = r.u32()?;
    let group_count = r.u32()?;
    let group_ids = r.u32()?;
    info.user_flags = r.u32()?;
    let _user_session_key = r.bytes(16)?;
    let logon_server = r.ndr_string_header()?;
    let logon_domain_name = r.ndr_string_header()?;
    let logon_domain_id = r.u32()?;
    let _reserved1 = r.bytes(8)?;
    info.user_account_control = r.u32()?;
    info.sub_auth_status = r.u32()?;
    info.last_successful_i_logon = r.filetime()?;
    info.last_failed_i_logon = r.filetime()?;
    info.failed_i_logon_count = r.u32()?;
    let _reserved3 = r.u32()?;
    let sid_count = r.u32()?;
    let extra_sids = r.u32()?;
    let resource_group_domain_sid = r.u32()?;
    let resource_group_count = r.u32()?;
    let resource_group_ids = r.u32()?;

    // the deferred referents, in the order of their pointers
    info.effective_name = r.deferred_string(&effective_name)?;
    info.full_name = r.deferred_string(&full_name)?;
    info.logon_script = r.deferred_string(&logon_script)?;
    info.profile_path = r.deferred_string(&profile_path)?;
    info.home_directory = r.deferred_string(&home_directory)?;
    info.home_directory_drive = r.deferred_string(&home_directory_drive)?;
    if group_ids != 0 {
        info.group_ids = r.ndr_groups(group_count)?;
    }
    info.logon_server = r.deferred_string(&logon_server)?;
    info.logon_domain_name = r.deferred_string(&logon_domain_name)?;
    if logon_domain_id != 0 {
        info.logon_domain_id = Some(r.ndr_sid()?);
    }
    if extra_sids != 0 {
        r.align(4)?;
        let n = r.count()?;
        if u32::try_from(n).ok() != Some(sid_count) {
            return Err(invalid("extra SID count"));
        }
        // the array of KERB_SID_AND_ATTRIBUTES, then the SIDs it points to
        let entries: Vec<(u32, u32)> = (0..n).map(|_| Ok((r.u32()?, r.u32()?))).collect::<Result<_>>()?;
        for (pointer, attributes) in entries {
            if pointer != 0 {
                info.extra_sids.push(GroupMembership {
                    sid: r.ndr_sid()?,
                    attributes,
                });
            }
        }
    }
    if resource_group_domain_sid != 0 {
        info.resource_group_domain_sid = Some(r.ndr_sid()?);
    }
    if resource_group_ids != 0 {
        info.resource_group_ids = r.ndr_groups(resource_group_count)?;
    }
    Ok(info)
}

fn decode_client_info(data: &[u8]) -> Result<ClientInfo> {
    let mut r = Reader::new(data);
    let client_id = r.filetime()?;
    let length = usize::from(r.u16()?);
    let name = r.utf16(length)?;
    Ok(ClientInfo { client_id, name })
}

fn decode_upn_dns_info(data: &[u8]) -> Result<UpnDnsInfo> {
    let mut r = Reader::new(data);
    let field = |length: u16, offset: u16| -> Result<&[u8]> {
        let (start, len) = (usize::from(offset), usize::from(length));
        data.get(start..start + len)
            .ok_or_else(|| invalid("UPN_DNS_INFO offset"))
    };
    let string =
        |length: u16, offset: u16| -> Result<String> { Reader::new(field(length, offset)?).utf16(usize::from(length)) };
    let (upn_len, upn_off) = (r.u16()?, r.u16()?);
    let (dns_len, dns_off) = (r.u16()?, r.u16()?);
    let flags = r.u32()?;
    let mut info = UpnDnsInfo {
        upn: string(upn_len, upn_off)?,
        dns_domain_name: string(dns_len, dns_off)?,
        flags,
        ..UpnDnsInfo::default()
    };
    if flags & upn_dns_flags::EXTENDED != 0 {
        let (sam_len, sam_off) = (r.u16()?, r.u16()?);
        let (sid_len, sid_off) = (r.u16()?, r.u16()?);
        info.sam_name = Some(string(sam_len, sam_off)?);
        info.sid = Some(Sid::from_bytes(field(sid_len, sid_off)?)?);
    }
    Ok(info)
}

/// Decodes a PAC (`PACTYPE`, [MS-PAC] 2.3).
pub fn decode(data: &[u8]) -> Result<Pac> {
    let mut r = Reader::new(data);
    let count = r.count()?;
    let version = r.u32()?;
    if version != 0 {
        return Err(invalid(format!("version {version}")));
    }
    let mut pac = Pac::default();
    for _ in 0..count {
        let buffer_type = r.u32()?;
        let size = usize::try_from(r.u32()?).map_err(|_| invalid("buffer size"))?;
        let offset = usize::try_from(r.u64()?).map_err(|_| invalid("buffer offset"))?;
        let buffer = data
            .get(offset..offset.checked_add(size).ok_or_else(|| invalid("buffer size"))?)
            .ok_or_else(|| invalid("buffer outside the PAC"))?;
        let what = |e: Error| invalid(format!("buffer {buffer_type}: {}", e.description));
        match buffer_type {
            buffer_type::LOGON_INFO => pac.logon_info = Some(decode_logon_info(buffer).map_err(what)?),
            buffer_type::CLIENT_INFO => pac.client_info = Some(decode_client_info(buffer).map_err(what)?),
            buffer_type::UPN_DNS_INFO => pac.upn_dns_info = Some(decode_upn_dns_info(buffer).map_err(what)?),
            buffer_type::REQUESTOR => pac.requestor = Some(Sid::from_bytes(buffer).map_err(what)?),
            buffer_type::ATTRIBUTES_INFO => {
                let mut b = Reader::new(buffer);
                let _flags_length = b.u32().map_err(what)?;
                pac.attributes = Some(b.u32().map_err(what)?);
            }
            _ => {}
        }
        pac.buffers.push(PacBuffer {
            buffer_type,
            data: buffer.to_vec(),
        });
    }
    Ok(pac)
}

/// The PAC in the authorization data of a ticket, if any.
pub fn find(authorization_data: &AuthorizationData) -> Option<Vec<u8>> {
    for element in &authorization_data.0 {
        let ad_type = element.ad_type.0.0.as_slice();
        let data = &element.ad_data.0.0;
        if ad_type == [AD_WIN2K_PAC] || ad_type == [0, AD_WIN2K_PAC] {
            return Some(data.clone());
        }
        if ad_type == [AD_IF_RELEVANT]
            && let Ok(inner) = picky_asn1_der::from_bytes::<AuthorizationData>(data)
            && let Some(pac) = find(&inner)
        {
            return Some(pac);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a PAC as a KDC would, to check the decoder against the layout of the specification.
    #[derive(Default)]
    struct Writer(Vec<u8>);

    impl Writer {
        fn u8(&mut self, v: u8) -> &mut Self {
            self.0.push(v);
            self
        }
        fn u16(&mut self, v: u16) -> &mut Self {
            self.0.extend(v.to_le_bytes());
            self
        }
        fn u32(&mut self, v: u32) -> &mut Self {
            self.0.extend(v.to_le_bytes());
            self
        }
        fn u64(&mut self, v: u64) -> &mut Self {
            self.0.extend(v.to_le_bytes());
            self
        }
        fn align(&mut self, n: usize) -> &mut Self {
            while !self.0.len().is_multiple_of(n) {
                self.0.push(0);
            }
            self
        }
        fn utf16(&mut self, s: &str) -> &mut Self {
            for u in s.encode_utf16() {
                self.u16(u);
            }
            self
        }
        fn raw_sid(&mut self, sid: &Sid) -> &mut Self {
            self.u8(sid.revision)
                .u8(u8::try_from(sid.sub_authorities.len()).unwrap());
            self.0.extend(&sid.authority.to_be_bytes()[2..]);
            for s in &sid.sub_authorities {
                self.u32(*s);
            }
            self
        }
        fn string_header(&mut self, s: &str, pointer: u32) -> &mut Self {
            let n = u16::try_from(s.encode_utf16().count() * 2).unwrap();
            self.u16(n).u16(n).u32(if s.is_empty() { 0 } else { pointer })
        }
        fn string(&mut self, s: &str) -> &mut Self {
            if s.is_empty() {
                return self;
            }
            let n = u32::try_from(s.encode_utf16().count()).unwrap();
            self.align(4).u32(n).u32(0).u32(n).utf16(s)
        }
        fn ndr_sid(&mut self, sid: &Sid) -> &mut Self {
            self.align(4)
                .u32(u32::try_from(sid.sub_authorities.len()).unwrap())
                .raw_sid(sid)
        }
    }

    fn sid(s: &str) -> Sid {
        let parts: Vec<&str> = s.split('-').collect();
        Sid {
            revision: parts[1].parse().unwrap(),
            authority: parts[2].parse().unwrap(),
            sub_authorities: parts[3..].iter().map(|p| p.parse().unwrap()).collect(),
        }
    }

    const DOMAIN: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    fn logon_info() -> Vec<u8> {
        let mut w = Writer::default();
        // headers, top level pointer
        w.u8(1).u8(0x10).u16(8).u32(0xcccc_cccc).u32(0).u32(0).u32(0x0002_0000);
        for t in 0..6u64 {
            w.u64(0x01d0_0000_0000_0000 + t);
        }
        w.string_header("bob", 0x0002_0004)
            .string_header("Bob Smith", 0x0002_0008)
            .string_header("", 0)
            .string_header("", 0)
            .string_header("\\\\srv\\home\\bob", 0x0002_000c)
            .string_header("H:", 0x0002_0010);
        w.u16(42).u16(1).u32(1105).u32(513);
        w.u32(2).u32(0x0002_0014); // groups
        w.u32(0x20 | 0x200); // user flags: extra SIDs, resource groups
        w.0.extend([0u8; 16]);
        w.string_header("DC1", 0x0002_0018).string_header("CORP", 0x0002_001c);
        w.u32(0x0002_0020); // logon domain id
        w.u32(0).u32(0); // reserved1
        w.u32(0x10).u32(0); // user account control, sub auth status
        w.u64(0).u64(0).u32(0).u32(0);
        w.u32(1).u32(0x0002_0024); // extra SIDs
        w.u32(0x0002_0028); // resource group domain SID
        w.u32(1).u32(0x0002_002c); // resource groups
        // deferred
        w.string("bob")
            .string("Bob Smith")
            .string("\\\\srv\\home\\bob")
            .string("H:");
        w.align(4).u32(2).u32(513).u32(7).u32(1107).u32(7);
        w.string("DC1").string("CORP");
        w.ndr_sid(&sid(DOMAIN));
        w.align(4).u32(1).u32(0x0002_0030).u32(7);
        w.ndr_sid(&sid("S-1-18-1"));
        w.ndr_sid(&sid("S-1-5-21-4-5-6"));
        w.align(4).u32(1).u32(1201).u32(0x2000_0007);
        w.0
    }

    fn pac() -> Vec<u8> {
        let logon = logon_info();
        let mut client = Writer::default();
        client.u64(0x01d0_0000_0000_0001).u16(6).utf16("bob");
        let mut upn = Writer::default();
        // UPN at 24, DNS domain after it, SAM name, SID
        let (u, d, s) = ("bob@corp.example.org", "CORP.EXAMPLE.ORG", "bob");
        let (ul, dl, sl) = (
            u16::try_from(u.len() * 2).unwrap(),
            u16::try_from(d.len() * 2).unwrap(),
            u16::try_from(s.len() * 2).unwrap(),
        );
        let user_sid = sid(&format!("{DOMAIN}-1105"));
        let sid_len = 8 + 4 * u16::try_from(user_sid.sub_authorities.len()).unwrap();
        upn.u16(ul).u16(24).u16(dl).u16(24 + ul).u32(upn_dns_flags::EXTENDED);
        upn.u16(sl).u16(24 + ul + dl).u16(sid_len).u16(24 + ul + dl + sl);
        upn.u32(0);
        upn.utf16(u).utf16(d).utf16(s).raw_sid(&user_sid);
        let mut requestor = Writer::default();
        requestor.raw_sid(&user_sid);
        let mut attributes = Writer::default();
        attributes.u32(2).u32(1);

        let buffers: Vec<(u32, Vec<u8>)> = vec![
            (buffer_type::LOGON_INFO, logon),
            (buffer_type::CLIENT_INFO, client.0),
            (buffer_type::UPN_DNS_INFO, upn.0),
            (buffer_type::REQUESTOR, requestor.0),
            (buffer_type::ATTRIBUTES_INFO, attributes.0),
            (buffer_type::SERVER_CHECKSUM, vec![0x10, 0, 0, 0, 1, 2, 3, 4]),
        ];
        let mut w = Writer::default();
        w.u32(u32::try_from(buffers.len()).unwrap()).u32(0);
        let mut offset = 8 + 16 * buffers.len();
        for (t, data) in &buffers {
            w.u32(*t)
                .u32(u32::try_from(data.len()).unwrap())
                .u64(u64::try_from(offset).unwrap());
            offset = (offset + data.len()).div_ceil(8) * 8;
        }
        for (_, data) in &buffers {
            w.align(8);
            w.0.extend(data);
        }
        w.0
    }

    #[test]
    fn decode_pac() {
        let pac = decode(&pac()).unwrap();
        let info = pac.logon_info.as_ref().unwrap();
        assert_eq!(info.effective_name, "bob");
        assert_eq!(info.full_name, "Bob Smith");
        assert_eq!(info.logon_script, "");
        assert_eq!(info.home_directory, "\\\\srv\\home\\bob");
        assert_eq!(info.home_directory_drive, "H:");
        assert_eq!((info.logon_count, info.bad_password_count), (42, 1));
        assert_eq!(info.logon_server, "DC1");
        assert_eq!(info.logon_domain_name, "CORP");
        assert_eq!(info.user_account_control, 0x10);
        assert_eq!(info.logon_time, 0x01d0_0000_0000_0000);
        assert_eq!(info.user_sid().unwrap().to_string(), format!("{DOMAIN}-1105"));
        assert_eq!(info.primary_group_sid().unwrap().to_string(), format!("{DOMAIN}-513"));
        let groups: Vec<String> = info.group_sids().iter().map(|g| g.sid.to_string()).collect();
        assert_eq!(
            groups,
            [
                format!("{DOMAIN}-513"),
                format!("{DOMAIN}-1107"),
                "S-1-18-1".to_string(),
                "S-1-5-21-4-5-6-1201".to_string()
            ]
        );
        assert_eq!(
            info.group_sids()[3].attributes & group_attributes::RESOURCE,
            group_attributes::RESOURCE
        );

        assert_eq!(pac.client_info.as_ref().unwrap().name, "bob");
        let upn = pac.upn_dns_info.as_ref().unwrap();
        assert_eq!(upn.upn, "bob@corp.example.org");
        assert_eq!(upn.dns_domain_name, "CORP.EXAMPLE.ORG");
        assert_eq!(upn.sam_name.as_deref(), Some("bob"));
        assert_eq!(upn.sid.as_ref().unwrap().to_string(), format!("{DOMAIN}-1105"));
        assert_eq!(pac.requestor.as_ref().unwrap().to_string(), format!("{DOMAIN}-1105"));
        assert_eq!(pac.attributes, Some(1));
        assert_eq!(pac.buffers.len(), 6);
        assert_eq!(pac.buffers[5].buffer_type, buffer_type::SERVER_CHECKSUM);
    }

    #[test]
    fn invalid_pacs() {
        let good = pac();
        for n in [0, 4, 8, 20, good.len() / 2, good.len() - 1] {
            assert!(decode(&good[..n]).is_err(), "{n}");
        }
        // a count larger than the PAC
        let mut huge = good.clone();
        huge[..4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(decode(&huge).is_err());
        // a big endian NDR stream
        let mut be = good.clone();
        let logon_offset = usize::try_from(u64::from_le_bytes(good[16..24].try_into().unwrap())).unwrap();
        be[logon_offset + 1] = 0;
        assert!(decode(&be).is_err());
    }

    #[test]
    fn sid_display() {
        assert_eq!(sid("S-1-5-32-544").to_string(), "S-1-5-32-544");
        let big = Sid {
            revision: 1,
            authority: 0x1234_5678_9abc,
            sub_authorities: vec![1],
        };
        assert_eq!(big.to_string(), "S-1-0x123456789ABC-1");
    }
}
