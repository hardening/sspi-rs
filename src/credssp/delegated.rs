//! The credentials a CredSSP client delegates to the server at the end of the exchange
//! ([MS-CSSP] 2.2.1.2), for the server to log the user on: a password, a smart card, or the logon
//! credential of Remote Credential Guard, which keeps the user's secrets on the client.
//!
//! [MS-CSSP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/

use std::fmt;

use picky_krb::constants::cred_ssp::{TS_PASSWORD_CREDS, TS_REMOTE_GUARD_CREDS, TS_SMART_CARD_CREDS};
use picky_krb::credssp::{
    TsCredentials, TsPasswordCreds, TsRemoteGuardCreds, TsRemoteGuardPackageCred, TsSmartCardCreds,
};

use crate::{Error, ErrorKind, Result, Secret};

/// A package credential of Remote Credential Guard ([MS-CSSP] 2.2.1.2.3.1): `Kerberos` with a
/// `KERB_TICKET_LOGON`, `NTLM` with an `NTLM_SUPPLEMENTAL_CREDENTIAL`...
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteGuardPackage {
    pub package_name: String,
    pub cred_buffer: Vec<u8>,
}

impl fmt::Debug for RemoteGuardPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RemoteGuardPackage({}, {} bytes)",
            self.package_name,
            self.cred_buffer.len()
        )
    }
}

/// What the client delegated (`TSCredentials`).
#[derive(Clone)]
pub enum DelegatedCredentials {
    /// `TSPasswordCreds`
    Password {
        user: String,
        domain: String,
        password: Secret<String>,
    },
    /// `TSPasswordCreds` with empty fields: Restricted Admin mode, nothing is delegated
    RestrictedAdmin,
    /// `TSSmartCardCreds`: the PIN and the card the client logged on with, for the server to log
    /// the user on with the card, redirected
    SmartCard {
        pin: Secret<String>,
        key_spec: u32,
        card_name: Option<String>,
        reader_name: Option<String>,
        container_name: Option<String>,
        csp_name: Option<String>,
        user_hint: Option<String>,
        domain_hint: Option<String>,
    },
    /// `TSRemoteGuardCreds`: the logon credential of Remote Credential Guard, and supplemental
    /// ones; the server then asks the client for the Kerberos operations (MS-RDPEAR)
    RemoteGuard {
        logon: RemoteGuardPackage,
        supplemental: Vec<RemoteGuardPackage>,
    },
}

impl DelegatedCredentials {
    /// `password`, `restrictedAdmin`, `smartCard`, `remoteGuard`
    pub fn kind(&self) -> &'static str {
        match self {
            DelegatedCredentials::Password { .. } => "password",
            DelegatedCredentials::RestrictedAdmin => "restrictedAdmin",
            DelegatedCredentials::SmartCard { .. } => "smartCard",
            DelegatedCredentials::RemoteGuard { .. } => "remoteGuard",
        }
    }
}

impl fmt::Debug for DelegatedCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelegatedCredentials::Password { user, domain, .. } => write!(f, "Password({domain}\\{user})"),
            DelegatedCredentials::RestrictedAdmin => write!(f, "RestrictedAdmin"),
            DelegatedCredentials::SmartCard {
                reader_name,
                card_name,
                user_hint,
                ..
            } => write!(f, "SmartCard({card_name:?} in {reader_name:?}, user {user_hint:?})"),
            DelegatedCredentials::RemoteGuard { logon, supplemental } => {
                write!(f, "RemoteGuard({logon:?}, {supplemental:?})")
            }
        }
    }
}

fn invalid(what: impl fmt::Display) -> Error {
    Error::new(ErrorKind::InvalidToken, format!("TSCredentials: {what}"))
}

/// The UTF-16LE strings of CredSSP.
fn utf16(data: &[u8]) -> Result<String> {
    if !data.len().is_multiple_of(2) {
        return Err(invalid("odd UTF-16 length"));
    }
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16"))
}

fn package(p: TsRemoteGuardPackageCred) -> Result<RemoteGuardPackage> {
    Ok(RemoteGuardPackage {
        package_name: utf16(&p.package_name.0.0)?,
        cred_buffer: p.cred_buffer.0.0,
    })
}

/// Decodes a `TSCredentials`, whatever its type.
pub fn read_delegated_credentials(data: &[u8]) -> Result<DelegatedCredentials> {
    let credentials: TsCredentials = picky_asn1_der::from_bytes(data)?;
    let inner = &credentials.credentials.0.0;
    let optional = |v: Option<&[u8]>| v.map(utf16).transpose();
    match credentials.cred_type.0.0.as_slice() {
        [TS_PASSWORD_CREDS] => {
            let p: TsPasswordCreds = picky_asn1_der::from_bytes(inner)?;
            let (user, domain, password) = (
                utf16(&p.user_name.0.0)?,
                utf16(&p.domain_name.0.0)?,
                utf16(&p.password.0.0)?,
            );
            Ok(if user.is_empty() && domain.is_empty() && password.is_empty() {
                DelegatedCredentials::RestrictedAdmin
            } else {
                DelegatedCredentials::Password {
                    user,
                    domain,
                    password: password.into(),
                }
            })
        }
        [TS_SMART_CARD_CREDS] => {
            let c: TsSmartCardCreds = picky_asn1_der::from_bytes(inner)?;
            let csp = c.csp_data.0;
            let key_spec = csp
                .key_spec
                .0
                .as_unsigned_bytes_be()
                .iter()
                .fold(0u32, |a, b| a << 8 | u32::from(*b));
            Ok(DelegatedCredentials::SmartCard {
                pin: utf16(&c.pin.0.0)?.into(),
                key_spec,
                card_name: optional(csp.card_name.0.as_ref().map(|v| v.0.0.as_slice()))?,
                reader_name: optional(csp.reader_name.0.as_ref().map(|v| v.0.0.as_slice()))?,
                container_name: optional(csp.container_name.0.as_ref().map(|v| v.0.0.as_slice()))?,
                csp_name: optional(csp.csp_name.0.as_ref().map(|v| v.0.0.as_slice()))?,
                user_hint: optional(c.user_hint.0.as_ref().map(|v| v.0.0.as_slice()))?,
                domain_hint: optional(c.domain_hint.0.as_ref().map(|v| v.0.0.as_slice()))?,
            })
        }
        [TS_REMOTE_GUARD_CREDS] => {
            let c: TsRemoteGuardCreds = picky_asn1_der::from_bytes(inner)?;
            Ok(DelegatedCredentials::RemoteGuard {
                logon: package(c.logon_cred.0)?,
                supplemental: c
                    .supplemental_creds
                    .0
                    .map(|s| s.0.0.into_iter().map(package).collect::<Result<_>>())
                    .transpose()?
                    .unwrap_or_default(),
            })
        }
        other => Err(invalid(format!("credential type {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use picky_asn1::wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
        ExplicitContextTag4, IntegerAsn1, OctetStringAsn1, Optional,
    };
    use picky_krb::credssp::TsCspDataDetail;

    use super::*;

    fn u16le(s: &str) -> OctetStringAsn1 {
        OctetStringAsn1::from(s.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>())
    }

    fn credentials(cred_type: u8, inner: Vec<u8>) -> Vec<u8> {
        picky_asn1_der::to_vec(&TsCredentials {
            cred_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![cred_type])),
            credentials: ExplicitContextTag1::from(OctetStringAsn1::from(inner)),
        })
        .unwrap()
    }

    fn password(user: &str, domain: &str, password: &str) -> Vec<u8> {
        credentials(
            TS_PASSWORD_CREDS,
            picky_asn1_der::to_vec(&TsPasswordCreds {
                domain_name: ExplicitContextTag0::from(u16le(domain)),
                user_name: ExplicitContextTag1::from(u16le(user)),
                password: ExplicitContextTag2::from(u16le(password)),
            })
            .unwrap(),
        )
    }

    #[test]
    fn password_and_restricted_admin() {
        match read_delegated_credentials(&password("bob", "CORP", "s3cret")).unwrap() {
            DelegatedCredentials::Password { user, domain, password } => {
                assert_eq!(
                    (user.as_str(), domain.as_str(), password.as_ref().as_str()),
                    ("bob", "CORP", "s3cret")
                );
            }
            other => panic!("{other:?}"),
        }
        let restricted = read_delegated_credentials(&password("", "", "")).unwrap();
        assert_eq!(restricted.kind(), "restrictedAdmin");
    }

    #[test]
    fn smart_card() {
        let card = TsSmartCardCreds {
            pin: ExplicitContextTag0::from(u16le("1234")),
            csp_data: ExplicitContextTag1::from(TsCspDataDetail {
                key_spec: ExplicitContextTag0::from(IntegerAsn1::from(vec![1])),
                card_name: Optional::from(Some(ExplicitContextTag1::from(u16le("YubiKey")))),
                reader_name: Optional::from(Some(ExplicitContextTag2::from(u16le("Yubico 0")))),
                container_name: Optional::from(None),
                csp_name: Optional::from(Some(ExplicitContextTag4::from(u16le(
                    "Microsoft Base Smart Card Crypto Provider",
                )))),
            }),
            user_hint: Optional::from(Some(ExplicitContextTag2::from(u16le("bob")))),
            domain_hint: Optional::from(Some(ExplicitContextTag3::from(u16le("CORP")))),
        };
        let data = credentials(TS_SMART_CARD_CREDS, picky_asn1_der::to_vec(&card).unwrap());
        match read_delegated_credentials(&data).unwrap() {
            DelegatedCredentials::SmartCard {
                pin,
                key_spec,
                card_name,
                reader_name,
                container_name,
                user_hint,
                domain_hint,
                ..
            } => {
                assert_eq!(pin.as_ref(), "1234");
                assert_eq!(key_spec, 1);
                assert_eq!(card_name.as_deref(), Some("YubiKey"));
                assert_eq!(reader_name.as_deref(), Some("Yubico 0"));
                assert_eq!(container_name, None);
                assert_eq!(
                    (user_hint.as_deref(), domain_hint.as_deref()),
                    (Some("bob"), Some("CORP"))
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn remote_guard() {
        let package = |name: &str, buffer: &[u8]| TsRemoteGuardPackageCred {
            package_name: ExplicitContextTag0::from(u16le(name)),
            cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(buffer.to_vec())),
        };
        let guard = TsRemoteGuardCreds {
            logon_cred: ExplicitContextTag0::from(package("Kerberos", &[1, 2, 3])),
            supplemental_creds: Optional::from(Some(ExplicitContextTag1::from(Asn1SequenceOf::from(vec![package(
                "NTLM",
                &[4, 5],
            )])))),
        };
        let data = credentials(TS_REMOTE_GUARD_CREDS, picky_asn1_der::to_vec(&guard).unwrap());
        match read_delegated_credentials(&data).unwrap() {
            DelegatedCredentials::RemoteGuard { logon, supplemental } => {
                assert_eq!(logon.package_name, "Kerberos");
                assert_eq!(logon.cred_buffer, [1, 2, 3]);
                assert_eq!(supplemental.len(), 1);
                assert_eq!(supplemental[0].package_name, "NTLM");
            }
            other => panic!("{other:?}"),
        }
        assert!(read_delegated_credentials(&credentials(9, vec![])).is_err());
        assert!(read_delegated_credentials(b"junk").is_err());
    }
}
