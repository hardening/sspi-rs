use picky_krb::constants::error_codes::KRB_AP_ERR_SKEW;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{KrbResult, ResultExt, Ticket};
use picky_krb::messages::{AsRep, KdcReqBody, TgtReq};
use rand::rngs::{StdRng, SysRng};
use rand_core::SeedableRng as _;
use time::OffsetDateTime;

use crate::generator::YieldPointLocal;
use crate::kerberos::TGT_SERVICE_NAME;
use std::fmt;
use std::time::{Duration, SystemTime};

use crate::generator::{Generator, NetworkRequest};
use crate::kerberos::ServerProperties;
use crate::kerberos::client::extractors::{
    decrypt_as_rep, extract_encryption_params_from_as_rep_with_salt, extract_preauth_salt,
};
use crate::kerberos::client::generators::{
    GenerateAsPaDataOptions, GenerateAsReqOptions, GenerateKeytabPaDataOptions, generate_as_req,
    generate_as_req_kdc_body, generate_nonce,
};
use crate::kerberos::client::kdc::as_exchange::clock_offset_from_error;
use crate::kerberos::client::principal::{
    ClientPrincipalName, get_client_principal_name, get_client_principal_name_type, get_client_principal_realm,
};
use crate::kerberos::pa_datas::AsReqPaDataOptions;
use crate::kerberos::utils::serialize_message;
use crate::{ClientRequestFlags, CredentialsBuffers, Error, ErrorKind, Kerberos, KerberosConfig, Result, Secret};

/// A TGT of the service principal, for Kerberos user to user: the client asks the KDC for a
/// ticket encrypted with its session key.
#[derive(Clone)]
pub struct ServiceTgt {
    pub ticket: Ticket,
    pub session_key: Secret<Vec<u8>>,
    /// when the TGT expires
    pub end_time: SystemTime,
    pub realm: String,
}

impl fmt::Debug for ServiceTgt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceTgt")
            .field("realm", &self.realm)
            .field("end_time", &self.end_time)
            .finish_non_exhaustive()
    }
}

/// Gives the Kerberos server the TGT of its service principal for user to user, instead of an AS
/// exchange in each security context: a cache, refreshed when needed, shared by the contexts.
pub trait ServiceTgtProvider: Send + Sync + fmt::Debug {
    fn service_tgt(&self) -> Result<ServiceTgt>;
}

/// Asks the KDC of `credentials` for a TGT (an AS exchange), outside of any security context: for
/// a [`ServiceTgtProvider`]. The generator yields the network requests to the KDC.
pub fn request_service_tgt(
    config: KerberosConfig,
    credentials: CredentialsBuffers,
) -> Generator<'static, NetworkRequest, Result<Vec<u8>>, Result<ServiceTgt>> {
    Generator::new(move |mut yield_point| async move {
        let properties = ServerProperties::new(&[], None, Duration::from_secs(300), None)?;
        let mut kerberos = Kerberos::new_server_from_config(config, properties)?;
        as_service_tgt(&mut kerberos, &credentials, &mut yield_point).await
    })
}

/// Requests the TGT ticket from KDC.
///
/// Basically, it performs the AS exchange (or asks the [`ServiceTgtProvider`]), saves the session
/// key, and returns the ticket.
pub(crate) async fn request_tgt(
    server: &mut Kerberos,
    credentials: Option<&CredentialsBuffers>,
    tgt_req: &TgtReq,
    yield_point: &mut YieldPointLocal,
) -> Result<Ticket> {
    let server_properties = server.server.as_ref().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidHandle,
            "Kerberos server properties are not initialized",
        )
    })?;
    let service_name = &server_properties.service_name;
    // the name components only: clients name the service as a host (NT-SRV-HST) as often as a
    // service instance (NT-SRV-INST), and by any of its principals
    if !server_properties.is_service_name(&tgt_req.server_name.0) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid ticket service name ({:?}): Kerberos server is configured for {:?}",
                tgt_req.server_name.0, service_name
            ),
        ));
    }

    let tgt = match (server_properties.tgt_provider.clone(), credentials) {
        (Some(provider), _) => provider.service_tgt()?,
        (None, Some(credentials)) => as_service_tgt(server, credentials, yield_point).await?,
        (None, None) => {
            return Err(Error::new(
                ErrorKind::IncompleteCredentials,
                "KRB5 U2U has been negotiated (requested by the client) but the user credentials are not preset in Kerberos server configuration",
            ));
        }
    };
    server.realm = Some(tgt.realm.clone());
    let server_props = server.server.as_mut().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidHandle,
            "Kerberos server properties are not initialized",
        )
    })?;
    server_props.ticket_decryption_key = Some(tgt.session_key);

    Ok(tgt.ticket)
}

/// The AS exchange of the service principal: its TGT.
async fn as_service_tgt(
    server: &mut Kerberos,
    credentials: &CredentialsBuffers,
    yield_point: &mut YieldPointLocal,
) -> Result<ServiceTgt> {
    // A keytab gives the long-term key of the service principal directly: the usual setup of a
    // host (computer) account, whose password nobody knows.
    let (username, password, realm, cname_type) = match credentials {
        CredentialsBuffers::AuthIdentity(auth_identity) => {
            let username = auth_identity.user.to_string();
            let domain = auth_identity.domain.to_string();
            let password = auth_identity.password.as_ref().as_ref().to_string();

            let realm = get_client_principal_realm(&username, &domain);
            let cname_type = get_client_principal_name_type(&username, &domain);

            (username, Some(password), realm, cname_type)
        }
        #[cfg(feature = "scard")]
        CredentialsBuffers::SmartCard(_) => {
            return Err(Error::new(
                ErrorKind::UnsupportedPreAuth,
                "smart card credentials are not supported in Kerberos application server",
            ));
        }
        CredentialsBuffers::Keytab(keytab) => {
            let ClientPrincipalName {
                name,
                realm_domain,
                name_type,
            } = get_client_principal_name(&keytab.principal);
            let realm = get_client_principal_realm(name, realm_domain);

            (name.to_owned(), None, realm, name_type)
        }
    };
    server.realm = Some(realm.clone());

    let mut rand = StdRng::try_from_rng(&mut SysRng)?;
    let nonce = generate_nonce(&mut rand);
    let options = GenerateAsReqOptions {
        realm: &realm,
        username: &username,
        cname_type,
        snames: &[TGT_SERVICE_NAME, &realm],
        nonce,
        hostname: &server.config.client_computer_name,
        context_requirements: ClientRequestFlags::empty(),
    };
    let kdc_req_body = generate_as_req_kdc_body(&options)?;

    let pa_data_options = match (credentials, &password) {
        (CredentialsBuffers::AuthIdentity(auth_identity), Some(password)) => {
            let domain = auth_identity.domain.to_string();
            let salt = format!("{domain}{username}").into_bytes();

            AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                password,
                salt,
                enc_params: server.encryption_params.clone(),
                with_pre_auth: false,
            })
        }
        (CredentialsBuffers::Keytab(keytab), _) => AsReqPaDataOptions::Keytab(GenerateKeytabPaDataOptions {
            key: keytab.key.clone(),
            key_enctype: keytab.key_enctype.clone(),
            with_pre_auth: false,
        }),
        _ => {
            return Err(Error::new(
                ErrorKind::UnsupportedPreAuth,
                "unsupported credentials in Kerberos application server",
            ));
        }
    };

    let (as_rep, preauth_salt) = as_exchange(server, yield_point, &kdc_req_body, pa_data_options).await?;

    debug!("AS exchange finished successfully.");

    server.realm = Some(as_rep.0.crealm.0.to_string());

    let (encryption_type, salt) = extract_encryption_params_from_as_rep_with_salt(&as_rep, &preauth_salt)?;

    let encryption_type = CipherSuite::try_from(usize::from(encryption_type))?;
    server.encryption_params.encryption_type = Some(encryption_type.clone());

    // the long-term key the KDC encrypted the reply with
    let key = match (credentials, &password) {
        (CredentialsBuffers::Keytab(keytab), _) => keytab.key.clone(),
        (_, password) => Secret::new(
            encryption_type
                .cipher()
                .generate_key_from_password(password.as_deref().unwrap_or_default().as_bytes(), salt.as_bytes())?,
        ),
    };
    let part = decrypt_as_rep(&as_rep, key.as_ref(), &server.encryption_params)?;
    let end_time = OffsetDateTime::try_from(part.end_time.0.0)
        .map_err(|e| Error::new(ErrorKind::InvalidToken, format!("TGT end time: {e:?}")))?;

    Ok(ServiceTgt {
        ticket: as_rep.0.ticket.0,
        session_key: part.key.0.key_value.0.to_vec().into(),
        end_time: SystemTime::from(end_time),
        realm: as_rep.0.crealm.0.to_string(),
    })
}

/// Performs the AS exchange as specified in [RFC 4120, section 3.1](https://www.rfc-editor.org/rfc/rfc4120#section-3.1).
///
/// On a KDC clock-skew error, retries pre-authentication once using the server
/// time in the error. The offset is kept on the client context for subsequent
/// TGS and AP authenticators; other errors are returned without retrying.
pub(crate) async fn as_exchange(
    client: &mut Kerberos,
    yield_point: &mut YieldPointLocal,
    kdc_req_body: &KdcReqBody,
    mut pa_data_options: AsReqPaDataOptions<'_>,
) -> Result<(AsRep, String)> {
    pa_data_options.with_pre_auth(false);
    let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;
    let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

    let response = client.send(yield_point, &serialize_message(&as_req)?).await?;

    // first 4 bytes are message len. skipping them
    {
        if response.len() < 4 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        }

        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

        if as_rep.is_ok() {
            error!("KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected.");

            return Err(Error::new(
                ErrorKind::InvalidToken,
                "KDC server should not process AS_REQ without the pa-pac data",
            ));
        }

        if let Some(correct_salt) = extract_preauth_salt(
            &as_rep.unwrap_err(),
            kdc_req_body.realm.0.0.as_utf8(),
            kdc_req_body
                .cname
                .0
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "missing client name in AS-REQ"))?,
        )? {
            debug!("salt extracted successfully from the KRB_ERROR");

            pa_data_options.with_salt(correct_salt.into_bytes());
        }
    }

    pa_data_options.with_pre_auth(true);
    let mut retried_skew = false;
    loop {
        let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;
        let as_req = generate_as_req(pa_datas, kdc_req_body.clone());
        let response = client.send(yield_point, &serialize_message(&as_req)?).await?;
        let received_at = OffsetDateTime::now_utc();

        if response.len() < 4 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        }

        // first 4 bytes are message len. skipping them
        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;
        match as_rep {
            Ok(as_rep) => {
                return Ok((as_rep, String::from_utf8_lossy(pa_data_options.salt()).into_owned()));
            }
            Err(err) if !retried_skew && err.0.error_code.0 == KRB_AP_ERR_SKEW => {
                client.clock_offset = clock_offset_from_error(&err, received_at)?;
                retried_skew = true;
                debug!(offset = ?client.clock_offset, "Retrying AS exchange with KDC clock offset");
            }
            Err(err) => {
                error!(?err, "AS exchange error");
                return Err(err.into());
            }
        }
    }
}
