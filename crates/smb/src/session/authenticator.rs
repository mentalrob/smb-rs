use std::net::SocketAddr;
use std::sync::Arc;

use crate::Error;
use crate::connection::AuthMethodsConfig;
use crate::connection::connection_info::ConnectionInfo;
use maybe_async::*;
use sspi::{
    AcquireCredentialsHandleResult, AuthIdentity, BufferType, ClientRequestFlags, CredentialUse,
    DataRepresentation, InitializeSecurityContextResult, Negotiate, SecurityBuffer, Sspi,
    ntlm::NtlmConfig,
};
use sspi::{CredentialsBuffers, NegotiateConfig, SspiImpl, Username};

#[derive(Debug)]
pub struct Authenticator {
    server_hostname: String,
    user_name: Username,

    ssp: Negotiate,
    cred_handle: AcquireCredentialsHandleResult<Option<CredentialsBuffers>>,
    current_state: Option<InitializeSecurityContextResult>,

    server_address: SocketAddr,
}

impl Authenticator {
    pub fn build(
        identity: AuthIdentity,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Authenticator> {
        log::debug!("Building authenticator for user: {:?}, server: {}, {:?}", identity.username, conn_info.server_name, conn_info.server_address);
        let client_computer_name = conn_info
            .config
            .client_name
            .as_ref()
            .unwrap_or(&String::from("smb-rs"))
            .clone();
        log::debug!("Using client computer name: {}", client_computer_name);
        let available_ssp_pkgs = Self::get_available_ssp_pkgs(&conn_info.config.auth_methods);
        log::debug!("Available SSP packages: {}", available_ssp_pkgs);
        
        let mut negotiate_ssp = Negotiate::new_client(NegotiateConfig::new(
            Box::new(NtlmConfig::default()),
            Some(available_ssp_pkgs),
            client_computer_name,
        ))?;
        log::debug!("Created Negotiate SSP client");
        let user_name = identity.username.clone();

        log::debug!("Acquiring credentials handle for outbound authentication");
        let cred_handle = negotiate_ssp
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&sspi::Credentials::AuthIdentity(identity.clone()))
            .execute(&mut negotiate_ssp)?;
        log::debug!("Successfully acquired credentials handle");

        log::debug!("Authenticator built successfully for user: {:?}", user_name);
        Ok(Authenticator {
            server_hostname: conn_info.server_name.clone(),
            ssp: negotiate_ssp,
            cred_handle,
            current_state: None,
            user_name,
            server_address: conn_info.server_address,
        })
    }

    pub fn user_name(&self) -> &Username {
        &self.user_name
    }

    pub fn is_authenticated(&self) -> crate::Result<bool> {
        if self.current_state.is_none() {
            log::debug!("Authentication status: false (no current state)");
            return Ok(false);
        }
        let is_auth = self.current_state.as_ref().unwrap().status == sspi::SecurityStatus::Ok;
        log::debug!("Authentication status: {} (current status: {:?})", is_auth, self.current_state.as_ref().unwrap().status);
        Ok(is_auth)
    }

    pub fn session_key(&self) -> crate::Result<[u8; 16]> {
        log::debug!("Retrieving session key from SSP context");
        // Use the first 16 bytes of the session key.
        let key_info = self.ssp.query_context_session_key()?;
        let full_key_len = key_info.session_key.as_ref().len();
        log::debug!("Retrieved session key of {} bytes, using first 16 bytes", full_key_len);
        let k = &key_info.session_key.as_ref()[..16];
        Ok(k.try_into().unwrap())
    }

    fn make_sspi_target_name(server_fqdn: &str) -> String {
        format!("cifs/{server_fqdn}")
    }

    fn get_context_requirements() -> ClientRequestFlags {
        ClientRequestFlags::DELEGATE
            | ClientRequestFlags::MUTUAL_AUTH
            | ClientRequestFlags::INTEGRITY
            | ClientRequestFlags::FRAGMENT_TO_FIT
            | ClientRequestFlags::USE_SESSION_KEY
    }

    const SSPI_REQ_DATA_REPRESENTATION: DataRepresentation = DataRepresentation::Native;

    #[maybe_async]
    pub async fn next(&mut self, gss_token: &[u8]) -> crate::Result<Vec<u8>> {
        log::debug!("Processing authentication token of {} bytes", gss_token.len());
        
        if self.is_authenticated()? {
            log::debug!("Authentication already completed, rejecting new token");
            return Err(Error::InvalidState("Authentication already done.".into()));
        }

        if self.current_state.is_some()
            && self.current_state.as_ref().unwrap().status != sspi::SecurityStatus::ContinueNeeded
        {
            let current_status = &self.current_state.as_ref().unwrap().status;
            log::debug!("Invalid authentication state: {:?}, expected ContinueNeeded", current_status);
            return Err(Error::InvalidState(
                "NTLM GSS session is not in a state to process next token.".into(),
            ));
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let target_name = Self::make_sspi_target_name(&self.server_hostname);
        log::debug!("Using SSPI target name: {}", target_name);
        let context_requirements = Self::get_context_requirements();
        log::debug!("Context requirements: {:?}", context_requirements);
        
        let mut builder = self
            .ssp
            .initialize_security_context()
            .with_credentials_handle(&mut self.cred_handle.credentials_handle)
            .with_context_requirements(context_requirements)
            .with_target_data_representation(Self::SSPI_REQ_DATA_REPRESENTATION)
            .with_output(&mut output_buffer);

        if cfg!(feature = "kerberos") {
            log::debug!("Kerberos feature enabled, setting target name");
            builder = builder.with_target_name(&target_name)
        } else {
            log::debug!("Kerberos feature disabled");
        }

        let mut input_buffers = vec![];
        input_buffers.push(SecurityBuffer::new(gss_token.to_owned(), BufferType::Token));
        log::debug!("Prepared input buffer with {} bytes", gss_token.len());
        builder = builder.with_input(&mut input_buffers);

        let result = {
            log::debug!("Initializing security context");
            let mut generator = self.ssp.initialize_security_context_impl(&mut builder)?;
            log::debug!("Security context initialized");
            // Kerberos requires a network client to be set up.
            // We avoid compiling with the network client if kerberos is not enabled,
            // so be sure to avoid using it in that case.
            // while default, sync network client is supported in sspi,
            // an implementation of the async one had to be added in this module.
            #[cfg(feature = "kerberos")]
            {
                use super::sspi_network_client::ReqwestNetworkClient;
                log::debug!("Resolving with Kerberos network client");
                #[cfg(feature = "async")]
                {
                    use std::net::IpAddr;

                    let server_address = self.server_address.ip();
                    if let IpAddr::V4(server_address) = server_address {
                        generator
                            .resolve_with_async_client(&mut ReqwestNetworkClient::new(server_address))
                            .await?
                    } else {
                        return Err(Error::InvalidState("Server address is not an IPv4 address.".into()));
                    }
                }
                #[cfg(not(feature = "async"))]
                {
                    use std::net::IpAddr;

                    let server_address = self.server_address.ip();
                    if let IpAddr::V4(server_address) = server_address {
                        generator.resolve_with_client(&ReqwestNetworkClient::new(server_address))?;
                    } else {
                        return Err(Error::InvalidState("Server address is not an IPv4 address.".into()));
                    }
                }
            }
            #[cfg(not(feature = "kerberos"))]
            {
                log::debug!("Resolving without Kerberos network client");
                generator.resolve_to_result()?
            }
        };

        log::debug!("Security context result status: {:?}", result.status);
        self.current_state = Some(result);

        let output_buffer = output_buffer
            .pop()
            .ok_or_else(|| Error::InvalidState("SSPI output buffer is empty.".to_string()))?
            .buffer;
        
        log::debug!("Returning authentication token of {} bytes", output_buffer.len());
        Ok(output_buffer)
    }

    fn get_available_ssp_pkgs(config: &AuthMethodsConfig) -> String {
        log::debug!("Configuring SSP packages - NTLM: {}, Kerberos: {}", config.ntlm, config.kerberos);
        
        let krb_pku2u_config = if cfg!(feature = "kerberos") && config.kerberos {
            log::debug!("Kerberos enabled in config and feature");
            "kerberos,!pku2u"
        } else {
            log::debug!("Kerberos disabled (feature: {}, config: {})", cfg!(feature = "kerberos"), config.kerberos);
            "!kerberos,!pku2u"
        };
        let ntlm_config = if config.ntlm { 
            log::debug!("NTLM enabled");
            "ntlm" 
        } else { 
            log::debug!("NTLM disabled");
            "!ntlm" 
        };
        let result = format!("{ntlm_config},{krb_pku2u_config}");
        log::debug!("Final SSP package configuration: {}", result);
        result
    }
}
