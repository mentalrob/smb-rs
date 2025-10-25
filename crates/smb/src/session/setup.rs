use crate::session::authenticator::Authenticator;

use super::*;

/// Session setup processor.
///
/// This is an internal structure.
/// It is assume that T is properly implemented and tested in-crate,
/// and so, the wide use of unwrap() is acceptable.
pub(crate) struct SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    last_setup_response: Option<SessionSetupResponse>,
    flags: Option<SessionFlags>,

    handler: Option<ChannelMessageHandler>,

    /// should always be set; this is Option to allow moving it out during setup,
    /// when it is being updated.
    preauth_hash: Option<PreauthHashState>,

    result: Option<Arc<RwLock<SessionAndChannel>>>,

    authenticator: Authenticator,
    upstream: &'a ChannelUpstream,
    conn_info: &'a Arc<ConnectionInfo>,

    // A place to store the current setup channel, until it is set into the info.
    channel: Option<ChannelInfo>,
    new_channel_id: u32,

    _phantom: std::marker::PhantomData<T>,
}

#[maybe_async]
impl<'a, T> SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    pub async fn new(
        identity: sspi::AuthIdentity,
        upstream: &'a ChannelUpstream,
        conn_info: &'a Arc<ConnectionInfo>,
        new_channel_id: u32,
        primary_session: Option<&Arc<RwLock<SessionAndChannel>>>,
    ) -> crate::Result<Self> {
        log::debug!("Creating new SessionSetup for user: {:?}, channel_id: {}", identity.username, new_channel_id);
        log::debug!("Primary session provided: {}", primary_session.is_some());
        
        let authenticator = Authenticator::build(identity, conn_info)?;

        let mut result = Self {
            last_setup_response: None,
            flags: None,
            result: None,
            handler: None,
            preauth_hash: Some(conn_info.preauth_hash.clone()),
            authenticator,
            upstream,
            conn_info,
            channel: None,
            new_channel_id,
            _phantom: std::marker::PhantomData,
        };

        if let Some(primary_session) = primary_session {
            log::debug!("Setting up session binding with existing primary session");
            let primary_session = primary_session.read().await?;

            let session = primary_session.session.clone();
            log::debug!("Cloned session from primary session");

            let channel = primary_session
                .channel
                .as_ref()
                .expect("A properly initialized session is expected in session setup.")
                .clone();
            log::debug!("Cloned channel from primary session");
            #[cfg(feature = "ksmbd-multichannel-compat")]
            let channel = {
                log::debug!("Enabling ksmbd multichannel compatibility");
                channel.with_binding(true)
            };

            result.set_session(session).await?;
            log::debug!("Session set for binding setup");
            result
                .result
                .as_ref()
                .expect("Should have been set up by set_session()")
                .write()
                .await?
                .channel = Some(channel);
            log::debug!("Channel assigned to session for binding");
        }

        log::debug!("SessionSetup created successfully");
        Ok(result)
    }

    /// Common session setup logic.
    ///
    /// This function sets up a session against a connection, and it is somewhat abstract.
    /// by calling impl functions, this function's behavior is modified to support both new sessions and binding to existing sessions.
    pub(crate) async fn setup(&mut self) -> crate::Result<Arc<RwLock<SessionAndChannel>>> {
        log::debug!(
            "Setting up session for user {} (@{}).",
            self.authenticator.user_name().account_name(),
            self.authenticator.user_name().domain_name().unwrap_or("")
        );

        let result = self._setup_loop().await;
        match result {
            Ok(()) => Ok(self.result.take().unwrap()),
            Err(e) => {
                log::error!("Failed to setup session: {}", e);
                if let Err(ce) = T::error_cleanup(self).await {
                    log::error!("Failed to cleanup after setup error: {}", ce);
                }
                Err(e)
            }
        }
    }

    /// *DO NOT OVERLOAD*
    ///
    /// Performs the session setup negotiation.
    ///
    /// This function loops until the authentication is complete, requesting GSS tokens
    /// and passing them to the server.
    async fn _setup_loop(&mut self) -> crate::Result<()> {
        log::debug!("Starting authentication setup loop");
        let mut iteration = 0;
        
        // While there's a response to process, do so.
        while !self.authenticator.is_authenticated()? {
            iteration += 1;
            log::debug!("Authentication loop iteration {}", iteration);
            let next_buf = match self.last_setup_response.as_ref() {
                Some(response) => {
                    log::debug!("Processing server response buffer of {} bytes", response.buffer.len());
                    self.authenticator.next(&response.buffer).await?
                },
                None => {
                    log::debug!("Starting authentication with empty buffer");
                    self.authenticator.next(&[]).await?
                },
            };
            let is_auth_done = self.authenticator.is_authenticated()?;
            log::debug!("Authentication completed after this iteration: {}", is_auth_done);

            // If keys are exchanged, set them up, to enable validation of next response!
            log::debug!("Sending setup request with {} bytes", next_buf.len());
            let request = self.send_setup_request(next_buf).await?;
            if is_auth_done {
                log::debug!("Authentication completed, finalizing preauth hash and creating channel");
                self.preauth_hash = self.preauth_hash.take().unwrap().finish().into();
                self.make_channel().await?;
            }

            log::debug!("Waiting for setup response to message ID: {}", request.msg_id);
            let response = self.receive_setup_response(request.msg_id).await?;
            let message_form = response.form;
            let session_id = response.message.header.session_id;
            log::debug!("Received response with session ID: {}, message form: {:?}", session_id, message_form);
            let session_setup_response = response.message.content.to_sessionsetup()?;

            // First iteration: construct a session state object.
            // TODO: currently, there's a bug which prevents authentication on first attempt
            // to complete successfully: since we need the session ID to construct the session state,
            // which is required for channel construction and signature validation,
            // the first request must arrive here, and then be validated.
            if self.result.is_none() {
                log::debug!("First iteration: creating session state with ID {}", session_id);
                self.set_session(T::init_session(self, session_id).await?)
                    .await?;
                log::debug!("Session state created and initialized");
            }

            if is_auth_done {
                log::debug!("Authentication completed, validating message security");
                // Important: If we did NOT make sure the message's signature is valid,
                // we should do it now, as long as the session is not anonymous or guest.
                let is_guest_or_null = session_setup_response.session_flags.is_guest_or_null_session();
                let is_signed_or_encrypted = message_form.signed_or_encrypted();
                log::debug!("Session flags - guest/null: {}, message signed/encrypted: {}", is_guest_or_null, is_signed_or_encrypted);
                
                if !is_guest_or_null && !is_signed_or_encrypted {
                    log::error!("Authentication completed but message is not signed for non-guest session");
                    return Err(Error::InvalidMessage(
                        "Expected a signed message!".to_string(),
                    ));
                }
                log::debug!("Message security validation passed");
            } else {
                log::debug!("Authentication not yet complete, updating preauth hash");
                self.next_preauth_hash(&response.raw);
            }

            log::debug!("Session flags: {:?}", session_setup_response.session_flags);
            self.flags = Some(session_setup_response.session_flags);
            self.last_setup_response = Some(session_setup_response);
            log::debug!("Completed iteration {}, continuing authentication loop", iteration);
        }

        self.flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))?;

        log::trace!("setup success, finishing up.");
        T::on_setup_success(self).await?;

        Ok(())
    }

    async fn set_session(&mut self, session: Arc<RwLock<SessionInfo>>) -> crate::Result<()> {
        let session_id = session.read().await?.id();
        log::debug!("Setting up session with ID: {}", session_id);
        let result = SessionAndChannel::new(session_id, session);
        let session = Arc::new(RwLock::new(result));
        log::debug!("SessionAndChannel wrapper created");

        log::debug!("Creating channel message handler for setup");
        let setup_handler = ChannelMessageHandler::make_for_setup(&session, self.upstream).await?;
        self.handler = Some(setup_handler);
        log::debug!("Channel message handler created and assigned");

        log::debug!("Notifying upstream worker of session start");
        self.upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))
            .unwrap()
            .session_started(&session)
            .await?;
        log::debug!("Upstream worker notified successfully");

        self.result = Some(session);
        log::debug!("Session setup completed and stored in result");

        Ok(())
    }

    async fn receive_setup_response(&mut self, for_msg_id: u64) -> crate::Result<IncomingMessage> {
        let is_auth_done = self.authenticator.is_authenticated()?;
        log::debug!("Receiving setup response for message ID: {}, auth_done: {}", for_msg_id, is_auth_done);

        let expected_status = if is_auth_done {
            log::debug!("Expecting Success status");
            &[Status::Success]
        } else {
            log::debug!("Expecting MoreProcessingRequired status");
            &[Status::MoreProcessingRequired]
        };

        let roptions = ReceiveOptions::new()
            .with_status(expected_status)
            .with_msg_id_filter(for_msg_id);

        let channel_set_up = self.result.is_some()
            && self
                .result
                .as_ref()
                .unwrap()
                .read()
                .await?
                .channel
                .is_some();
        let skip_security_validation = !is_auth_done && !channel_set_up;
        log::debug!("Channel setup status: {}, skip security validation: {}", channel_set_up, skip_security_validation);
        if self.handler.is_some() {
            log::debug!(
                "Receiving with channel handler; skip_security_validation={}", skip_security_validation
            );
            let result = self.handler
                .as_ref()
                .unwrap()
                .recvo_internal(roptions, skip_security_validation)
                .await?;
            log::debug!("Received response via channel handler");
            Ok(result)
        } else {
            assert!(skip_security_validation);
            log::debug!("Receiving with upstream handler");
            let result = self.upstream.handler.recvo(roptions).await?;
            log::debug!("Received response via upstream handler");
            Ok(result)
        }
    }

    async fn send_setup_request(&mut self, buf: Vec<u8>) -> crate::Result<SendMessageResult> {
        log::debug!("Preparing setup request with buffer size: {}", buf.len());
        // We'd like to update preauth hash with the last request before accept.
        // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
        let request = T::make_request(self, buf).await?;
        log::debug!("Setup request created");

        let send_result = if let Some(handler) = self.handler.as_ref() {
            log::debug!("Sending setup request with channel handler");
            let result = handler.sendo(request).await?;
            log::debug!("Setup request sent via channel handler, message ID: {}", result.msg_id);
            result
        } else {
            log::debug!("Sending setup request with upstream handler");
            let result = self.upstream.sendo(request).await?;
            log::debug!("Setup request sent via upstream handler, message ID: {}", result.msg_id);
            result
        };

        log::debug!("Updating preauth hash with sent request data");
        self.next_preauth_hash(send_result.raw.as_ref().unwrap());
        log::debug!("Setup request completed successfully");
        Ok(send_result)
    }

    /// Initializes the channel that is resulted from the current session setup.
    /// - Calls `T::on_session_key_exchanged` before setting up the channel.
    /// - Sets `self.channel` to the instantiated channel.
    /// - Calls `T::on_channel_set_up` after setting up the channel.
    async fn make_channel(&mut self) -> crate::Result<()> {
        log::debug!("Starting channel creation process");
        T::on_session_key_exchanged(self).await?;
        log::debug!("Session key exchange completed");

        let session_key = self.session_key()?;
        let preauth_hash = self.preauth_hash_value();
        log::debug!("Creating channel with ID: {}, has_preauth_hash: {}", self.new_channel_id, preauth_hash.is_some());
        
        let channel_info = ChannelInfo::new(
            self.new_channel_id,
            &session_key,
            &preauth_hash,
            self.conn_info,
        )?;
        log::debug!("ChannelInfo created successfully");

        self.channel = Some(channel_info);
        log::debug!("Channel stored in setup state");

        let mut session_lock = self.result.as_ref().unwrap().write().await?;
        session_lock.set_channel(self.channel.take().unwrap());
        log::debug!("Channel assigned to session");

        log::debug!("Channel creation and assignment completed successfully");
        Ok(())
    }

    fn session_key(&self) -> crate::Result<KeyToDerive> {
        self.authenticator.session_key()
    }

    fn preauth_hash_value(&self) -> Option<PreauthHashValue> {
        self.preauth_hash
            .as_ref()
            .unwrap()
            .unwrap_final_hash()
            .copied()
    }

    fn next_preauth_hash(&mut self, data: &IoVec) -> &PreauthHashState {
        if let Some(ref mut hash) = self.preauth_hash {
            *hash = hash.clone().next(data);
        }
        self.preauth_hash.as_ref().unwrap()
    }

    pub fn upstream(&self) -> &'a ChannelUpstream {
        self.upstream
    }

    pub fn conn_info(&self) -> &'a Arc<ConnectionInfo> {
        self.conn_info
    }
}

#[maybe_async(AFIT)]
pub(crate) trait SessionSetupProperties {
    /// This function is called when setup error is encountered, to perform any necessary cleanup.
    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;

    fn _make_default_request(buffer: Vec<u8>) -> OutgoingMessage {
        OutgoingMessage::new(
            SessionSetupRequest::new(
                buffer,
                SessionSecurityMode::new().with_signing_enabled(true),
                SetupRequestFlags::new(),
            )
            .into(),
        )
        .with_return_raw_data(true)
    }

    async fn make_request<T>(
        _setup: &mut SessionSetup<'_, T>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
    {
        Ok(Self::_make_default_request(buffer))
    }

    async fn init_session<T>(
        _setup: &'_ SessionSetup<'_, T>,
        _session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties;

    async fn on_session_key_exchanged<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // Default implementation does nothing.
        Ok(())
    }

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;
}

pub(crate) struct SmbSessionBind;

#[maybe_async(AFIT)]
impl SessionSetupProperties for SmbSessionBind {
    async fn make_request<T>(
        _setup: &mut SessionSetup<'_, T>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
    {
        log::debug!("SmbSessionBind: Creating binding request with {} bytes", buffer.len());
        let mut request = Self::_make_default_request(buffer);
        request
            .message
            .content
            .as_mut_sessionsetup()
            .unwrap()
            .flags
            .set_binding(true);
        log::debug!("SmbSessionBind: Binding flag set on request");
        Ok(request)
    }

    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::debug!("SmbSessionBind: Starting error cleanup");
        if setup.result.is_none() {
            log::warn!("SmbSessionBind: No session to cleanup in binding");
            return Ok(());
        }
        log::debug!("SmbSessionBind: Notifying worker of session end");
        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
            .await?;
        log::debug!("SmbSessionBind: Error cleanup completed");
        Ok(())
    }

    async fn init_session<T>(
        _setup: &SessionSetup<'_, T>,
        _session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties,
    {
        panic!("(Primary) Session should be provided in construction, rather than during setup!");
    }

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::debug!("SmbSessionBind: Session binding completed successfully");
        Ok(())
    }
}

pub(crate) struct SmbSessionNew;

#[maybe_async(AFIT)]
impl SessionSetupProperties for SmbSessionNew {
    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::debug!("SmbSessionNew: Starting error cleanup for new session");
        if setup.result.is_none() {
            log::debug!("SmbSessionNew: No session to cleanup in setup");
            return Ok(());
        }

        log::debug!("SmbSessionNew: Invalidating session before cleanup");
        let session = setup.result.as_ref().unwrap();
        {
            let session_lock = session.read().await?;
            session_lock.session.write().await?.invalidate();
        }
        log::debug!("SmbSessionNew: Session invalidated");

        log::debug!("SmbSessionNew: Notifying worker of session end");
        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
            .await?;
        log::debug!("SmbSessionNew: Error cleanup completed");
        Ok(())
    }

    async fn on_session_key_exchanged<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // Only on new sessions we need to initialize the session state with the keys.
        log::debug!("SmbSessionNew: Session keys exchanged, setting up session state");
        setup
            .result
            .as_ref()
            .unwrap()
            .read()
            .await?
            .session
            .write()
            .await?
            .setup(
                &setup.session_key()?,
                &setup.preauth_hash_value(),
                setup.conn_info,
            )?;
        log::debug!("SmbSessionNew: Session state setup completed with keys");
        Ok(())
    }

    async fn on_setup_success<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::debug!("SmbSessionNew: Session setup successful, marking session as ready");
        let result = setup.result.as_ref().unwrap().read().await?;
        let mut session = result.session.write().await?;
        let flags = setup.flags.unwrap();
        log::debug!("SmbSessionNew: Setting session ready with flags: {:?}", flags);
        session.ready(flags, setup.conn_info)?;
        log::debug!("SmbSessionNew: Session marked as ready successfully");
        Ok(())
    }

    async fn init_session<T>(
        _setup: &SessionSetup<'_, T>,
        session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties,
    {
        log::debug!("SmbSessionNew: Initializing new session with ID: {}", session_id);
        let session_info = SessionInfo::new(session_id);
        let session_info = Arc::new(RwLock::new(session_info));
        log::debug!("SmbSessionNew: New session info created and wrapped");

        Ok(session_info)
    }
}
