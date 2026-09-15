use crate::client::{
    AuthorizationSummary, ChatPermissionAnswer, ClientError, RunCancelAccepted, RunMessageAccepted,
    RunPermissionAnswerAccepted, RunResumeAccepted, RunSubmitAccepted,
};
use crate::client_stream::{read_value, write_all_before, ClientStream};
use crate::protocol_helpers::{
    deadline, fresh_nonce, fresh_request_id, is_hex_secret, is_rfc3339, map_frame_error,
    map_protocol_error, parse_message, reject_protocol_error, validate_capability_revocation,
};
use crate::{
    encode_frame, Authorization, Client, DesktopClientAuthorizedGrant, Envelope, EventName, Hello,
    Id, Operation, Protocol, Request, Response, VersionRange, Welcome, MAX_TEXT_LENGTH, PROTOCOL,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
// Grant issuance can take longer than the default desktop request deadline.
const RUN_SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_THREAD_ID_LENGTH: usize = 36;
const MAX_CURSOR_LENGTH: usize = 1024;
const MAX_RUN_MESSAGE_TEXT_LENGTH: usize = 32 * 1024;
const MAX_PERMISSION_GATE_ID_LENGTH: usize = 256;

/// A connection-bound client for the peer-authorized desktop session.
pub struct DesktopClient {
    stream: Box<dyn ClientStream + Send>,
    runtime_version: String,
    profile_id: String,
    workspace_scopes: BTreeMap<String, BTreeSet<String>>,
    capability: String,
    summary: AuthorizationSummary,
    authorized_at: Instant,
    chat_subscription_id: Option<Id>,
    io_timeout: Duration,
    last_request_error: Option<crate::ProtocolError>,
}

impl std::fmt::Debug for DesktopClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DesktopClient { .. }")
    }
}

impl DesktopClient {
    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn runtime_version(&self) -> &str {
        &self.runtime_version
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn workspace_scopes(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.workspace_scopes
    }

    pub fn authorization_summary(&self) -> AuthorizationSummary {
        self.summary.clone()
    }

    /// Returns the protocol error from the most recent wire request, if it failed.
    pub fn last_request_error(&self) -> Option<&crate::ProtocolError> {
        self.last_request_error.as_ref()
    }

    pub(crate) fn take_request_error(&mut self) -> Option<crate::ProtocolError> {
        self.last_request_error.take()
    }

    pub fn request(
        &mut self,
        operation: Operation,
        idempotency_key: Option<Id>,
        body: Value,
    ) -> Result<Response, ClientError> {
        self.request_before(operation, idempotency_key, body, deadline(self.io_timeout))
    }

    fn request_before(
        &mut self,
        operation: Operation,
        idempotency_key: Option<Id>,
        body: Value,
        request_deadline: Instant,
    ) -> Result<Response, ClientError> {
        self.last_request_error = None;
        let request_id = fresh_request_id()?;
        let request = Request {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation,
            capability: self.capability.clone(),
            idempotency_key,
            body,
        };
        let bytes = encode_frame(&request).map_err(map_frame_error)?;
        write_all_before(self.stream.as_mut(), &bytes, request_deadline)?;
        match serde_json::from_value(read_value(self.stream.as_mut(), request_deadline)?)
            .map_err(|_| ClientError::UnexpectedMessage)?
        {
            Envelope::Response(response) if response.request_id == request_id => Ok(response),
            Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                let outcome = map_protocol_error(error.error.code());
                self.last_request_error = Some(error.error);
                Err(outcome)
            }
            _ => Err(ClientError::UnexpectedMessage),
        }
    }

    pub fn rename_thread(&mut self, thread_id: &str, title: &str) -> Result<(), ClientError> {
        if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH || title.is_empty() {
            return Err(ClientError::UnexpectedMessage);
        }
        let response = self.request(
            Operation::ThreadRename,
            Some(fresh_request_id()?),
            serde_json::json!({"thread_id": thread_id, "title": title}),
        )?;
        if response.body != serde_json::json!({}) {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(())
    }

    pub fn delete_thread(&mut self, thread_id: &str) -> Result<(), ClientError> {
        if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        let response = self.request(
            Operation::ThreadDelete,
            Some(fresh_request_id()?),
            serde_json::json!({"thread_id": thread_id}),
        )?;
        if response.body != serde_json::json!({}) {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(())
    }

    pub fn thread_select(&mut self, thread_id: &str) -> Result<(), ClientError> {
        if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        let response = self.request(
            Operation::ThreadSelect,
            None,
            serde_json::json!({"thread_id": thread_id}),
        )?;
        if response.body != serde_json::json!({}) {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(())
    }

    pub fn recheck_retention(&mut self) -> Result<(), ClientError> {
        let response = self.request(Operation::RetentionRecheck, None, serde_json::json!({}))?;
        if response.body != serde_json::json!({}) {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(())
    }

    pub fn run_submit(
        &mut self,
        text: &str,
        files: &[String],
        thread_id: Option<&str>,
    ) -> Result<RunSubmitAccepted, ClientError> {
        if text.trim().is_empty()
            || text.len() > MAX_TEXT_LENGTH
            || files
                .iter()
                .any(|file| file.trim().is_empty() || file.len() > MAX_TEXT_LENGTH)
            || thread_id.is_some_and(|thread_id| thread_id.is_empty() || thread_id.len() > 36)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        let response = self.request_before(
            Operation::RunSubmit,
            Some(fresh_request_id()?),
            serde_json::json!({"text": text, "files": files, "thread_id": thread_id}),
            deadline(RUN_SUBMIT_TIMEOUT),
        )?;
        let accepted: RunSubmitAccepted =
            serde_json::from_value(response.body).map_err(|_| ClientError::UnexpectedMessage)?;
        if Id::new(accepted.run_id.clone()).is_err()
            || Id::new(accepted.thread_id.clone()).is_err()
            || thread_id.is_some_and(|thread_id| accepted.thread_id != thread_id)
            || accepted.committed_seq == 0
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || !is_rfc3339(&accepted.accepted_at)
            || accepted.attachments.len() != files.len()
            || accepted.attachments.iter().any(|attachment| {
                attachment.display_name.trim().is_empty()
                    || attachment.display_name.len() > MAX_TEXT_LENGTH
                    || attachment.media_type.as_ref().is_some_and(|media_type| {
                        media_type.trim().is_empty() || media_type.len() > MAX_TEXT_LENGTH
                    })
            })
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(accepted)
    }

    pub fn run_cancel(&mut self, run_id: &str) -> Result<RunCancelAccepted, ClientError> {
        let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
        let response = self.request(
            Operation::RunCancel,
            Some(fresh_request_id()?),
            serde_json::json!({"run_id": run_id.as_str()}),
        )?;
        let accepted: RunCancelAccepted =
            serde_json::from_value(response.body).map_err(|_| ClientError::UnexpectedMessage)?;
        if accepted.run_id != run_id.as_str()
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || !is_rfc3339(&accepted.accepted_at)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(accepted)
    }

    pub fn run_resume(&mut self, run_id: &str) -> Result<RunResumeAccepted, ClientError> {
        let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
        let response = self.request(
            Operation::RunResume,
            Some(fresh_request_id()?),
            serde_json::json!({"run_id": run_id.as_str()}),
        )?;
        let accepted: RunResumeAccepted =
            serde_json::from_value(response.body).map_err(|_| ClientError::UnexpectedMessage)?;
        if accepted.run_id != run_id.as_str()
            || Id::new(accepted.thread_id.clone()).is_err()
            || accepted.committed_seq == 0
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || !is_rfc3339(&accepted.accepted_at)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(accepted)
    }

    pub fn run_permission_answer(
        &mut self,
        run_id: &str,
        gate_id: &str,
        answer: ChatPermissionAnswer,
    ) -> Result<RunPermissionAnswerAccepted, ClientError> {
        let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
        if gate_id.trim().is_empty() || gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        let response = self.request(
            Operation::RunPermissionAnswer,
            Some(fresh_request_id()?),
            serde_json::json!({
                "run_id": run_id.as_str(),
                "gate_id": gate_id,
                "answer": &answer,
            }),
        )?;
        let accepted: RunPermissionAnswerAccepted =
            serde_json::from_value(response.body).map_err(|_| ClientError::UnexpectedMessage)?;
        if accepted.run_id != run_id.as_str()
            || accepted.gate_id != gate_id
            || accepted.answer != answer
            || accepted.committed_seq == 0
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || !is_rfc3339(&accepted.accepted_at)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(accepted)
    }

    pub fn run_steer(
        &mut self,
        run_id: &str,
        text: &str,
    ) -> Result<RunMessageAccepted, ClientError> {
        self.run_message(Operation::RunSteer, run_id, text)
    }

    pub fn run_follow_up(
        &mut self,
        run_id: &str,
        text: &str,
    ) -> Result<RunMessageAccepted, ClientError> {
        self.run_message(Operation::RunFollowUp, run_id, text)
    }

    fn run_message(
        &mut self,
        operation: Operation,
        run_id: &str,
        text: &str,
    ) -> Result<RunMessageAccepted, ClientError> {
        let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
        if text.trim().is_empty() || text.len() > MAX_RUN_MESSAGE_TEXT_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        let response = self.request(
            operation,
            Some(fresh_request_id()?),
            serde_json::json!({"run_id": run_id.as_str(), "text": text}),
        )?;
        let accepted: RunMessageAccepted =
            serde_json::from_value(response.body).map_err(|_| ClientError::UnexpectedMessage)?;
        if accepted.run_id != run_id.as_str()
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || !is_rfc3339(&accepted.accepted_at)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(accepted)
    }

    pub fn session_status(&mut self) -> Result<Value, ClientError> {
        self.request_body(
            Operation::SessionStatus,
            None,
            serde_json::json!({}),
            &["signed_in", "subject", "expires_at"],
        )
    }

    pub fn entitlement_snapshot(&mut self) -> Result<Value, ClientError> {
        self.request_body(
            Operation::EntitlementSnapshot,
            None,
            serde_json::json!({}),
            &["snapshot", "changed_snapshot_version"],
        )
    }

    pub fn list_devices(&mut self) -> Result<Value, ClientError> {
        self.request_body(
            Operation::DeviceList,
            None,
            serde_json::json!({}),
            &["devices"],
        )
    }

    pub fn sign_out(&mut self) -> Result<Value, ClientError> {
        self.request_body(
            Operation::SessionSignOut,
            Some(fresh_request_id()?),
            serde_json::json!({}),
            &["status"],
        )
    }

    pub fn sign_in(&mut self) -> Result<Value, ClientError> {
        let body = self
            .request_before(
                Operation::SessionSignIn,
                Some(fresh_request_id()?),
                serde_json::json!({}),
                deadline(SIGN_IN_TIMEOUT),
            )?
            .body;
        let object = body.as_object().ok_or(ClientError::UnexpectedMessage)?;
        if !object.contains_key("status") {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(body)
    }

    pub fn thread_summaries(
        &mut self,
        limit: u8,
        cursor: Option<&str>,
    ) -> Result<Value, ClientError> {
        let body = thread_read_body(limit, cursor)?;
        Ok(self.request(Operation::ThreadSummaries, None, body)?.body)
    }

    pub fn thread_history(
        &mut self,
        thread_id: &str,
        limit: u8,
        cursor: Option<&str>,
    ) -> Result<Value, ClientError> {
        if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        let mut body = thread_read_body(limit, cursor)?;
        body["thread_id"] = Value::String(thread_id.into());
        Ok(self.request(Operation::ThreadHistory, None, body)?.body)
    }

    pub fn subscribe_chat_events(&mut self) -> Result<String, ClientError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Subscription {
            subscription_id: String,
        }

        let response = self.request(Operation::RunChatEvents, None, serde_json::json!({}))?;
        let subscription: Subscription =
            serde_json::from_value(response.body).map_err(|_| ClientError::UnexpectedMessage)?;
        let subscription_id =
            Id::new(subscription.subscription_id).map_err(|_| ClientError::UnexpectedMessage)?;
        let result = subscription_id.as_str().to_owned();
        self.chat_subscription_id = Some(subscription_id);
        Ok(result)
    }

    pub fn read_chat_event(&mut self) -> Result<Value, ClientError> {
        let subscription_id = self
            .chat_subscription_id
            .as_ref()
            .ok_or(ClientError::UnexpectedMessage)?;
        let authorization_remaining = Duration::from_secs(self.summary.expires_in_seconds)
            .saturating_sub(self.authorized_at.elapsed());
        let wait =
            authorization_remaining.min(Duration::from_secs(self.summary.idle_timeout_seconds));
        if wait.is_zero() {
            return Err(ClientError::AuthorizationExpired);
        }
        let value = read_value(self.stream.as_mut(), deadline(wait)).map_err(|error| {
            if error == ClientError::ConnectionClosed {
                ClientError::DesktopUnavailable
            } else {
                error
            }
        })?;
        if value
            .get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|protocol| protocol != PROTOCOL)
        {
            return Err(ClientError::ProtocolIncompatible);
        }
        let event =
            match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                Envelope::Event(event) => event,
                Envelope::Error(error) => return Err(map_protocol_error(error.error.code())),
                _ => return Err(ClientError::UnexpectedMessage),
            };
        if event.event == EventName::CapabilityRevoked {
            validate_capability_revocation(&event)?.ok_or(ClientError::UnexpectedMessage)?;
            return Err(ClientError::CapabilityRevoked);
        }
        if &event.subscription_id != subscription_id
            || event.event != EventName::ChatEvent
            || event.run_id.is_some()
            || event.run_seq.is_some()
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(event.body)
    }

    pub fn list_companions(&mut self) -> Result<Value, ClientError> {
        self.request_body(
            Operation::CompanionList,
            None,
            serde_json::json!({}),
            &["companions"],
        )
    }

    pub fn list_companies(&mut self) -> Result<Value, ClientError> {
        self.request_body(
            Operation::CompanyList,
            None,
            serde_json::json!({}),
            &["companies", "current"],
        )
    }

    pub fn create_company(&mut self, name: &str) -> Result<Value, ClientError> {
        if name.trim().is_empty() || name.len() > MAX_TEXT_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        self.request_body(
            Operation::CompanyCreate,
            Some(fresh_request_id()?),
            serde_json::json!({"name": name}),
            &["company"],
        )
    }

    pub fn select_company(&mut self, company_id: &str) -> Result<Value, ClientError> {
        if company_id.is_empty() || company_id.len() > MAX_THREAD_ID_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        self.request_body(
            Operation::CompanySelect,
            Some(fresh_request_id()?),
            serde_json::json!({"company_id": company_id}),
            &["company"],
        )
    }

    pub fn rename_company(&mut self, company_id: &str, name: &str) -> Result<Value, ClientError> {
        if company_id.is_empty()
            || company_id.len() > MAX_THREAD_ID_LENGTH
            || name.trim().is_empty()
            || name.len() > MAX_TEXT_LENGTH
        {
            return Err(ClientError::UnexpectedMessage);
        }
        self.request_body(
            Operation::CompanyRename,
            Some(fresh_request_id()?),
            serde_json::json!({"company_id": company_id, "name": name}),
            &["company"],
        )
    }

    pub fn record_sql(&mut self, body: Value) -> Result<Value, ClientError> {
        self.request_body(Operation::RecordSql, None, body, &[])
    }

    pub fn record_propose(&mut self, body: Value) -> Result<Value, ClientError> {
        self.request_body(Operation::RecordPropose, None, body, &[])
    }

    pub fn record_commit(&mut self, body: Value) -> Result<Value, ClientError> {
        self.request_body(
            Operation::RecordCommit,
            Some(fresh_request_id()?),
            body,
            &[],
        )
    }

    pub fn record_kinds(&mut self, body: Value) -> Result<Value, ClientError> {
        self.request_body(Operation::RecordKinds, None, body, &["kinds"])
    }

    pub fn record_query(&mut self, body: Value) -> Result<Value, ClientError> {
        self.request_body(Operation::RecordQuery, None, body, &[])
    }

    pub fn record_entity(&mut self, body: Value) -> Result<Value, ClientError> {
        self.request_body(Operation::RecordEntity, None, body, &[])
    }

    pub fn revoke_companion(&mut self, client_identity: &str) -> Result<Value, ClientError> {
        if client_identity.is_empty() || client_identity.len() > MAX_TEXT_LENGTH {
            return Err(ClientError::UnexpectedMessage);
        }
        let body = self.request_body(
            Operation::CompanionRevoke,
            Some(fresh_request_id()?),
            serde_json::json!({"client_identity": client_identity}),
            &[],
        )?;
        if body != serde_json::json!({}) {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(body)
    }

    fn request_body(
        &mut self,
        operation: Operation,
        idempotency_key: Option<Id>,
        body: Value,
        expected_keys: &[&str],
    ) -> Result<Value, ClientError> {
        let body = self.request(operation, idempotency_key, body)?.body;
        let object = body.as_object().ok_or(ClientError::UnexpectedMessage)?;
        if !expected_keys.iter().all(|key| object.contains_key(*key)) {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(body)
    }
}

#[cfg(all(test, unix))]
pub(crate) fn desktop_client_for_test(
    stream: Box<dyn ClientStream + Send>,
    runtime_version: String,
    io_timeout: Duration,
) -> DesktopClient {
    DesktopClient {
        stream,
        runtime_version,
        profile_id: "profile".to_string(),
        workspace_scopes: BTreeMap::new(),
        capability: "capability".to_string(),
        summary: AuthorizationSummary {
            expires_in_seconds: 60,
            idle_timeout_seconds: 60,
        },
        authorized_at: Instant::now(),
        chat_subscription_id: None,
        io_timeout,
        last_request_error: None,
    }
}

fn thread_read_body(limit: u8, cursor: Option<&str>) -> Result<Value, ClientError> {
    if limit == 0
        || limit > 100
        || cursor.is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
    {
        return Err(ClientError::UnexpectedMessage);
    }
    let mut body = serde_json::json!({"limit": limit});
    if let Some(cursor) = cursor {
        body["cursor"] = Value::String(cursor.into());
    }
    Ok(body)
}

#[doc(hidden)]
pub fn handshake_desktop_client(
    mut stream: Box<dyn ClientStream + Send>,
    client_version: &str,
    io_timeout: Duration,
) -> Result<DesktopClient, ClientError> {
    let hello = Hello {
        protocol: Protocol,
        client: Client {
            kind: "desktop-client".into(),
            version: client_version.into(),
        },
        supported: VersionRange { min: 1, max: 1 },
        client_nonce: fresh_nonce()?,
        authorized_client_id: Id::new(fresh_request_id()?.as_str())
            .map_err(|_| ClientError::UnexpectedMessage)?,
        authorized_client_credential: None,
    };
    let bytes = encode_frame(&hello).map_err(map_frame_error)?;
    write_all_before(stream.as_mut(), &bytes, deadline(io_timeout))?;

    let welcome_value = read_value(stream.as_mut(), deadline(io_timeout))?;
    reject_protocol_error(&welcome_value)?;
    let welcome: Welcome = parse_message(welcome_value)?;
    if welcome.selected != 1
        || welcome.authorization != Authorization::Authorized
        || !is_hex_secret(&welcome.server_nonce, 32)
    {
        return Err(ClientError::UnexpectedMessage);
    }

    let authorized_value = read_value(stream.as_mut(), deadline(io_timeout))?;
    reject_protocol_error(&authorized_value)?;
    if authorized_value
        .get("authorized_client_credential")
        .is_some()
    {
        return Err(ClientError::UnexpectedMessage);
    }
    let authorized: DesktopClientAuthorizedGrant = parse_message(authorized_value)?;
    if authorized.workspace_scopes.len() > 1
        || !is_hex_secret(&authorized.capability, 64)
        || authorized.expires_at == 0
        || authorized.expires_at > 8 * 60 * 60
        || authorized.idle_timeout_seconds == 0
        || authorized.idle_timeout_seconds > 15 * 60
    {
        return Err(ClientError::UnexpectedMessage);
    }
    Ok(DesktopClient {
        stream,
        runtime_version: welcome.desktop_version,
        profile_id: authorized.profile_id,
        workspace_scopes: authorized.workspace_scopes,
        capability: authorized.capability,
        summary: AuthorizationSummary {
            expires_in_seconds: authorized.expires_at,
            idle_timeout_seconds: authorized.idle_timeout_seconds,
        },
        authorized_at: Instant::now(),
        chat_subscription_id: None,
        io_timeout,
        last_request_error: None,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn sign_in_keeps_the_authorization_code_for_the_shell() {
        let (client, mut server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let failure = crate::ProtocolError::authorization_failed(
            "native authorization failed: HttpStatus status=400 error_code=invalid_device_proof cf_ray=0123456789abcdef-IAD",
        );
        let expected = failure.clone();
        let worker = std::thread::spawn(move || {
            let mut prefix = [0; 4];
            server.read_exact(&mut prefix).unwrap();
            let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
            server.read_exact(&mut body).unwrap();
            let request: Request = serde_json::from_slice(&body).unwrap();
            assert_eq!(request.operation, Operation::SessionSignIn);
            let response = serde_json::json!({
                "protocol": "muniment.attach/1", "request_id": request.request_id,
                "ok": false, "error": failure,
            });
            server.write_all(&encode_frame(&response).unwrap()).unwrap();
        });
        let mut client =
            desktop_client_for_test(Box::new(client), "1.0.0".into(), Duration::from_secs(5));
        assert_eq!(client.sign_in(), Err(ClientError::AuthorizationFailed));
        assert_eq!(client.last_request_error(), Some(&expected));
        worker.join().unwrap();
    }

    #[test]
    fn request_errors_do_not_survive_success_mismatched_responses_or_disconnects() {
        let (client, mut server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            for index in 0..4 {
                let mut prefix = [0; 4];
                server.read_exact(&mut prefix).unwrap();
                let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
                server.read_exact(&mut body).unwrap();
                let request: Request = serde_json::from_slice(&body).unwrap();
                let response = if index == 1 {
                    serde_json::json!({
                        "protocol": "muniment.attach/1", "request_id": request.request_id,
                        "ok": true, "body": {},
                    })
                } else {
                    serde_json::json!({
                        "protocol": "muniment.attach/1",
                        "request_id": if index == 3 { fresh_request_id().unwrap() } else { request.request_id },
                        "ok": false, "error": crate::ProtocolError::runtime_draining(),
                    })
                };
                server.write_all(&encode_frame(&response).unwrap()).unwrap();
            }
        });
        let mut client =
            desktop_client_for_test(Box::new(client), "1.0.0".into(), Duration::from_secs(5));
        for expected in [
            Some(ClientError::RequestRejected),
            None,
            Some(ClientError::RequestRejected),
            Some(ClientError::UnexpectedMessage),
        ] {
            assert_eq!(
                client
                    .request(Operation::SessionStatus, None, serde_json::json!({}))
                    .err(),
                expected
            );
            assert_eq!(
                client.last_request_error().cloned(),
                (expected == Some(ClientError::RequestRejected))
                    .then(crate::ProtocolError::runtime_draining)
            );
        }
        worker.join().unwrap();
        assert_eq!(
            client.request(Operation::SessionStatus, None, serde_json::json!({})),
            Err(ClientError::ConnectionClosed)
        );
        assert_eq!(client.last_request_error(), None);
    }
}
