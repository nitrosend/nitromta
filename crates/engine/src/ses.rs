//! The SES v2 API: an HTTPS listener serving the generated SES server. Each
//! request's signature is verified against the bytes it arrived as, with
//! the access keys of the policy snapshot it is decided under, before the
//! server decodes it, and its key's permission for what it asks,
//! to send or to manage. `SendEmail` goes through the shared
//! acceptance, answering only once the acceptance has committed; a managing
//! operation's change, once it has committed and its policy is published.

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_smithy_http_server::Extension;
use aws_smithy_http_server::body::{BoxBody, to_boxed};
use aws_smithy_http_server::protocol::rest::router::RestRouter;
use aws_smithy_http_server::protocol::rest_json_1::RestJson1;
use aws_smithy_http_server::routing::{Route, RoutingService};
use bytes::Bytes;
use engine_api::ses::{self as mapping, ErrorResponse};
use engine_api::ses_manage::{self as manage, Arns, Refused as Unmanaged};
use engine_api::sigv4;
use engine_api::snapshot::Snapshot;
use engine_core::command::{Answer, Command, Commit};
use engine_core::id::{
    ConfigurationId, DestinationId, HoldId, IdGenerator, IdentityId, MessageId, PoolId, TemplateId,
    TenantId,
};
use engine_core::policy::{Change, Credential, PolicyRefusal, Target};
use engine_ses_v2::error::{
    CreateConfigurationSetError, CreateConfigurationSetEventDestinationError,
    CreateDedicatedIpPoolError, CreateEmailIdentityError, CreateEmailTemplateError,
    CreateTenantError, CreateTenantResourceAssociationError,
    DeleteConfigurationSetEventDestinationError, DeleteEmailIdentityError,
    DeleteEmailTemplateError, DeleteSuppressedDestinationError,
    DeleteTenantResourceAssociationError, GetAccountError, GetConfigurationSetError,
    GetConfigurationSetEventDestinationsError, GetDedicatedIpError, GetDedicatedIpsError,
    GetEmailIdentityError, GetEmailTemplateError, GetReputationEntityError,
    GetSuppressedDestinationError, GetTenantError, ListConfigurationSetsError,
    ListEmailIdentitiesError, ListEmailTemplatesError, ListResourceTenantsError,
    ListSuppressedDestinationsError, ListTenantResourcesError, ListTenantsError,
    PutConfigurationSetDeliveryOptionsError, PutConfigurationSetReputationOptionsError,
    PutDedicatedIpInPoolError, PutEmailIdentityDkimAttributesError,
    PutEmailIdentityDkimSigningAttributesError, PutEmailIdentityFeedbackAttributesError,
    PutEmailIdentityMailFromAttributesError, PutSuppressedDestinationError, SendBulkEmailError,
    SendEmailError, UpdateConfigurationSetEventDestinationError, UpdateEmailTemplateError,
    UpdateReputationEntityCustomerManagedStatusError,
};
use engine_ses_v2::input::{
    CreateConfigurationSetEventDestinationInput, CreateConfigurationSetInput,
    CreateDedicatedIpPoolInput, CreateEmailIdentityInput, CreateEmailTemplateInput,
    CreateTenantInput, CreateTenantResourceAssociationInput,
    DeleteConfigurationSetEventDestinationInput, DeleteEmailIdentityInput,
    DeleteEmailTemplateInput, DeleteSuppressedDestinationInput,
    DeleteTenantResourceAssociationInput, GetAccountInput,
    GetConfigurationSetEventDestinationsInput, GetConfigurationSetInput, GetDedicatedIpInput,
    GetDedicatedIpsInput, GetEmailIdentityInput, GetEmailTemplateInput, GetReputationEntityInput,
    GetSuppressedDestinationInput, GetTenantInput, ListConfigurationSetsInput,
    ListEmailIdentitiesInput, ListEmailTemplatesInput, ListResourceTenantsInput,
    ListSuppressedDestinationsInput, ListTenantResourcesInput, ListTenantsInput,
    PutConfigurationSetDeliveryOptionsInput, PutConfigurationSetReputationOptionsInput,
    PutDedicatedIpInPoolInput, PutEmailIdentityDkimAttributesInput,
    PutEmailIdentityDkimSigningAttributesInput, PutEmailIdentityFeedbackAttributesInput,
    PutEmailIdentityMailFromAttributesInput, PutSuppressedDestinationInput, SendBulkEmailInput,
    SendEmailInput, UpdateConfigurationSetEventDestinationInput, UpdateEmailTemplateInput,
    UpdateReputationEntityCustomerManagedStatusInput,
};
use engine_ses_v2::model::{AmazonResourceName, BulkEmailEntryResult, TenantName};
use engine_ses_v2::output::{
    CreateConfigurationSetEventDestinationOutput, CreateConfigurationSetOutput,
    CreateDedicatedIpPoolOutput, CreateEmailIdentityOutput, CreateEmailTemplateOutput,
    CreateTenantOutput, CreateTenantResourceAssociationOutput,
    DeleteConfigurationSetEventDestinationOutput, DeleteEmailIdentityOutput,
    DeleteEmailTemplateOutput, DeleteSuppressedDestinationOutput,
    DeleteTenantResourceAssociationOutput, GetAccountOutput,
    GetConfigurationSetEventDestinationsOutput, GetConfigurationSetOutput, GetDedicatedIpOutput,
    GetDedicatedIpsOutput, GetEmailIdentityOutput, GetEmailTemplateOutput,
    GetReputationEntityOutput, GetSuppressedDestinationOutput, GetTenantOutput,
    ListConfigurationSetsOutput, ListEmailIdentitiesOutput, ListEmailTemplatesOutput,
    ListResourceTenantsOutput, ListSuppressedDestinationsOutput, ListTenantResourcesOutput,
    ListTenantsOutput, PutConfigurationSetDeliveryOptionsOutput,
    PutConfigurationSetReputationOptionsOutput, PutDedicatedIpInPoolOutput,
    PutEmailIdentityDkimAttributesOutput, PutEmailIdentityDkimSigningAttributesOutput,
    PutEmailIdentityFeedbackAttributesOutput, PutEmailIdentityMailFromAttributesOutput,
    PutSuppressedDestinationOutput, SendBulkEmailOutput, SendEmailOutput,
    UpdateConfigurationSetEventDestinationOutput, UpdateEmailTemplateOutput,
    UpdateReputationEntityCustomerManagedStatusOutput,
};
use engine_ses_v2::{SimpleEmailServiceV2, SimpleEmailServiceV2Config};
use http::{HeaderValue, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

use crate::acceptance::{Acceptance, Prepared, Refused};
use crate::clock::SystemClock;
use crate::operator::{Listener, Pressure};
use crate::policy::Current;

/// The generated server, routing requests whose bodies are already read.
type Server = SimpleEmailServiceV2<RoutingService<RestRouter<Route<Full<Bytes>>>, RestJson1>>;

/// Kibibytes of request bodies read before their signatures are verified,
/// from every client at once, at most: past them, a request is
/// refused before its body is read, and its client tries again.
pub const UNVERIFIED_KIB: usize = 256 * 1024;

/// How long a request's body may take to arrive.
const BODY: Duration = Duration::from_secs(60);

/// How long a request's header may take to arrive, and a connection kept
/// open may wait for its next request.
const HEADER: Duration = Duration::from_secs(60);

pub struct Ses {
    /// Its certificate, which a reload replaces.
    pub tls: Arc<crate::tls::Certified>,
    pub policy: Arc<Current>,
    pub region: String,
    pub acceptance: Arc<Acceptance>,
    /// The IDs of what managing operations create.
    pub ids: Mutex<IdGenerator>,
    /// Where bounces arrive, which an identity's MAIL FROM domain's MX must
    /// name: none if the installation takes none.
    pub bounce_host: Option<String>,
    /// The SNS subset served beside it, if `[sns]` is configured.
    pub sns: Option<Arc<crate::sns::Sns>>,
    /// How SNS's subscribers are reached.
    pub network: crate::events::Network,
    pub clock: Arc<SystemClock>,
    pub max_recipients: usize,
    /// The rule bundle's default warmup ladder, which a dedicated IP's
    /// warmup is measured against.
    pub ladder: Arc<[u64]>,
    /// What is left of [`UNVERIFIED_KIB`].
    pub unverified: Arc<tokio::sync::Semaphore>,
}

impl Ses {
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<(), String> {
        let server = SimpleEmailServiceV2::builder(SimpleEmailServiceV2Config::builder().build())
            .send_email(send_email)
            .send_bulk_email(send_bulk_email)
            .create_email_identity(create_email_identity)
            .get_email_identity(get_email_identity)
            .delete_email_identity(delete_email_identity)
            .list_email_identities(list_email_identities)
            .put_email_identity_dkim_attributes(put_email_identity_dkim_attributes)
            .put_email_identity_dkim_signing_attributes(put_email_identity_dkim_signing_attributes)
            .put_email_identity_feedback_attributes(put_email_identity_feedback_attributes)
            .put_email_identity_mail_from_attributes(put_email_identity_mail_from_attributes)
            .create_configuration_set(create_configuration_set)
            .get_configuration_set(get_configuration_set)
            .list_configuration_sets(list_configuration_sets)
            .put_configuration_set_reputation_options(put_configuration_set_reputation_options)
            .create_tenant(create_tenant)
            .get_tenant(get_tenant)
            .list_tenants(list_tenants)
            .create_tenant_resource_association(create_tenant_resource_association)
            .delete_tenant_resource_association(delete_tenant_resource_association)
            .list_tenant_resources(list_tenant_resources)
            .list_resource_tenants(list_resource_tenants)
            .get_reputation_entity(get_reputation_entity)
            .update_reputation_entity_customer_managed_status(
                update_reputation_entity_customer_managed_status,
            )
            .get_account(get_account)
            .get_suppressed_destination(get_suppressed_destination)
            .put_suppressed_destination(put_suppressed_destination)
            .delete_suppressed_destination(delete_suppressed_destination)
            .list_suppressed_destinations(list_suppressed_destinations)
            .create_dedicated_ip_pool(create_dedicated_ip_pool)
            .put_dedicated_ip_in_pool(put_dedicated_ip_in_pool)
            .get_dedicated_ip(get_dedicated_ip)
            .get_dedicated_ips(get_dedicated_ips)
            .put_configuration_set_delivery_options(put_configuration_set_delivery_options)
            .create_configuration_set_event_destination(create_configuration_set_event_destination)
            .get_configuration_set_event_destinations(get_configuration_set_event_destinations)
            .update_configuration_set_event_destination(update_configuration_set_event_destination)
            .delete_configuration_set_event_destination(delete_configuration_set_event_destination)
            .create_email_template(create_email_template)
            .get_email_template(get_email_template)
            .update_email_template(update_email_template)
            .delete_email_template(delete_email_template)
            .list_email_templates(list_email_templates)
            .build_unchecked();
        let operations = Arc::clone(&self.acceptance.operations);
        let most = crate::listen::MOST_OPEN;
        crate::listen::accept(listener, Listener::Ses, most, &operations, |tcp| {
            Arc::clone(&self).connection(tcp, server.clone())
        })
        .await
    }

    async fn connection(self: Arc<Self>, tcp: TcpStream, server: Server) {
        let Ok(peer) = tcp.peer_addr().map(|peer| peer.ip()) else {
            return;
        };
        let Some(tls) = self.tls.accept(tcp).await else {
            return;
        };
        // Counted while open, so a stop lets its request under way finish
        // and the response reach the client. Once the stop
        // starts, it closes when that response is written, or at once if no
        // request is under way.
        let stop = Arc::clone(&self.acceptance.stop);
        let Some(_open) = stop.begin() else {
            return;
        };
        let closing = stop.closing();
        let service = hyper::service::service_fn(move |request| {
            let ses = Arc::clone(&self);
            let server = server.clone();
            async move {
                let mut response = ses.answer(request, server, peer).await;
                // Every answer names its request, as SES's do: SDKs give
                // it to their callers, which log it.
                if let Some(id) = request_id() {
                    response.headers_mut().insert("x-amzn-requestid", id);
                }
                Ok::<_, Infallible>(response)
            }
        });
        // A request's header, and the next request on a connection kept
        // open, wait so long at most.
        let connection = hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(HEADER)
            .serve_connection(TokioIo::new(tls), service);
        tokio::pin!(connection);
        tokio::select! {
            biased;
            _ = connection.as_mut() => return,
            () = closing.cancelled() => {}
        }
        connection.as_mut().graceful_shutdown();
        let _ = connection.await;
    }

    /// Reads a request whole, verifies its signature, and hands it to the
    /// server with the credential that signed it and the snapshot that
    /// holds it.
    async fn answer(
        self: Arc<Self>,
        request: http::Request<Incoming>,
        server: Server,
        peer: IpAddr,
    ) -> http::Response<BoxBody> {
        // SNS's certificates are served whatever else holds, so consumers
        // can go on verifying what was posted them.
        let sns = self.sns.clone();
        if let Some(sns) = &sns
            && request.method() == http::Method::GET
            && request.uri().path().starts_with(crate::sns::CERTIFICATES)
        {
            let (parts, _) = request.into_parts();
            return crate::sns::answer(&self, sns, &parts, &Bytes::new(), peer).await;
        }
        // Refused before it is read: in SNS's XML on its route, posted to
        // the root as AWS Query's are, else in SES's JSON.
        let on_sns = sns.is_some() && request.uri().path() == "/";
        let early = |refused: ErrorResponse| {
            if on_sns {
                crate::sns::early(&self, &refused)
            } else {
                error(refused)
            }
        };
        // An address past its failures is refused before its signature is
        // checked.
        if !self.acceptance.may_authenticate(peer) {
            return early(ErrorResponse::too_many_failures());
        }
        // One that arrives once the stop has started is refused. One under
        // way finishes, its connection counted until it is answered.
        if self.acceptance.stop.stopping() {
            return early(ErrorResponse::shutting_down());
        }
        // While the store cannot take more mail, before its body is read.
        if let Some(pressure) = self.acceptance.pressure() {
            return early(ErrorResponse::storage_pressed(pressure.reason()));
        }
        let (mut parts, body) = request.into_parts();
        // Its body is held against what every request not yet verified may
        // hold at once, by its length, nothing for one with no body, or the
        // most a request may be when its length is not known, until its
        // signature is verified.
        let most = mapping::max_request_bytes(self.acceptance.limits);
        let length = hyper::body::Body::size_hint(&body)
            .exact()
            .and_then(|length| usize::try_from(length).ok())
            .map_or(most, |length| length.min(most));
        let Some(unverified) = u32::try_from(length.div_ceil(1024)).ok().and_then(|kib| {
            Arc::clone(&self.unverified)
                .try_acquire_many_owned(kib)
                .ok()
        }) else {
            return early(ErrorResponse::busy());
        };
        let body = match tokio::time::timeout(BODY, Limited::new(body, most).collect()).await {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(_)) => return early(ErrorResponse::too_large()),
            Err(_) => return early(ErrorResponse::timed_out()),
        };
        // SNS's operations are posted to its root, as AWS Query's are.
        if parts.uri.path() == "/" {
            return match &sns {
                Some(sns) => crate::sns::answer(&self, sns, &parts, &body, peer).await,
                None => error(ErrorResponse::not_implemented(
                    parts.method.as_str(),
                    parts.uri.path(),
                )),
            };
        }
        let snapshot = self.policy.load();
        let credential: Arc<Credential> = {
            let headers: Vec<(&str, &[u8])> = parts
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes()))
                .collect();
            let signed = sigv4::Request {
                method: parts.method.as_str(),
                path: parts.uri.path(),
                query: parts.uri.query().unwrap_or_default(),
                headers: &headers,
                body: &body,
            };
            let now = self.clock.now().wall;
            match mapping::verify(
                &signed,
                snapshot.policy(),
                &self.region,
                mapping::SERVICE,
                now,
            ) {
                Ok(credential) => Arc::new(credential.clone()),
                Err(failure) => {
                    self.acceptance.authentication_failed(peer);
                    return error(ErrorResponse::denied(&failure));
                }
            }
        };
        drop(unverified);
        // Sending is its two operations; anything else manages.
        let sending = parts.method == http::Method::POST
            && matches!(
                parts.uri.path(),
                "/v2/email/outbound-emails" | "/v2/email/outbound-bulk-emails"
            );
        let permitted = if sending {
            credential.permissions.sends
        } else {
            credential.permissions.manages
        };
        if !permitted {
            return error(ErrorResponse::not_permitted(
                parts.method.as_str(),
                parts.uri.path(),
                sending,
            ));
        }
        let body = match mapping::older_listing(
            parts.method.as_str(),
            parts.uri.path(),
            parts.uri.query().unwrap_or_default(),
        ) {
            Some((path, listing)) => {
                parts.method = http::Method::POST;
                parts.uri = http::Uri::from_static(path);
                parts.headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                parts.headers.remove(http::header::CONTENT_LENGTH);
                Bytes::from(listing)
            }
            None => body,
        };
        parts.extensions.insert(Signed {
            snapshot,
            credential,
            peer,
        });
        parts.extensions.insert(self);
        let (method, path) = (parts.method.to_string(), parts.uri.path().to_owned());
        let response = match server
            .oneshot(http::Request::from_parts(parts, Full::new(body)))
            .await
        {
            Ok(response) => response,
            Err(never) => match never {},
        };
        // An operation with no handler the generated server answers as an
        // internal failure, which SDKs retry; no handler of the engine's
        // answers that, so it is an operation the engine does not
        // implement, refused for good.
        let missing = response.status() == StatusCode::INTERNAL_SERVER_ERROR
            && response
                .headers()
                .get("x-amzn-errortype")
                .is_some_and(|kind| kind == "InternalFailureException");
        if missing {
            return error(ErrorResponse::not_implemented(&method, &path));
        }
        response
    }

    /// How the account `signed` sends for names its resources.
    fn arns(&self, signed: &Signed) -> Arns<'_> {
        Arns {
            region: &self.region,
            account: signed.credential.account,
        }
    }

    pub(crate) fn new_id(&self) -> engine_core::id::Id {
        let now = self.clock.now().wall;
        self.ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next(now)
    }

    /// Commits a managing operation's `change`, its refusal answered as
    /// `refused` says, and returns the policy it made, which the store
    /// publishes before it answers.
    async fn change(
        &self,
        change: Change,
        refused: impl FnOnce(PolicyRefusal) -> Unmanaged,
    ) -> Result<Arc<Snapshot>, Unmanaged> {
        let command = Command::ChangePolicy(change);
        // A tenant's key is made before the change creating it is asked.
        let store = &self.acceptance.store;
        let answer = self
            .acceptance
            .sealer
            .ask(store, &self.policy, command)
            .await
            .map_err(|why| {
                tracing::error!(why = %why, "a tenant's key could not be made");
                Unmanaged::Busy("A tenant's key could not be made; try again".to_owned())
            })?;
        match answer {
            Some(Answer::Policy(Commit::Committed(_))) => Ok(self.policy.load()),
            Some(Answer::Policy(Commit::Refused(refusal))) => Err(refused(refusal)),
            _ => Err(Unmanaged::Busy(
                "Storage could not say whether it changed; try again".to_owned(),
            )),
        }
    }
}

/// A request's credential, and the snapshot it was verified under, which
/// its message is decided under too.
#[derive(Clone)]
struct Signed {
    snapshot: Arc<Snapshot>,
    credential: Arc<Credential>,
    /// The client's address, which SES-shaped events tag mail with.
    peer: IpAddr,
}

async fn send_email(
    input: SendEmailInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<SendEmailOutput, SendEmailError> {
    let received = std::time::Instant::now();
    let acceptance = &ses.acceptance;
    let recipients = mapping::check(&input, ses.max_recipients)?;
    let id = acceptance.message_id();
    let now = ses.clock.now().wall;
    let limits = acceptance.limits;
    let to = recipients.clone();
    let admitting = Arc::clone(&ses);
    let (authority, content, mail) = acceptance
        .prepare(id, move || {
            let Signed {
                snapshot,
                credential,
                peer,
            } = signed;
            // Its rates are charged what it comes to once composed, for the
            // tenant it is sent for.
            let admit = |tenant: Option<&str>, bytes| {
                admitting.acceptance.admit(
                    snapshot.policy(),
                    &credential,
                    tenant,
                    to.len() as u64,
                    bytes,
                )
            };
            let to = mapping::To {
                recipients: &to,
                source_ip: peer,
            };
            let arns = Arns {
                region: &admitting.region,
                account: credential.account,
            };
            mapping::content(
                &input,
                &snapshot,
                &credential,
                id,
                now,
                limits,
                to,
                arns,
                admit,
            )
        })
        .await
        .ok_or_else(mapping::unavailable)??;
    match acceptance
        .accept(authority, &recipients, id, content, mail, received)
        .await
    {
        Ok(commit) => mapping::answered(&commit, id),
        Err(Refused::Hook(refused)) => Err(mapping::admission_refused(&refused)),
        Err(Refused::Draining) => Err(mapping::pressed(Pressure::Draining.reason())),
    }
}

/// `SendBulkEmail`: its entries rendered and prepared on the
/// preparation pool, those that can be sent accepted together in one
/// commit, and each entry answered in the order it came.
async fn send_bulk_email(
    input: SendBulkEmailInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<SendBulkEmailOutput, SendBulkEmailError> {
    let received = std::time::Instant::now();
    let acceptance = &ses.acceptance;
    let checked = mapping::bulk_check(&input, ses.max_recipients)?;
    let recipients: usize = checked
        .iter()
        .filter_map(|entry| entry.as_ref().ok())
        .map(Vec::len)
        .sum();
    let ids: Vec<MessageId> = checked.iter().map(|_| acceptance.message_id()).collect();
    let now = ses.clock.now().wall;
    let limits = acceptance.limits;
    let first = ids[0];
    let admitting = Arc::clone(&ses);
    let (authority, prepared, checked, ids) = acceptance
        .prepare(first, move || {
            let Signed {
                snapshot,
                credential,
                peer,
            } = signed;
            // Its rates are charged what it comes to once rendered.
            let admit = |bytes| {
                admitting.acceptance.admit(
                    snapshot.policy(),
                    &credential,
                    input.tenant_name.as_ref().map(|name| name.as_str()),
                    recipients as u64,
                    bytes,
                )
            };
            mapping::bulk_content(
                &input,
                &snapshot,
                &credential,
                &checked,
                &ids,
                now,
                limits,
                peer,
                Arns {
                    region: &admitting.region,
                    account: credential.account,
                },
                admit,
            )
            .map(|(authority, prepared)| (authority, prepared, checked, ids))
        })
        .await
        .ok_or_else(|| mapping::bulk(mapping::unavailable()))??;
    // Each entry that can be sent, in its place; the rest answered already.
    let mut results: Vec<Option<BulkEmailEntryResult>> = Vec::with_capacity(ids.len());
    let mut messages = Vec::new();
    let mut places = Vec::new();
    for (place, ((recipients, content), id)) in
        checked.into_iter().zip(prepared).zip(&ids).enumerate()
    {
        match (recipients, content) {
            (Ok(recipients), Ok((content, mail))) => {
                messages.push(Prepared {
                    id: *id,
                    recipients,
                    content,
                    mail,
                });
                places.push(place);
                results.push(None);
            }
            (Err(result), _) | (_, Err(result)) => results.push(Some(result)),
        }
    }
    let (hooked, commit) = acceptance.accept_many(authority, messages, received).await;
    for (place, refused) in places.into_iter().zip(hooked) {
        let id = ids[place];
        results[place] = Some(match (refused, &commit) {
            (Some(refused), _) => mapping::failed(mapping::admission_refused(&refused)),
            (None, Some(Ok(commit))) => match mapping::answered(commit, id) {
                Ok(_) => mapping::entry_sent(id),
                Err(error) => mapping::failed(error),
            },
            (None, Some(Err(_))) => mapping::failed(mapping::pressed(Pressure::Draining.reason())),
            (None, None) => mapping::failed(mapping::unavailable()),
        });
    }
    Ok(mapping::bulk_answered(
        results.into_iter().flatten().collect(),
    ))
}

async fn create_email_identity(
    input: CreateEmailIdentityInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<CreateEmailIdentityOutput, CreateEmailIdentityError> {
    let account = signed.credential.account;
    let id = IdentityId(ses.new_id());
    let change = manage::create(&input, account, id, ses.clock.now().wall)?;
    let name = input.email_identity.as_str();
    let snapshot = ses
        .change(change, |refusal| manage::identity_refused(refusal, name))
        .await?;
    Ok(manage::created(manage::identity(
        snapshot.policy(),
        account,
        name,
    )?))
}

async fn get_email_identity(
    input: GetEmailIdentityInput,
    Extension(signed): Extension<Signed>,
) -> Result<GetEmailIdentityOutput, GetEmailIdentityError> {
    let policy = signed.snapshot.policy();
    let found = manage::identity(
        policy,
        signed.credential.account,
        input.email_identity.as_str(),
    )?;
    Ok(manage::got(policy, found))
}

async fn delete_email_identity(
    input: DeleteEmailIdentityInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<DeleteEmailIdentityOutput, DeleteEmailIdentityError> {
    let name = input.email_identity.as_str();
    let change = manage::delete(signed.credential.account, name);
    ses.change(change, |refusal| manage::identity_refused(refusal, name))
        .await?;
    Ok(DeleteEmailIdentityOutput {})
}

async fn list_email_identities(
    input: ListEmailIdentitiesInput,
    Extension(signed): Extension<Signed>,
) -> Result<ListEmailIdentitiesOutput, ListEmailIdentitiesError> {
    Ok(manage::list(
        signed.snapshot.policy(),
        signed.credential.account,
        &input,
    )?)
}

async fn put_email_identity_dkim_attributes(
    input: PutEmailIdentityDkimAttributesInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<PutEmailIdentityDkimAttributesOutput, PutEmailIdentityDkimAttributesError> {
    let name = input.email_identity.as_str();
    let change = manage::signs(
        signed.snapshot.policy(),
        signed.credential.account,
        name,
        input.signing_enabled,
    )?;
    ses.change(change, |refusal| manage::identity_refused(refusal, name))
        .await?;
    Ok(PutEmailIdentityDkimAttributesOutput {})
}

async fn put_email_identity_dkim_signing_attributes(
    input: PutEmailIdentityDkimSigningAttributesInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<PutEmailIdentityDkimSigningAttributesOutput, PutEmailIdentityDkimSigningAttributesError>
{
    let account = signed.credential.account;
    let change = manage::new_key(&input, account, ses.clock.now().wall)?;
    let name = input.email_identity.as_str();
    let snapshot = ses
        .change(change, |refusal| manage::identity_refused(refusal, name))
        .await?;
    Ok(manage::keyed(manage::identity(
        snapshot.policy(),
        account,
        name,
    )?))
}

async fn put_email_identity_feedback_attributes(
    input: PutEmailIdentityFeedbackAttributesInput,
    Extension(signed): Extension<Signed>,
) -> Result<PutEmailIdentityFeedbackAttributesOutput, PutEmailIdentityFeedbackAttributesError> {
    manage::feedback(
        signed.snapshot.policy(),
        signed.credential.account,
        input.email_identity.as_str(),
        input.email_forwarding_enabled,
    )?;
    Ok(PutEmailIdentityFeedbackAttributesOutput {})
}

async fn put_email_identity_mail_from_attributes(
    input: PutEmailIdentityMailFromAttributesInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<PutEmailIdentityMailFromAttributesOutput, PutEmailIdentityMailFromAttributesError> {
    let change = manage::mail_from(
        &input,
        signed.credential.account,
        ses.bounce_host.as_deref(),
        ses.clock.now().wall,
    )?;
    ses.change(change, |refusal| {
        manage::identity_refused(refusal, input.email_identity.as_str())
    })
    .await?;
    Ok(PutEmailIdentityMailFromAttributesOutput {})
}

async fn create_configuration_set(
    input: CreateConfigurationSetInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<CreateConfigurationSetOutput, CreateConfigurationSetError> {
    let id = ConfigurationId(ses.new_id());
    let change = manage::create_configuration(&input, signed.credential.account, id)?;
    let name = &input.configuration_set_name;
    ses.change(change, |refusal| {
        manage::configuration_refused(refusal, name)
    })
    .await?;
    Ok(CreateConfigurationSetOutput {})
}

async fn get_configuration_set(
    input: GetConfigurationSetInput,
    Extension(signed): Extension<Signed>,
) -> Result<GetConfigurationSetOutput, GetConfigurationSetError> {
    let policy = signed.snapshot.policy();
    let found = manage::configuration(
        policy,
        signed.credential.account,
        &input.configuration_set_name,
    )?;
    Ok(manage::got_configuration(policy, found))
}

async fn put_configuration_set_reputation_options(
    input: PutConfigurationSetReputationOptionsInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<PutConfigurationSetReputationOptionsOutput, PutConfigurationSetReputationOptionsError> {
    let name = &input.configuration_set_name;
    let change = Change::ReputationMetrics {
        account: signed.credential.account,
        configuration: name.clone(),
        enabled: input.reputation_metrics_enabled,
    };
    ses.change(change, |refusal| {
        manage::configuration_refused(refusal, name)
    })
    .await?;
    Ok(PutConfigurationSetReputationOptionsOutput {})
}

async fn create_tenant(
    input: CreateTenantInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<CreateTenantOutput, CreateTenantError> {
    let account = signed.credential.account;
    let id = TenantId(ses.new_id());
    let change = manage::create_tenant(&input, account, id, ses.clock.now().wall)?;
    let name = input.tenant_name.as_str();
    let snapshot = ses
        .change(change, |refusal| manage::tenant_refused(refusal, name))
        .await?;
    let policy = snapshot.policy();
    Ok(manage::created_tenant(
        policy,
        ses.arns(&signed),
        manage::tenant(policy, account, name)?,
    ))
}

async fn get_tenant(
    input: GetTenantInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<GetTenantOutput, GetTenantError> {
    let policy = signed.snapshot.policy();
    let found = manage::tenant(
        policy,
        signed.credential.account,
        input.tenant_name.as_str(),
    )?;
    Ok(manage::got_tenant(policy, ses.arns(&signed), found))
}

async fn list_configuration_sets(
    input: ListConfigurationSetsInput,
    Extension(signed): Extension<Signed>,
) -> Result<ListConfigurationSetsOutput, ListConfigurationSetsError> {
    Ok(manage::list_configurations(
        signed.snapshot.policy(),
        signed.credential.account,
        &input,
    )?)
}

async fn create_email_template(
    input: CreateEmailTemplateInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<CreateEmailTemplateOutput, CreateEmailTemplateError> {
    let id = TemplateId(ses.new_id());
    let now = ses.clock.now().wall;
    let change = manage::create_template(&input, signed.credential.account, id, now)?;
    let name = input.template_name.as_str();
    ses.change(change, |refusal| manage::template_refused(refusal, name))
        .await?;
    Ok(CreateEmailTemplateOutput {})
}

async fn get_email_template(
    input: GetEmailTemplateInput,
    Extension(signed): Extension<Signed>,
) -> Result<GetEmailTemplateOutput, GetEmailTemplateError> {
    let policy = signed.snapshot.policy();
    let found = manage::template(
        policy,
        signed.credential.account,
        input.template_name.as_str(),
    )?;
    Ok(manage::got_template(found)?)
}

async fn update_email_template(
    input: UpdateEmailTemplateInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<UpdateEmailTemplateOutput, UpdateEmailTemplateError> {
    let change = manage::update_template(&input, signed.credential.account)?;
    let name = input.template_name.as_str();
    ses.change(change, |refusal| manage::template_refused(refusal, name))
        .await?;
    Ok(UpdateEmailTemplateOutput {})
}

async fn delete_email_template(
    input: DeleteEmailTemplateInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<DeleteEmailTemplateOutput, DeleteEmailTemplateError> {
    let name = input.template_name.as_str();
    let change = Change::Remove(Target::Template {
        account: signed.credential.account,
        name: name.to_owned(),
    });
    ses.change(change, |refusal| manage::template_refused(refusal, name))
        .await?;
    Ok(DeleteEmailTemplateOutput {})
}

async fn list_email_templates(
    input: ListEmailTemplatesInput,
    Extension(signed): Extension<Signed>,
) -> Result<ListEmailTemplatesOutput, ListEmailTemplatesError> {
    Ok(manage::list_templates(
        signed.snapshot.policy(),
        signed.credential.account,
        &input,
    )?)
}

async fn list_tenants(
    input: ListTenantsInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<ListTenantsOutput, ListTenantsError> {
    Ok(manage::list_tenants(
        signed.snapshot.policy(),
        ses.arns(&signed),
        &input,
    )?)
}

async fn create_tenant_resource_association(
    input: CreateTenantResourceAssociationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<CreateTenantResourceAssociationOutput, CreateTenantResourceAssociationError> {
    associated(&ses, &signed, &input.tenant_name, &input.resource_arn, true).await?;
    Ok(CreateTenantResourceAssociationOutput {})
}

async fn delete_tenant_resource_association(
    input: DeleteTenantResourceAssociationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<DeleteTenantResourceAssociationOutput, DeleteTenantResourceAssociationError> {
    associated(
        &ses,
        &signed,
        &input.tenant_name,
        &input.resource_arn,
        false,
    )
    .await?;
    Ok(DeleteTenantResourceAssociationOutput {})
}

/// Associates the resource `arn` names with `tenant`, or with `associate`
/// false takes the association away.
async fn associated(
    ses: &Ses,
    signed: &Signed,
    tenant: &TenantName,
    arn: &AmazonResourceName,
    associate: bool,
) -> Result<(), Unmanaged> {
    let (tenant, arn) = (tenant.as_str(), arn.as_str());
    let change = manage::association(ses.arns(signed), tenant, arn, associate)?;
    ses.change(change, |refusal| {
        manage::association_refused(refusal, tenant, arn)
    })
    .await?;
    Ok(())
}

async fn list_tenant_resources(
    input: ListTenantResourcesInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<ListTenantResourcesOutput, ListTenantResourcesError> {
    Ok(manage::tenant_resources(
        signed.snapshot.policy(),
        ses.arns(&signed),
        &input,
    )?)
}

async fn list_resource_tenants(
    input: ListResourceTenantsInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<ListResourceTenantsOutput, ListResourceTenantsError> {
    Ok(manage::resource_tenants(
        signed.snapshot.policy(),
        ses.arns(&signed),
        &input,
    )?)
}

async fn get_reputation_entity(
    input: GetReputationEntityInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<GetReputationEntityOutput, GetReputationEntityError> {
    Ok(manage::reputation_entity(
        signed.snapshot.policy(),
        ses.arns(&signed),
        &input,
    )?)
}

async fn update_reputation_entity_customer_managed_status(
    input: UpdateReputationEntityCustomerManagedStatusInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<
    UpdateReputationEntityCustomerManagedStatusOutput,
    UpdateReputationEntityCustomerManagedStatusError,
> {
    let id = HoldId(ses.new_id());
    let changed = manage::customer_status(signed.snapshot.policy(), ses.arns(&signed), &input, id)?;
    let Some(change) = changed else {
        return Ok(UpdateReputationEntityCustomerManagedStatusOutput {});
    };
    let reference = input.reputation_entity_reference.as_str();
    match ses
        .acceptance
        .store
        .ask(Command::ChangePolicy(change))
        .await
    {
        // Lifted meanwhile is enabled, as asked.
        Some(Answer::Policy(
            Commit::Committed(_) | Commit::Refused(PolicyRefusal::Unknown { kind: "hold", .. }),
        )) => {}
        Some(Answer::Policy(Commit::Refused(_))) => {
            return Err(Unmanaged::NotFound(format!(
                "{reference} is no longer a resource of this account."
            ))
            .into());
        }
        _ => return Err(Unmanaged::Busy("Storage could not say; try again".to_owned()).into()),
    }
    Ok(UpdateReputationEntityCustomerManagedStatusOutput {})
}

async fn get_account(
    _input: GetAccountInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<GetAccountOutput, GetAccountError> {
    let account = signed.credential.account;
    let now = ses.clock.now().wall;
    let sent = match ses
        .acceptance
        .store
        .ask(Command::Sent { account, now })
        .await
    {
        Some(Answer::Sent(Ok(sent))) => sent,
        _ => {
            return Err(Unmanaged::Busy("Storage is unavailable; try again".to_owned()).into());
        }
    };
    Ok(manage::account(signed.snapshot.policy(), account, sent))
}

async fn create_dedicated_ip_pool(
    input: CreateDedicatedIpPoolInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<CreateDedicatedIpPoolOutput, CreateDedicatedIpPoolError> {
    let id = PoolId(ses.new_id());
    let change = manage::create_pool(&input, signed.credential.account, id)?;
    let name = &input.pool_name;
    ses.change(change, |refusal| manage::pool_refused(refusal, name))
        .await?;
    Ok(CreateDedicatedIpPoolOutput {})
}

async fn put_dedicated_ip_in_pool(
    input: PutDedicatedIpInPoolInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<PutDedicatedIpInPoolOutput, PutDedicatedIpInPoolError> {
    let change = manage::into_pool(&input, signed.credential.account)?;
    let name = &input.destination_pool_name;
    ses.change(change, |refusal| manage::pool_refused(refusal, name))
        .await?;
    Ok(PutDedicatedIpInPoolOutput {})
}

async fn get_dedicated_ip(
    input: GetDedicatedIpInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<GetDedicatedIpOutput, GetDedicatedIpError> {
    let policy = signed.snapshot.policy();
    Ok(manage::dedicated_ip(
        policy,
        signed.credential.account,
        &input,
        &ses.ladder,
    )?)
}

async fn get_dedicated_ips(
    input: GetDedicatedIpsInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<GetDedicatedIpsOutput, GetDedicatedIpsError> {
    let policy = signed.snapshot.policy();
    Ok(manage::dedicated_ips(
        policy,
        signed.credential.account,
        &input,
        &ses.ladder,
    )?)
}

async fn put_configuration_set_delivery_options(
    input: PutConfigurationSetDeliveryOptionsInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<PutConfigurationSetDeliveryOptionsOutput, PutConfigurationSetDeliveryOptionsError> {
    let change = manage::delivery_options(&input, signed.credential.account)?;
    let name = input.sending_pool_name.as_deref().unwrap_or_default();
    ses.change(change, |refusal| manage::pool_refused(refusal, name))
        .await?;
    Ok(PutConfigurationSetDeliveryOptionsOutput {})
}

async fn create_configuration_set_event_destination(
    input: CreateConfigurationSetEventDestinationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<CreateConfigurationSetEventDestinationOutput, CreateConfigurationSetEventDestinationError>
{
    let (configuration, name) = (&input.configuration_set_name, &input.event_destination_name);
    let id = DestinationId(ses.new_id());
    let change = manage::destination(
        configuration,
        name,
        &input.event_destination,
        signed.credential.account,
        &ses.region,
        id,
        false,
    )?;
    ses.change(change, |refusal| {
        manage::destination_refused(refusal, configuration, name)
    })
    .await?;
    Ok(CreateConfigurationSetEventDestinationOutput {})
}

async fn get_configuration_set_event_destinations(
    input: GetConfigurationSetEventDestinationsInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<GetConfigurationSetEventDestinationsOutput, GetConfigurationSetEventDestinationsError> {
    let policy = signed.snapshot.policy();
    let configuration = manage::configuration(
        policy,
        signed.credential.account,
        &input.configuration_set_name,
    )?;
    Ok(manage::destinations(policy, configuration, &ses.region))
}

async fn update_configuration_set_event_destination(
    input: UpdateConfigurationSetEventDestinationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<UpdateConfigurationSetEventDestinationOutput, UpdateConfigurationSetEventDestinationError>
{
    let (configuration, name) = (&input.configuration_set_name, &input.event_destination_name);
    let id = DestinationId(ses.new_id());
    let change = manage::destination(
        configuration,
        name,
        &input.event_destination,
        signed.credential.account,
        &ses.region,
        id,
        true,
    )?;
    ses.change(change, |refusal| {
        manage::destination_refused(refusal, configuration, name)
    })
    .await?;
    Ok(UpdateConfigurationSetEventDestinationOutput {})
}

async fn delete_configuration_set_event_destination(
    input: DeleteConfigurationSetEventDestinationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<DeleteConfigurationSetEventDestinationOutput, DeleteConfigurationSetEventDestinationError>
{
    let (configuration, name) = (&input.configuration_set_name, &input.event_destination_name);
    let change = manage::delete_destination(signed.credential.account, configuration, name);
    ses.change(change, |refusal| {
        manage::destination_refused(refusal, configuration, name)
    })
    .await?;
    Ok(DeleteConfigurationSetEventDestinationOutput {})
}

/// What the store answers to `command`, or SES's refusal for now.
async fn asked(ses: &Ses, command: Command) -> Result<Answer, Unmanaged> {
    ses.acceptance
        .store
        .ask(command)
        .await
        .ok_or_else(|| Unmanaged::Busy("Storage is unavailable; try again".to_owned()))
}

fn unavailable() -> Unmanaged {
    Unmanaged::Busy("Storage could not say; try again".to_owned())
}

async fn get_suppressed_destination(
    input: GetSuppressedDestinationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<GetSuppressedDestinationOutput, GetSuppressedDestinationError> {
    let command = manage::suppression(&input, signed.credential.account)?;
    match asked(&ses, command).await? {
        Answer::Suppression(Ok(found)) => Ok(manage::got_suppression(&input, found)?),
        _ => Err(unavailable().into()),
    }
}

async fn put_suppressed_destination(
    input: PutSuppressedDestinationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<PutSuppressedDestinationOutput, PutSuppressedDestinationError> {
    let command = manage::suppress(&input, signed.credential.account, ses.clock.now().wall)?;
    match asked(&ses, command).await? {
        Answer::Suppressions(Commit::Committed(_)) => Ok(PutSuppressedDestinationOutput {}),
        _ => Err(unavailable().into()),
    }
}

async fn delete_suppressed_destination(
    input: DeleteSuppressedDestinationInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<DeleteSuppressedDestinationOutput, DeleteSuppressedDestinationError> {
    let command = manage::unsuppress(&input, signed.credential.account)?;
    match asked(&ses, command).await? {
        Answer::Suppressions(Commit::Committed(0)) => Err(manage::not_suppressed(&input).into()),
        Answer::Suppressions(Commit::Committed(_)) => Ok(DeleteSuppressedDestinationOutput {}),
        _ => Err(unavailable().into()),
    }
}

async fn list_suppressed_destinations(
    input: ListSuppressedDestinationsInput,
    Extension(ses): Extension<Arc<Ses>>,
    Extension(signed): Extension<Signed>,
) -> Result<ListSuppressedDestinationsOutput, ListSuppressedDestinationsError> {
    let command = manage::suppressions(&input, signed.credential.account)?;
    match asked(&ses, command).await? {
        Answer::SuppressionPage(Ok(page)) => Ok(manage::listed_suppressions(page)),
        _ => Err(unavailable().into()),
    }
}

fn error(answer: ErrorResponse) -> http::Response<BoxBody> {
    let mut response = http::Response::new(to_boxed(answer.body));
    *response.status_mut() = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::FORBIDDEN);
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert("x-amzn-errortype", HeaderValue::from_static(answer.code));
    response
}

/// A request's ID, as SES gives each: a random UUID.
fn request_id() -> Option<HeaderValue> {
    let mut id = [0u8; 16];
    aws_lc_rs::rand::fill(&mut id).ok()?;
    // Version 4, variant 1.
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    let hex: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
    let text = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    HeaderValue::from_str(&text).ok()
}
