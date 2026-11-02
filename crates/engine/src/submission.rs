//! SMTP submission: the listener, and a task per connection running the
//! server session. A login is checked against the policy snapshot of its
//! moment, and each transaction is decided under the snapshot current when
//! it arrives, so a login removed since stops sending. A transaction is
//! prepared and accepted through the shared acceptance, and its reply goes
//! back only once the acceptance has committed.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use engine_api::snapshot::{Tagged, own_from};
use engine_api::submission as mapping;
use engine_core::component::Component;
use engine_core::id::CredentialId;
use engine_core::policy::Denial;
use engine_smtp::reply::Reply;
use engine_smtp::server::{Config, Input, Output, Session, Transaction};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::acceptance::{Acceptance, Refused};
use crate::clock::SystemClock;
use crate::operator::{Listener, Pressure};
use crate::policy::Current;
use crate::stream::{self, Read};

pub struct Submission {
    pub session: Arc<Config>,
    /// Its certificate, which a reload replaces.
    pub tls: Arc<crate::tls::Certified>,
    pub policy: Arc<Current>,
    pub acceptance: Arc<Acceptance>,
    pub clock: Arc<SystemClock>,
}

impl Submission {
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<(), String> {
        let operations = Arc::clone(&self.acceptance.operations);
        let most = crate::listen::MOST_OPEN;
        crate::listen::accept(listener, Listener::Submission, most, &operations, |tcp| {
            Arc::clone(&self).connection(tcp)
        })
        .await
    }

    async fn connection(self: Arc<Self>, tcp: TcpStream) {
        let Ok(peer) = tcp.peer_addr().map(|peer| peer.ip()) else {
            return;
        };
        let mut session = Session::new(Arc::clone(&self.session));
        let mut login = None;
        let Ok(Some(tcp)) = self.drive(&mut session, &mut login, peer, tcp).await else {
            return;
        };
        let Some(tls) = self.tls.accept(tcp).await else {
            return;
        };
        session.handle(self.clock.now(), Input::TlsStarted);
        let _ = self.drive(&mut session, &mut login, peer, tls).await;
    }

    /// Runs the session over `stream` until it closes, or until it asks for
    /// TLS, when the stream comes back for the handshake.
    async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        session: &mut Session,
        login: &mut Option<CredentialId>,
        peer: IpAddr,
        mut stream: S,
    ) -> io::Result<Option<S>> {
        let mut out = Vec::new();
        let mut pending: Vec<Bytes> = Vec::new();
        let mut buffer = Vec::new();
        // A transaction is counted until its reply is written, so a stop
        // lets it finish.
        let mut _under_way = None;
        loop {
            let deadline = session.poll(self.clock.now(), &mut out);
            let mut answered = false;
            for output in out.drain(..) {
                match output {
                    Output::Send(bytes) => pending.push(Bytes::from(bytes)),
                    Output::StartTls => {
                        stream::write(&mut stream, &mut pending).await?;
                        return Ok(Some(stream));
                    }
                    Output::Close => {
                        stream::write(&mut stream, &mut pending).await?;
                        stream::close(&mut stream).await;
                        return Ok(None);
                    }
                    Output::Authenticate { user, password } => {
                        // An address past its failures is refused before its
                        // credentials are checked.
                        let snapshot = self.policy.load();
                        let credential = self
                            .acceptance
                            .may_authenticate(peer)
                            .then(|| mapping::authenticate(snapshot.policy(), &user, &password))
                            .flatten();
                        let verdict = credential.is_some();
                        match credential {
                            Some(credential) => *login = Some(credential.id),
                            None => self.acceptance.authentication_failed(peer),
                        }
                        session.handle(self.clock.now(), Input::Authenticated(verdict));
                        answered = true;
                    }
                    // Submission takes any recipient it can parse, while the
                    // store can take more mail.
                    Output::Recipient => {
                        let verdict = match self.acceptance.pressure() {
                            None => Ok(()),
                            Some(Pressure::Disk) => Err(mapping::storage_full()),
                            Some(Pressure::Pending) => Err(mapping::storage_busy()),
                            Some(Pressure::Draining) => Err(mapping::draining()),
                        };
                        session.handle(self.clock.now(), Input::Recipient(verdict));
                        answered = true;
                    }
                    Output::Submit(transaction) => {
                        stream::write(&mut stream, &mut pending).await?;
                        let reply = match self.acceptance.stop.begin() {
                            Some(transaction_under_way) => {
                                _under_way = Some(transaction_under_way);
                                self.submit(*login, transaction, peer).await
                            }
                            None => mapping::shutting_down(),
                        };
                        session.handle(self.clock.now(), Input::Answered(reply));
                        answered = true;
                    }
                }
            }
            // An answer given at once needs no write of its own: what is
            // pending goes out together before the next read.
            if answered {
                continue;
            }
            stream::write(&mut stream, &mut pending).await?;
            _under_way = None;
            match stream::read(&mut stream, &mut buffer, deadline, &self.clock).await? {
                Read::Bytes(bytes) => session.handle(self.clock.now(), Input::Received(bytes)),
                Read::Deadline => {}
                Read::Closed => return Ok(None),
            }
        }
    }

    /// Prepares, signs and accepts a transaction, and returns its reply.
    async fn submit(
        &self,
        login: Option<CredentialId>,
        transaction: Transaction,
        peer: IpAddr,
    ) -> Reply {
        let received = std::time::Instant::now();
        let unavailable = || Reply::new(451, "4.3.0 Try again later");
        let Some(login) = login else {
            return Reply::new(530, "5.7.0 Authentication required");
        };
        let snapshot = self.policy.load();
        let Some(credential) = snapshot.policy().credential(login).cloned() else {
            return mapping::denied(Denial::UnknownCredential);
        };
        let acceptance = &self.acceptance;
        let recipients = transaction.recipients.len() as u64;
        let id = acceptance.message_id();
        let limits = acceptance.limits;
        let content = transaction.content;
        let to = transaction.recipients.clone();
        let admitting = Arc::clone(acceptance);
        let prepared = acceptance
            .prepare(id, move || {
                // Its rates are charged for the tenant its `X-SES-TENANT`
                // names, if it names one, as SES sends it for that tenant.
                let admit = |tenant: Option<&str>, bytes| {
                    admitting.admit(snapshot.policy(), &credential, tenant, recipients, bytes)
                };
                let (authority, prepared) =
                    snapshot.prepare(&content, limits, &credential, None, None, None, admit)?;
                let mail = snapshot.mail(&authority, &content, &prepared, &to, || {
                    let tagged = Tagged {
                        operation: "SendSmtpEmail",
                        caller: engine_api::ses::caller(&credential),
                        source_ip: peer,
                        given: Vec::new(),
                    };
                    Some((own_from(&prepared)?, tagged))
                });
                Ok((authority, prepared, mail))
            })
            .await;
        let (authority, content, mail) = match prepared {
            Some(Ok(prepared)) => prepared,
            Some(Err(unprepared)) => return mapping::unprepared(&unprepared),
            None => return unavailable(),
        };
        match acceptance
            .accept(
                authority,
                &transaction.recipients,
                id,
                content,
                mail,
                received,
            )
            .await
        {
            Ok(commit) => mapping::answered(&commit, id),
            Err(Refused::Hook(refused)) => mapping::admission_refused(&refused),
            Err(Refused::Draining) => mapping::draining(),
        }
    }
}
