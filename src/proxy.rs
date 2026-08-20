//! The forward proxy: plain HTTP in absolute-form, and HTTPS via `CONNECT` with TLS terminated
//! against the run's own CA so response bodies can be cached.

use crate::ca::Ca;
use crate::entry::Entry;
use crate::policy::{Policy, Reject};
use crate::stats::{Outcome, Stats};
use crate::store::Store;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderMap, HeaderName};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use url::Url;

type ResBody = BoxBody<Bytes, std::io::Error>;

/// Headers scoped to a single hop, dropped in both directions.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub struct Proxy {
    ca: Arc<Ca>,
    policy: Policy,
    store: Arc<Store>,
    stats: Arc<Stats>,
    /// Redirects are followed inside the proxy for cacheable requests so that the entry is keyed
    /// on the stable URL the client asked for. Release downloads in particular redirect to a
    /// pre-signed URL that differs on every request and could never be cached on its own.
    fetcher: reqwest::Client,
    forwarder: reqwest::Client,
    mitm_ports: Vec<u16>,
    shutdown: watch::Sender<bool>,
}

impl Proxy {
    pub fn new(
        ca: Arc<Ca>,
        policy: Policy,
        store: Arc<Store>,
        stats: Arc<Stats>,
        mitm_ports: Vec<u16>,
        follow_redirects: bool,
        shutdown: watch::Sender<bool>,
    ) -> Result<Arc<Self>> {
        let redirect = if follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        };
        // `no_proxy` matters: the proxy exports HTTP_PROXY into the job environment, and without
        // this its own upstream requests would come back to itself.
        let fetcher = reqwest::Client::builder()
            .no_proxy()
            .redirect(redirect)
            .build()?;
        let forwarder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Arc::new(Self {
            ca,
            policy,
            store,
            stats,
            fetcher,
            forwarder,
            mitm_ports,
            shutdown,
        }))
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        let mut shutdown = self.shutdown.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let proxy = self.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |req| {
                            let proxy = proxy.clone();
                            async move { proxy.dispatch(req, None).await }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .with_upgrades()
                            .await;
                    });
                }
            }
        }
    }

    /// Entry point for every request. `tunnel_authority` is set for requests arriving inside a
    /// decrypted `CONNECT` tunnel, where the URI is in origin-form and the host is only known from
    /// the tunnel it arrived on.
    async fn dispatch(
        self: Arc<Self>,
        req: Request<Incoming>,
        tunnel_authority: Option<String>,
    ) -> Result<Response<ResBody>, Infallible> {
        if tunnel_authority.is_none() {
            if req.method() == Method::CONNECT {
                return Ok(self.connect(req));
            }
            if req.uri().authority().is_none() {
                return Ok(self.control(req));
            }
        }

        let url = match absolute_url(&req, tunnel_authority.as_deref()) {
            Ok(url) => url,
            Err(err) => return Ok(bad_request(&format!("{err:#}"))),
        };

        match self.handle(req, url.clone()).await {
            Ok(response) => Ok(response),
            Err(err) => {
                let message = format!("{err:#}");
                self.stats
                    .record(&Outcome::Error(&message), "GET", url.as_str(), 0, 0);
                Ok(bad_gateway(&message))
            }
        }
    }

    /// Endpoints for the wrapper steps, reachable only in origin-form directly at the listener.
    fn control(&self, req: Request<Incoming>) -> Response<ResBody> {
        match req.uri().path() {
            "/__cicache/ping" => text(StatusCode::OK, "ok"),
            "/__cicache/stats" => {
                let body = serde_json::to_string_pretty(&self.stats.summary()).unwrap_or_default();
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(full(Bytes::from(body)))
                    .unwrap()
            }
            "/__cicache/shutdown" => {
                let _ = self.shutdown.send(true);
                text(StatusCode::OK, "shutting down")
            }
            _ => text(StatusCode::NOT_FOUND, "unknown control endpoint"),
        }
    }

    fn connect(self: Arc<Self>, mut req: Request<Incoming>) -> Response<ResBody> {
        let Some(authority) = req.uri().authority().cloned() else {
            return bad_request("CONNECT without authority");
        };
        let host = authority.host().to_string();
        let port = authority.port_u16().unwrap_or(443);
        let intercept = self.mitm_ports.contains(&port);

        tokio::spawn(async move {
            let upgraded = match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => TokioIo::new(upgraded),
                Err(err) => {
                    eprintln!("cicache: CONNECT upgrade to {host}:{port} failed: {err}");
                    return;
                }
            };

            let result = if intercept {
                self.clone().intercept(upgraded, host.clone(), port).await
            } else {
                self.stats.record(
                    &Outcome::Pass("tunnelled port"),
                    "CONNECT",
                    &format!("{host}:{port}"),
                    0,
                    0,
                );
                tunnel(upgraded, &host, port).await
            };
            if let Err(err) = result {
                eprintln!("cicache: connection to {host}:{port} failed: {err:#}");
            }
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(empty())
            .unwrap()
    }

    async fn intercept<I>(self: Arc<Self>, io: I, host: String, port: u16) -> Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let config = self.ca.server_config(&host)?;
        let tls = TlsAcceptor::from(config).accept(io).await?;
        let authority = if port == 443 {
            host
        } else {
            format!("{host}:{port}")
        };

        let service = service_fn(move |req| {
            let proxy = self.clone();
            let authority = authority.clone();
            async move { proxy.dispatch(req, Some(authority)).await }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(tls), service)
            .await?;
        Ok(())
    }

    async fn handle(&self, req: Request<Incoming>, url: Url) -> Result<Response<ResBody>> {
        let method = req.method().clone();
        let client_headers = req.headers().clone();
        let body = req.into_body().collect().await?.to_bytes();

        let eligible = self.policy.request_eligible(&method, &url, &client_headers);
        if let Err(reject) = eligible {
            return self
                .forward(method, url, client_headers, body, reject)
                .await;
        }

        let key = self.policy.key(&url);
        if let Some(raw) = self.store.get(&key).await {
            match Entry::decode(&raw) {
                Ok(entry) => {
                    let len = entry.body.len() as u64;
                    self.stats
                        .record(&Outcome::Hit, method.as_str(), url.as_str(), len, 0);
                    return Ok(replay(entry));
                }
                Err(err) => {
                    eprintln!("cicache: discarding entry for {url}: {err:#}");
                }
            }
        }

        self.fetch_and_store(method, url, client_headers, key).await
    }

    async fn fetch_and_store(
        &self,
        method: Method,
        url: Url,
        client_headers: HeaderMap,
        key: String,
    ) -> Result<Response<ResBody>> {
        // Entries are stored and replayed as received, so the encoding is pinned to identity
        // rather than being negotiated per client.
        let mut upstream_headers = sanitize(&client_headers);
        upstream_headers.remove(hyper::header::ACCEPT_ENCODING);
        upstream_headers.insert(hyper::header::ACCEPT_ENCODING, "identity".parse()?);

        let started = Instant::now();
        let response = self
            .fetcher
            .request(method.clone(), url.as_str())
            .headers(upstream_headers)
            .send()
            .await?;

        let status = response.status();
        let headers = sanitize(response.headers());
        let declared = response.content_length().unwrap_or(0);

        // Streaming past the ceiling avoids holding a large artifact in memory only to reject it.
        if declared > self.policy.max_size {
            let elapsed = started.elapsed().as_millis() as u64;
            self.stats.record(
                &Outcome::Miss(Reject::TooLarge.as_str()),
                method.as_str(),
                url.as_str(),
                declared,
                elapsed,
            );
            return Ok(stream_response(status, headers, response, "MISS"));
        }

        let body = response.bytes().await?;
        let elapsed = started.elapsed().as_millis() as u64;
        let len = body.len() as u64;

        let storable = self
            .policy
            .response_storable(&url, status.as_u16(), &headers, len);
        let outcome = match storable {
            Ok(()) => {
                let entry = Entry::new(url.as_str(), status.as_u16(), &headers, body.clone());
                match entry.encode() {
                    Ok(encoded) => {
                        self.store.put(key, encoded).await;
                        Outcome::Stored
                    }
                    Err(err) => {
                        eprintln!("cicache: encoding entry for {url} failed: {err:#}");
                        Outcome::Miss("encode failed")
                    }
                }
            }
            Err(reject) => Outcome::Miss(reject.as_str()),
        };
        self.stats
            .record(&outcome, method.as_str(), url.as_str(), len, elapsed);

        Ok(build(status, headers, body, "MISS"))
    }

    /// Passes a request through untouched, streaming the body in both directions.
    async fn forward(
        &self,
        method: Method,
        url: Url,
        client_headers: HeaderMap,
        body: Bytes,
        reject: Reject,
    ) -> Result<Response<ResBody>> {
        let started = Instant::now();
        let response = self
            .forwarder
            .request(method.clone(), url.as_str())
            .headers(sanitize(&client_headers))
            .body(body)
            .send()
            .await?;

        let status = response.status();
        let headers = sanitize(response.headers());
        let elapsed = started.elapsed().as_millis() as u64;
        self.stats.record(
            &Outcome::Pass(reject.as_str()),
            method.as_str(),
            url.as_str(),
            response.content_length().unwrap_or(0),
            elapsed,
        );
        Ok(stream_response(status, headers, response, "PASS"))
    }
}

/// Reconstructs the absolute URL a request is for. Absolute-form arrives from plain HTTP clients;
/// origin-form arrives inside a decrypted tunnel and is completed from the tunnel's authority.
fn absolute_url(req: &Request<Incoming>, tunnel_authority: Option<&str>) -> Result<Url> {
    if let Some(authority) = tunnel_authority {
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        return Ok(Url::parse(&format!("https://{authority}{path}"))?);
    }
    Url::parse(&req.uri().to_string()).map_err(|err| anyhow!("unparsable request URI: {err}"))
}

fn sanitize(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if HOP_BY_HOP.contains(&name.as_str()) || name == hyper::header::HOST {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn replay(entry: Entry) -> Response<ResBody> {
    let status = StatusCode::from_u16(entry.header.status).unwrap_or(StatusCode::OK);
    let headers = entry.header_map();
    build(status, headers, entry.body, "HIT")
}

fn build(status: StatusCode, headers: HeaderMap, body: Bytes, cache: &str) -> Response<ResBody> {
    let mut response = Response::builder().status(status);
    if let Some(target) = response.headers_mut() {
        *target = headers;
        target.remove(hyper::header::CONTENT_LENGTH);
        target.insert(
            hyper::header::CONTENT_LENGTH,
            body.len()
                .to_string()
                .parse()
                .expect("length is a valid header value"),
        );
        insert_cache_header(target, cache);
    }
    response.body(full(body)).expect("response is well-formed")
}

fn stream_response(
    status: StatusCode,
    headers: HeaderMap,
    response: reqwest::Response,
    cache: &str,
) -> Response<ResBody> {
    let stream = response
        .bytes_stream()
        .map_ok(Frame::data)
        .map_err(std::io::Error::other);

    let mut builder = Response::builder().status(status);
    if let Some(target) = builder.headers_mut() {
        *target = headers;
        insert_cache_header(target, cache);
    }
    builder
        .body(StreamBody::new(stream).boxed())
        .expect("response is well-formed")
}

fn insert_cache_header(headers: &mut HeaderMap, cache: &str) {
    if let Ok(value) = cache.parse() {
        headers.insert(HeaderName::from_static("x-cicache"), value);
    }
}

async fn tunnel<I>(mut client: I, host: &str, port: u16) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut server = TcpStream::connect((host, port)).await?;
    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}

fn full(body: Bytes) -> ResBody {
    Full::new(body)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn empty() -> ResBody {
    full(Bytes::new())
}

fn text(status: StatusCode, message: &str) -> Response<ResBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(full(Bytes::from(format!("{message}\n"))))
        .expect("response is well-formed")
}

fn bad_request(message: &str) -> Response<ResBody> {
    text(StatusCode::BAD_REQUEST, message)
}

fn bad_gateway(message: &str) -> Response<ResBody> {
    text(StatusCode::BAD_GATEWAY, message)
}
