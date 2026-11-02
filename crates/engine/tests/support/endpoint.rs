//! An HTTP endpoint on loopback that events are posted to: it answers 503
//! until it takes, then 200, and keeps every post's headers and body.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

/// A post it was sent: its headers, their names in lowercase, and its body.
#[derive(Clone, Debug)]
pub struct Posted {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Posted {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

pub struct Endpoint {
    pub url: String,
    pub taking: Arc<AtomicBool>,
    posts: Arc<Mutex<Vec<Posted>>>,
}

impl Endpoint {
    /// One at `path`, taking what it is posted if `taking`.
    pub fn start(path: &str, taking: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let url = format!("http://{}{path}", listener.local_addr().expect("bound"));
        let taking = Arc::new(AtomicBool::new(taking));
        let posts = Arc::new(Mutex::new(Vec::new()));
        let (took, kept) = (Arc::clone(&taking), Arc::clone(&posts));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (took, kept) = (Arc::clone(&took), Arc::clone(&kept));
                std::thread::spawn(move || serve(stream, &took, &kept));
            }
        });
        Self { url, taking, posts }
    }

    pub fn posts(&self) -> Vec<Posted> {
        self.posts.lock().expect("not poisoned").clone()
    }

    /// Each post's body, as JSON.
    pub fn bodies(&self) -> Vec<Value> {
        self.posts().iter().map(Posted::json).collect()
    }
}

/// Answers each request on one kept connection.
fn serve(stream: TcpStream, taking: &AtomicBool, posts: &Mutex<Vec<Posted>>) {
    let mut writer = stream.try_clone().expect("a clone");
    let mut reader = BufReader::new(stream);
    loop {
        let mut length = 0;
        let mut headers = Vec::new();
        let mut line = String::new();
        // The request line, then its headers.
        let mut first = true;
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
            if std::mem::take(&mut first) {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_owned());
                if name == "content-length" {
                    length = value.parse().unwrap_or(0);
                }
                headers.push((name, value));
            }
        }
        let mut body = vec![0; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        posts
            .lock()
            .expect("not poisoned")
            .push(Posted { headers, body });
        let status = if taking.load(Ordering::SeqCst) {
            "200 OK"
        } else {
            "503 Service Unavailable"
        };
        let answer = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\n\r\n");
        if writer.write_all(answer.as_bytes()).is_err() {
            return;
        }
    }
}
