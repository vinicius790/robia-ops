//! Cliente e parser HTTP/1.1 (RFC 9110/9112) rodando diretamente sobre o TCP deste stack.

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn get(host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: "GET".into(),
            path: path.into(),
            host: host.into(),
            headers: vec![("Connection".into(), "close".into())],
            body: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            self.method, self.path, self.host
        );
        if !self.body.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        let sep = find_header_end(raw).ok_or(Error::WouldBlock)?;
        let head = std::str::from_utf8(&raw[..sep])
            .map_err(|_| Error::Unsupported("http: cabeçalho não-UTF8"))?;
        let mut lines = head.split("\r\n");
        let req_line = lines
            .next()
            .ok_or(Error::Unsupported("http: request vazio"))?;
        let mut parts = req_line.split_whitespace();
        let method = parts
            .next()
            .ok_or(Error::Unsupported("http: método ausente"))?
            .to_string();
        let path = parts
            .next()
            .ok_or(Error::Unsupported("http: path ausente"))?
            .to_string();
        let mut host = String::new();
        let mut headers = Vec::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("host") {
                    host = val.clone();
                } else {
                    headers.push((key, val));
                }
            }
        }
        Ok(Self {
            method,
            path,
            host,
            headers,
            body: raw[sep + 4..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Type".into(), "text/plain; charset=utf-8".into()),
                ("Connection".into(), "close".into()),
            ],
            body: body.into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
            self.status,
            self.reason,
            self.body.len()
        );
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        let sep = find_header_end(raw).ok_or(Error::WouldBlock)?;
        let head = std::str::from_utf8(&raw[..sep])
            .map_err(|_| Error::Unsupported("http: resposta não-UTF8"))?;
        let mut lines = head.split("\r\n");
        let status_line = lines
            .next()
            .ok_or(Error::Unsupported("http: resposta vazia"))?;
        let mut parts = status_line.splitn(3, ' ');
        let _version = parts
            .next()
            .ok_or(Error::Unsupported("http: versão ausente"))?;
        let status: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::Unsupported("http: status inválido"))?;
        let reason = parts.next().unwrap_or("").to_string();

        let mut headers = Vec::new();
        let mut content_length: Option<usize> = None;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = val.parse().ok();
                }
                headers.push((key, val));
            }
        }
        let body_slice = &raw[sep + 4..];
        if let Some(expected) = content_length {
            if body_slice.len() < expected {
                return Err(Error::WouldBlock);
            }
            return Ok(Self {
                status,
                reason,
                headers,
                body: body_slice[..expected].to_vec(),
            });
        }
        Ok(Self {
            status,
            reason,
            headers,
            body: body_slice.to_vec(),
        })
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_response_roundtrip() {
        let req = HttpRequest::get("example.local", "/health");
        let parsed_req = HttpRequest::parse(&req.encode()).unwrap();
        assert_eq!(parsed_req.method, "GET");
        assert_eq!(parsed_req.path, "/health");
        assert_eq!(parsed_req.host, "example.local");

        let resp = HttpResponse::ok(b"ok-200".to_vec());
        let parsed_resp = HttpResponse::parse(&resp.encode()).unwrap();
        assert_eq!(parsed_resp.status, 200);
        assert_eq!(parsed_resp.body, b"ok-200");
    }
}
