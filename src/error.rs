//! Erros do stack.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("frame truncado em {layer}: precisa {need}, veio {got}")]
    Truncated {
        layer: &'static str,
        need: usize,
        got: usize,
    },

    #[error("checksum inválido: {0}")]
    BadChecksum(&'static str),

    #[error("não suportado: {0}")]
    Unsupported(&'static str),

    #[error("dispositivo: {0}")]
    Device(String),

    #[error("ARP: sem resolução para {0:?}")]
    ArpUnresolved([u8; 4]),

    #[error("socket: {0}")]
    Socket(String),

    #[error("TCP: {0}")]
    Tcp(&'static str),

    #[error("fila vazia / timeout")]
    WouldBlock,
}
