//! TUN (IFF_TUN | IFF_NO_PI) — **somente** com feature `tun` + CAP_NET_ADMIN.
//!
//! Pacotes são datagramas **IPv4 crus** (sem Ethernet). Use `Stack::with_l3_device`.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

use crate::error::{Error, Result};
use crate::netdev::NetDevice;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

/// `TUNSETIFF` = _IOW('T', 202, int) — linux/if_tun.h
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

/// Dispositivo TUN L3. O MAC é sintético (trait [`NetDevice`]).
pub struct TunDevice {
    name: String,
    file: std::fs::File,
    mac: [u8; 6],
}

impl TunDevice {
    /// Abre `/dev/net/tun` e cria/anexa a iface `name` (ex.: `"tun0"`).
    ///
    /// Requer `CAP_NET_ADMIN` ou root. Sem privilégio a chamada falha com
    /// mensagem apontando para `CAPABILITIES.md`.
    pub fn open(name: &str) -> Result<Self> {
        if name.is_empty() || name.len() >= 16 {
            return Err(Error::Device("nome TUN inválido (1..15 chars)".into()));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                Error::Device(format!(
                    "open /dev/net/tun: {e} — módulo tun carregado? veja CAPABILITIES.md"
                ))
            })?;

        let mut req = IfReq {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());

        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            return Err(Error::Device(format!(
                "TUNSETIFF({name}): {err} — precisa CAP_NET_ADMIN/root (CAPABILITIES.md)"
            )));
        }

        // Non-blocking para `recv` poder retornar WouldBlock.
        let fd = file.into_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };

        let mut mac = [0u8; 6];
        mac[0] = 0x02; // locally administered
        mac[5] = 0x01;

        Ok(Self {
            name: name.to_string(),
            file,
            mac,
        })
    }
}

impl NetDevice for TunDevice {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, packet: &[u8]) -> Result<()> {
        self.file
            .write_all(packet)
            .map_err(|e| Error::Device(format!("tun write: {e}")))
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        match self.file.read(&mut buf) {
            Ok(0) => Err(Error::Device("tun EOF".into())),
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
            Err(e) => Err(Error::Device(format!("tun read: {e}"))),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}
