//! RTO Jacobson/Karels simplificado.
#[derive(Clone, Debug)]
pub struct Rto {
    pub srtt: f64,
    pub rttvar: f64,
    pub rto: f64,
}
impl Default for Rto {
    fn default() -> Self {
        Self {
            srtt: 0.0,
            rttvar: 0.0,
            rto: 1.0,
        }
    }
}
impl Rto {
    /// Ignore invalid or retransmitted RTT samples (Karn's rule via sample_ack).
    pub fn sample(&mut self, rtt: f64) {
        if !rtt.is_finite() || rtt <= 0.0 {
            return;
        }
        if self.srtt == 0.0 {
            self.srtt = rtt;
            self.rttvar = rtt / 2.0;
        } else {
            let d = (self.srtt - rtt).abs();
            self.rttvar = 0.75 * self.rttvar + 0.25 * d;
            self.srtt = 0.875 * self.srtt + 0.125 * rtt;
        }
        self.rto = (self.srtt + 4.0 * self.rttvar).clamp(0.2, 60.0);
    }
}

impl Rto {
    /// A retransmitted segment cannot provide an unambiguous RTT sample.
    pub fn sample_ack(&mut self, rtt: f64, retransmitted: bool) {
        if !retransmitted {
            self.sample(rtt);
        }
    }
    /// Exponential timeout backoff, bounded to one minute.
    pub fn on_timeout(&mut self) -> f64 {
        self.rto = (self.rto * 2.0).clamp(0.2, 60.0);
        self.rto
    }
}
#[cfg(test)]
mod expansion_tests {
    use super::*;
    #[test]
    fn retransmission_and_backoff() {
        let mut r = Rto::default();
        r.sample(0.1);
        let before = r.rto;
        r.sample_ack(9.0, true);
        r.sample(f64::NAN);
        assert_eq!(r.rto, before);
        assert_eq!(r.on_timeout(), before * 2.0);
        for _ in 0..100 {
            r.on_timeout();
        }
        assert_eq!(r.rto, 60.0);
    }
}
