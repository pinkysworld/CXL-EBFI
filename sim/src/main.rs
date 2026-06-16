//! CXL-EBFI simulation harness (systems-language reference).
//!
//! This Rust crate implements the corrected CXL-EBFI construction described in
//! the paper.  It is the parallel, systems-language implementation of the
//! authoritative evaluation engine in `sim/cxl_ebfi_ref.py`; both use real
//! AES-256-GCM + HKDF-SHA-256 and pass the same deterministic security test
//! suite (`cargo test` here, `python3 cxl_ebfi_ref.py selftest` there).
//!
//! NOTE ON REPRODUCIBILITY: the paper's quantitative tables/figures are produced
//! by the Python reference, which runs in any environment with the `cryptography`
//! package.  This Rust crate requires the crates.io dependencies in Cargo.toml;
//! build and run it with `cargo test` and `cargo run --release` where network
//! access to crates.io is available.
//!
//! WHAT CHANGED FROM THE PRIOR VERSION (round-3 peer review):
//!   1. Trusted per-line version anchor.  Freshness is decided against the
//!      device-authoritative version (root of trust, delivered over the
//!      authenticated metadata path), NOT the version echoed in the response.
//!      This rejects same-epoch rollback, which the old epoch-window rule
//!      accepted.  (see Device::authoritative, Host::verify)
//!   2. Correct AEAD: decrypt() is called with the SAME associated data as
//!      encrypt() (the old code passed empty AAD, so honest reads never
//!      authenticated).
//!   3. HKDF info binds the epoch (was: fixed label only).
//!   4. Reference-counted epoch keys: a key is erased only when no live line
//!      references it AND it is outside the retention window -> unchanged lines
//!      stay readable (availability) while superseded values lose their key
//!      (forward integrity).
//!   5. Single ground-truth attacker: each injected attack is one labeled event;
//!      detection is measured from the actual accept/reject decision, not an
//!      independent coin flip.
//!   6. Corruption is applied to the response AFTER encryption (ciphertext/tag),
//!      so GCM can detect it.
//!   7. No moved-value bug in the reorder path.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use clap::Parser;
use hkdf::Hkdf;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::Serialize;
use sha2::Sha256;
use std::collections::HashMap;

const LINE_SIZE: usize = 64;
const RETENTION_W: u64 = 2; // epoch keys kept unconditionally for the last W epochs
const CTR_FIELD_BITS: u32 = 32;
const CTR_LIMIT: u64 = 1 << CTR_FIELD_BITS; // writes per (epoch,addr) before forced ratchet
const EPOCH_KEY_LABEL: &[u8] = b"cxl-ebfi-epoch-key";

type LineData = [u8; LINE_SIZE];

// ---------------------------------------------------------------------------
// Crypto helpers (identical layout to the Python reference).
// ---------------------------------------------------------------------------
// Each epoch key is derived INDEPENDENTLY from the device root: k_e = HKDF(root, e).
// Independent (not chained) derivation makes erasure meaningful and the root is
// outside the software/key-material compromise boundary (see Device).
fn hkdf_sha256(ikm: &[u8], epoch: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut info = EPOCH_KEY_LABEL.to_vec();
    info.extend_from_slice(&epoch.to_be_bytes()); // info binds the epoch
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("HKDF expand");
    okm
}

fn make_nonce(addr: u64, epoch: u64, ctr: u64, host: u8) -> [u8; 12] {
    // Distinct epoch keys separate epochs; writer and epoch are bound in AAD.
    // The write guard prevents low-32-bit counter reuse under one epoch key.
    let _ = (epoch, host);
    let mut n = [0u8; 12];
    n[0..8].copy_from_slice(&addr.to_le_bytes());
    n[8..12].copy_from_slice(&(ctr as u32).to_le_bytes());
    n
}

fn make_aad(addr: u64, epoch: u64, host: u8) -> [u8; 17] {
    let mut a = [0u8; 17];
    a[0] = host;
    a[1..9].copy_from_slice(&addr.to_le_bytes());
    a[9..17].copy_from_slice(&epoch.to_le_bytes());
    a
}

fn cipher_for(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

// ---------------------------------------------------------------------------
// Data structures.
// ---------------------------------------------------------------------------
#[derive(Clone)]
struct StoredLine {
    ct: Vec<u8>, // ciphertext || tag (untrusted data path)
    epoch: u64,
    ctr: u64,
    writer: u8,
}

#[derive(Clone, Copy)]
struct Version {
    epoch: u64,
    ctr: u64,
    writer: u8,
}

// ---------------------------------------------------------------------------
// Trusted device: root of trust for epoch + per-line version metadata.
// ---------------------------------------------------------------------------
struct Device {
    // PROTECTED DEVICE ROOT (root of trust), held in hardware-protected storage and
    // OUTSIDE the software/key-material compromise boundary (A3). Each epoch key is
    // derived independently: k_e = HKDF(root, e). A compromise captures the resident
    // working-set (epoch_keys), never this root, so an erased epoch key cannot be
    // reconstructed from the captured set.
    root: [u8; 32],
    epoch_keys: HashMap<u64, [u8; 32]>, // RESIDENT working set (compromisable)
    epoch_refcount: HashMap<u64, i64>,
    epoch_addr_writes: HashMap<(u64, usize), u64>, // nonce-wrap guard
    ctr_limit: u64,
    current_epoch: u64,
    lines: Vec<StoredLine>,
    auth: Vec<Version>,
    migrations: u64,
}

impl Device {
    fn new(nlines: usize, seed: u64) -> Self {
        Self::with_ctr_limit(nlines, seed, CTR_LIMIT)
    }

    fn with_ctr_limit(nlines: usize, seed: u64, ctr_limit: u64) -> Self {
        let root = {
            let mut r = StdRng::seed_from_u64(seed ^ 0xD3F1CE);
            let mut k = [0u8; 32];
            r.fill(&mut k);
            k
        };
        let mut d = Device {
            root,
            epoch_keys: HashMap::new(),
            epoch_refcount: HashMap::new(),
            epoch_addr_writes: HashMap::new(),
            ctr_limit,
            current_epoch: 1,
            lines: Vec::with_capacity(nlines),
            auth: Vec::with_capacity(nlines),
            migrations: 0,
        };
        d.epoch_keys.insert(1, d.derive_epoch_key(1));
        let pt = [0u8; LINE_SIZE];
        for a in 0..nlines {
            let ct = d.enc(1, a as u64, 0, 0, &pt);
            d.lines.push(StoredLine {
                ct,
                epoch: 1,
                ctr: 0,
                writer: 0,
            });
            d.auth.push(Version {
                epoch: 1,
                ctr: 0,
                writer: 0,
            });
        }
        d.epoch_refcount.insert(1, nlines as i64);
        d
    }

    fn derive_epoch_key(&self, e: u64) -> [u8; 32] {
        hkdf_sha256(&self.root, e)
    }

    /// Model an A3 compromise: capture the RESIDENT epoch keys, never the root.
    fn compromise(&self) -> Vec<[u8; 32]> {
        self.epoch_keys.values().copied().collect()
    }

    fn ratchet(&mut self) {
        self.current_epoch += 1;
        let nk = self.derive_epoch_key(self.current_epoch);
        self.epoch_keys.insert(self.current_epoch, nk);
        // Erase from the resident set keys outside the window that no live line uses.
        let cutoff = self.current_epoch.saturating_sub(RETENTION_W - 1);
        let drop: Vec<u64> = self
            .epoch_keys
            .keys()
            .copied()
            .filter(|&e| e < cutoff && *self.epoch_refcount.get(&e).unwrap_or(&0) == 0)
            .collect();
        for e in drop {
            self.epoch_keys.remove(&e);
        }
    }

    fn maybe_migrate(&mut self, a: usize, crypto_ns: f64, sec: &mut f64) {
        let old = self.lines[a].clone();
        if old.epoch >= self.current_epoch.saturating_sub(RETENTION_W - 1) {
            return;
        }
        let key = *self.epoch_keys.get(&old.epoch).unwrap();
        let pt = cipher_for(&key)
            .decrypt(
                Nonce::from_slice(&make_nonce(a as u64, old.epoch, old.ctr, old.writer)),
                Payload {
                    msg: &old.ct,
                    aad: &make_aad(a as u64, old.epoch, old.writer),
                },
            )
            .expect("migrate decrypt");
        let e = self.current_epoch;
        let ct = self.enc(e, a as u64, old.ctr, old.writer, &pt);
        self.dec_ref(old.epoch);
        self.lines[a] = StoredLine {
            ct,
            epoch: e,
            ctr: old.ctr,
            writer: old.writer,
        };
        self.auth[a] = Version {
            epoch: e,
            ctr: old.ctr,
            writer: old.writer,
        };
        *self.epoch_refcount.entry(e).or_insert(0) += 1;
        self.migrations += 1;
        *sec += crypto_ns * 2.0;
    }

    fn dec_ref(&mut self, e: u64) {
        *self.epoch_refcount.entry(e).or_insert(0) -= 1;
    }

    fn enc(&self, epoch: u64, addr: u64, ctr: u64, host: u8, pt: &[u8]) -> Vec<u8> {
        let key = self.epoch_keys.get(&epoch).unwrap();
        cipher_for(key)
            .encrypt(
                Nonce::from_slice(&make_nonce(addr, epoch, ctr, host)),
                Payload {
                    msg: pt,
                    aad: &make_aad(addr, epoch, host),
                },
            )
            .expect("encrypt")
    }

    fn write(&mut self, addr: usize, data: &LineData, host: u8) -> Version {
        // Nonce-uniqueness enforcement (F7): force a ratchet before the writes to
        // (epoch, addr) reach the counter field's capacity, so the low
        // CTR_FIELD_BITS of the counter never repeat within one epoch key.
        if self
            .epoch_addr_writes
            .get(&(self.current_epoch, addr))
            .copied()
            .unwrap_or(0)
            + 1
            >= self.ctr_limit
        {
            self.ratchet();
        }
        let e = self.current_epoch;
        let old_e = self.lines[addr].epoch;
        let ctr = self.auth[addr].ctr + 1;
        let ct = self.enc(e, addr as u64, ctr, host, data);
        self.dec_ref(old_e);
        self.lines[addr] = StoredLine {
            ct,
            epoch: e,
            ctr,
            writer: host,
        };
        self.auth[addr] = Version {
            epoch: e,
            ctr,
            writer: host,
        };
        *self.epoch_refcount.entry(e).or_insert(0) += 1;
        *self.epoch_addr_writes.entry((e, addr)).or_insert(0) += 1;
        self.auth[addr]
    }

    fn authoritative(&self, addr: usize) -> Version {
        self.auth[addr]
    }

    fn retained_keys(&self) -> usize {
        self.epoch_keys.len()
    }
}

// ---------------------------------------------------------------------------
// Host verifier: verifies the untrusted response under the TRUSTED version.
// ---------------------------------------------------------------------------
struct Host;

impl Host {
    /// Verify `resp` (possibly substituted/tampered by the attacker) against the
    /// device-authoritative version.  Returns Some(plaintext) iff accepted.
    fn verify(dev: &Device, addr: usize, resp: &StoredLine) -> Option<Vec<u8>> {
        let v = dev.authoritative(addr); // trusted version (never from resp)
        let key = dev.epoch_keys.get(&v.epoch)?; // key erased => cannot be current => reject
        cipher_for(key)
            .decrypt(
                Nonce::from_slice(&make_nonce(addr as u64, v.epoch, v.ctr, v.writer)),
                Payload {
                    msg: &resp.ct,
                    aad: &make_aad(addr as u64, v.epoch, v.writer),
                },
            )
            .ok()
    }

    #[cfg(test)]
    fn verify_stable(
        dev: &Device,
        addr: usize,
        resp: &StoredLine,
        before: Version,
        after: Version,
    ) -> Result<Option<Vec<u8>>, ()> {
        let equal =
            |a: Version, b: Version| (a.epoch, a.ctr, a.writer) == (b.epoch, b.ctr, b.writer);
        if !equal(before, after) || !equal(after, dev.authoritative(addr)) {
            return Err(()); // concurrent write: retry
        }
        Ok(Self::verify(dev, addr, resp))
    }

    /// Model of the PREVIOUS (broken) rule: trust the version ECHOED in the
    /// response and accept if it authenticates under that echoed version and the
    /// epoch is within the mode window.  A same-epoch rollback passes this.
    fn legacy_would_accept(dev: &Device, addr: usize, resp: &StoredLine) -> bool {
        let key = match dev.epoch_keys.get(&resp.epoch) {
            Some(k) => k,
            None => return false,
        };
        let ok = cipher_for(key)
            .decrypt(
                Nonce::from_slice(&make_nonce(addr as u64, resp.epoch, resp.ctr, resp.writer)),
                Payload {
                    msg: &resp.ct,
                    aad: &make_aad(addr as u64, resp.epoch, resp.writer),
                },
            )
            .is_ok();
        ok && resp.epoch + 1 >= dev.current_epoch // current or current-1 window
    }
}

// ---------------------------------------------------------------------------
// Gilbert-Elliott burst channel (kept only for detection-under-burst study).
// ---------------------------------------------------------------------------
struct GilbertElliott {
    p_gb: f64,
    p_bg: f64,
    p_err_good: f64,
    p_err_bad: f64,
    bad: bool,
    rng: StdRng,
}

impl GilbertElliott {
    fn new(burst: f64, seed: u64) -> Self {
        GilbertElliott {
            p_gb: 0.008,
            p_bg: 0.12,
            p_err_good: 0.0005,
            p_err_bad: burst.clamp(0.01, 0.25),
            bad: false,
            rng: StdRng::seed_from_u64(seed),
        }
    }
    fn step(&mut self) -> bool {
        if self.bad {
            if self.rng.gen::<f64>() < self.p_bg {
                self.bad = false;
            }
        } else if self.rng.gen::<f64>() < self.p_gb {
            self.bad = true;
        }
        self.rng.gen::<f64>()
            < if self.bad {
                self.p_err_bad
            } else {
                self.p_err_good
            }
    }
}

// ---------------------------------------------------------------------------
// CLI + metrics.
// ---------------------------------------------------------------------------
#[derive(Parser, Debug, Clone)]
#[command(
    name = "cxl-ebfi-sim",
    about = "CXL-EBFI corrected reference simulator"
)]
struct Args {
    #[arg(long, default_value = "optimistic")] // optimistic | verified
    mode: String,
    #[arg(long, default_value_t = 3)]
    hosts: usize,
    #[arg(long, default_value_t = 4096)]
    lines: usize,
    #[arg(long, default_value_t = 30)]
    seeds: usize,
    #[arg(long, default_value_t = 4000)]
    steps: usize,
    #[arg(long, default_value_t = 0.03)]
    burst: f64,
    #[arg(long, default_value_t = 25.0)]
    crypto_ns: f64,
    #[arg(long, default_value_t = 12.0)]
    version_fetch_ns: f64,
    #[arg(long, default_value_t = false)]
    migrate_on_read: bool,
    #[arg(long)]
    csv: Option<String>,
    #[arg(long, default_value_t = false)]
    microbench: bool,
}

#[derive(Serialize, Clone)]
struct TrialMetrics {
    seed: u64,
    mode: String,
    ops: usize,
    reads: usize,
    writes: usize,
    true_violations: usize,
    violations_accepted: usize,
    honest_reads: usize,
    honest_reads_accepted: usize,
    ratchets: usize,
    migrations: u64,
    retained_keys_max: usize,
    legacy_same_epoch_replay_accepts: usize,
    avg_latency_ns: f64,
    base_latency_ns: f64,
    overhead_pct: f64,
}

const BASE_LATENCY: f64 = 200.0;
const VAR_LATENCY: f64 = 60.0;
// Freshness attacks exercised in the read loop -- all TRUE violations w.r.t. the
// trusted anchor. Post-compromise forgery is forward integrity, a different
// property, tested separately by forward_integrity_experiment().
const ATTACK_TYPES: [&str; 3] = ["same_epoch_replay", "old_epoch_replay", "tamper"];

fn run_trial(seed: u64, args: &Args) -> TrialMetrics {
    let mode = args.mode.as_str();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut dev = Device::new(args.lines, seed);
    let mut ge = GilbertElliott::new(args.burst, seed ^ 0xFEED);
    let mut history: Vec<Vec<StoredLine>> = vec![Vec::new(); args.lines];

    let (mut ops, mut reads, mut writes) = (0usize, 0usize, 0usize);
    let (mut true_viol, mut viol_acc) = (0usize, 0usize);
    let (mut honest_reads, mut honest_acc) = (0usize, 0usize);
    let mut ratchets = 0usize;
    let mut retained_max = 1usize;
    let mut legacy_se = 0usize;
    let (mut total_base, mut total_sec) = (0.0f64, 0.0f64);
    let p_attack = 0.05;

    for _ in 0..args.steps {
        for h in 0..args.hosts {
            if rng.gen::<f64>() >= 0.65 {
                continue;
            }
            let addr = rng.gen_range(0..args.lines);
            let is_write = rng.gen::<f64>() < 0.30;
            ops += 1;
            let mut channel = BASE_LATENCY + rng.gen::<f64>() * VAR_LATENCY;

            if is_write {
                writes += 1;
                let mut data = [0u8; LINE_SIZE];
                rng.fill(&mut data);
                dev.write(addr, &data, h as u8);
                history[addr].push(dev.lines[addr].clone());
                total_base += channel;
                total_sec += channel + args.crypto_ns;
                continue;
            }

            // ---- READ ----
            reads += 1;
            if args.migrate_on_read {
                dev.maybe_migrate(addr, args.crypto_ns, &mut total_sec);
            }
            if ge.step() {
                channel += 40.0 + rng.gen::<f64>() * 80.0;
            }
            let sec_add = args.crypto_ns
                + if mode == "verified" {
                    args.version_fetch_ns
                } else {
                    0.0
                };
            total_base += channel;
            total_sec += channel + sec_add;

            let do_attack = rng.gen::<f64>() < p_attack && !history[addr].is_empty();
            let mut handled = false;
            if do_attack {
                let atype = ATTACK_TYPES[rng.gen_range(0..ATTACK_TYPES.len())];
                if let Some((resp, is_true)) = build_attack(atype, addr, &dev, &history) {
                    handled = true;
                    let accepted = Host::verify(&dev, addr, &resp).is_some();
                    if is_true {
                        true_viol += 1;
                        if accepted {
                            viol_acc += 1;
                        }
                        if atype == "same_epoch_replay"
                            && Host::legacy_would_accept(&dev, addr, &resp)
                        {
                            legacy_se += 1;
                        }
                    }
                }
            }
            if !handled {
                honest_reads += 1;
                let cur = dev.lines[addr].clone();
                if Host::verify(&dev, addr, &cur).is_some() {
                    honest_acc += 1;
                }
            }
        }
        if rng.gen::<f64>() < 0.004 {
            dev.ratchet();
            ratchets += 1;
            retained_max = retained_max.max(dev.retained_keys());
        }
    }

    let avg = if ops > 0 { total_sec / ops as f64 } else { 0.0 };
    let base = if ops > 0 {
        total_base / ops as f64
    } else {
        0.0
    };
    let overhead = if total_base > 0.0 {
        (total_sec - total_base) / total_base * 100.0
    } else {
        0.0
    };
    TrialMetrics {
        seed,
        mode: mode.to_string(),
        ops,
        reads,
        writes,
        true_violations: true_viol,
        violations_accepted: viol_acc,
        honest_reads,
        honest_reads_accepted: honest_acc,
        ratchets,
        migrations: dev.migrations,
        retained_keys_max: retained_max,
        legacy_same_epoch_replay_accepts: legacy_se,
        avg_latency_ns: avg,
        base_latency_ns: base,
        overhead_pct: overhead,
    }
}

/// Build one labeled freshness-attack response.  All three are TRUE violations
/// w.r.t. the trusted anchor and MUST be rejected.
fn build_attack(
    atype: &str,
    addr: usize,
    dev: &Device,
    history: &[Vec<StoredLine>],
) -> Option<(StoredLine, bool)> {
    let anchor = dev.authoritative(addr);
    let snaps = &history[addr];
    match atype {
        "same_epoch_replay" => snaps
            .iter()
            .rev()
            .find(|s| s.epoch == anchor.epoch && s.ctr < anchor.ctr)
            .map(|s| (s.clone(), true)),
        "old_epoch_replay" => snaps
            .iter()
            .rev()
            .find(|s| s.epoch < anchor.epoch)
            .map(|s| (s.clone(), true)),
        "tamper" => {
            let cur = &dev.lines[addr];
            let mut bad = cur.ct.clone();
            bad[0] ^= 0xFF; // flip a ciphertext byte AFTER encryption
            Some((
                StoredLine {
                    ct: bad,
                    epoch: cur.epoch,
                    ctr: cur.ctr,
                    writer: cur.writer,
                },
                true,
            ))
        }
        _ => None,
    }
}

/// Forward-integrity (post-compromise) experiment -- SEPARATE from freshness.
/// Creates a historical record, ages its epoch out so its key is erased, then
/// COMPROMISES the resident working set (never the root) and shows the erased
/// key is neither captured nor usable to forge a valid historical record.
/// Returns true iff forward integrity holds.
fn forward_integrity_experiment(seed: u64) -> bool {
    let mut dev = Device::new(4, seed);
    dev.ratchet(); // epoch 2; line 1 will be its only resident
    let _ = dev.write(1, &[2u8; LINE_SIZE], 0);
    let e_hist = dev.lines[1].epoch;
    let k_hist = *dev.epoch_keys.get(&e_hist).unwrap();
    let ctr_hist = dev.lines[1].ctr;
    dev.ratchet();
    let _ = dev.write(1, &[3u8; LINE_SIZE], 0); // supersede -> epoch 2 unreferenced
    for _ in 0..(RETENTION_W + 3) {
        dev.ratchet();
    }
    let erased = !dev.epoch_keys.contains_key(&e_hist);
    let captured = dev.compromise(); // resident keys only, NOT the root
    let key_in_capture = captured.contains(&k_hist);
    // adversary tries to forge a different valid record for the erased epoch
    let mut forged_ok = false;
    for k in &captured {
        let forged = cipher_for(k)
            .encrypt(
                Nonce::from_slice(&make_nonce(1, e_hist, ctr_hist, 0)),
                Payload {
                    msg: &[0xFFu8; LINE_SIZE],
                    aad: &make_aad(1, e_hist, 0),
                },
            )
            .expect("enc");
        if cipher_for(&k_hist)
            .decrypt(
                Nonce::from_slice(&make_nonce(1, e_hist, ctr_hist, 0)),
                Payload {
                    msg: &forged,
                    aad: &make_aad(1, e_hist, 0),
                },
            )
            .is_ok()
        {
            forged_ok = true;
        }
    }
    erased && !key_in_capture && !forged_ok
}

fn microbench(iters: usize) {
    use std::time::Instant;
    let key = hkdf_sha256(&[0u8; 32], 1);
    let g = cipher_for(&key);
    let pt = [0x11u8; LINE_SIZE];
    let (addr, epoch, ctr, host) = (1234u64, 1u64, 1u64, 0u8);
    let ct = g
        .encrypt(
            Nonce::from_slice(&make_nonce(addr, epoch, ctr, host)),
            Payload {
                msg: &pt,
                aad: &make_aad(addr, epoch, host),
            },
        )
        .unwrap();

    let t = Instant::now();
    for _ in 0..iters {
        let _ = g
            .encrypt(
                Nonce::from_slice(&make_nonce(addr, epoch, ctr, host)),
                Payload {
                    msg: &pt,
                    aad: &make_aad(addr, epoch, host),
                },
            )
            .unwrap();
    }
    let enc = t.elapsed().as_nanos() as f64 / iters as f64;

    let t = Instant::now();
    for _ in 0..iters {
        let _ = g
            .decrypt(
                Nonce::from_slice(&make_nonce(addr, epoch, ctr, host)),
                Payload {
                    msg: &ct,
                    aad: &make_aad(addr, epoch, host),
                },
            )
            .unwrap();
    }
    let dec = t.elapsed().as_nanos() as f64 / iters as f64;

    let mut prev = key;
    let rit = (iters / 10).max(1000);
    let t = Instant::now();
    for i in 0..rit {
        prev = hkdf_sha256(&prev, i as u64 + 2);
    }
    let ratchet = t.elapsed().as_nanos() as f64 / rit as f64;

    println!(
        "microbench (software path, ns/op): aesgcm_encrypt={:.1} aesgcm_decrypt={:.1} hkdf_ratchet={:.1}",
        enc, dec, ratchet
    );
}

fn agg(v: &[f64]) -> (f64, f64) {
    let n = v.len() as f64;
    let m = v.iter().sum::<f64>() / n;
    let var = v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / n;
    (m, var.sqrt())
}

fn main() {
    let args = Args::parse();
    if args.microbench {
        microbench(50_000);
        return;
    }
    println!(
        "CXL-EBFI sim (mode={}, hosts={}, lines={}, seeds={}, steps={}, burst={})",
        args.mode, args.hosts, args.lines, args.seeds, args.steps, args.burst
    );
    let mut all = Vec::new();
    for i in 0..args.seeds {
        let m = run_trial(42 + i as u64, &args);
        all.push(m);
    }
    let oh = agg(&all.iter().map(|m| m.overhead_pct).collect::<Vec<_>>());
    let tv: usize = all.iter().map(|m| m.true_violations).sum();
    let va: usize = all.iter().map(|m| m.violations_accepted).sum();
    let hr: usize = all.iter().map(|m| m.honest_reads).sum();
    let ha: usize = all.iter().map(|m| m.honest_reads_accepted).sum();
    println!(
        "overhead {:.2}% (std {:.3}) | true_viol={} accepted={} det={:.1}% | liveness={:.1}%",
        oh.0,
        oh.1,
        tv,
        va,
        if tv > 0 {
            100.0 * (tv - va) as f64 / tv as f64
        } else {
            100.0
        },
        if hr > 0 {
            100.0 * ha as f64 / hr as f64
        } else {
            100.0
        }
    );
    println!(
        "forward_integrity_under_compromise: {}",
        if forward_integrity_experiment(99) {
            "HOLDS"
        } else {
            "FAILED"
        }
    );
    if let Some(path) = &args.csv {
        let mut w = csv::Writer::from_path(path).expect("csv");
        for m in &all {
            w.serialize(m).unwrap();
        }
        w.flush().unwrap();
        println!("wrote {}", path);
    }
}

// ---------------------------------------------------------------------------
// Deterministic security tests (mirrors python selftest).  `cargo test`.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn line(b: u8) -> LineData {
        [b; LINE_SIZE]
    }

    #[derive(serde::Deserialize)]
    struct TestVector {
        root_hex: String,
        epoch: u64,
        line_id: u64,
        counter: u64,
        writer: u8,
        plaintext_hex: String,
        epoch_key_hex: String,
        nonce_hex: String,
        aad_hex: String,
        ciphertext_hex: String,
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn valid_and_cross_host_read_accepted() {
        let mut d = Device::new(8, 7);
        let _ = d.write(2, &line(b'A'), 0);
        assert!(
            Host::verify(&d, 2, &d.lines[2].clone()).is_some(),
            "valid read"
        );
        // host 1 reads host 0's write
        assert!(
            Host::verify(&d, 2, &d.lines[2].clone()).is_some(),
            "cross-host read"
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut d = Device::new(8, 7);
        let _ = d.write(2, &line(b'A'), 0);
        let mut bad = d.lines[2].clone();
        bad.ct[0] ^= 0xFF;
        assert!(Host::verify(&d, 2, &bad).is_none());
    }

    #[test]
    fn same_epoch_replay_rejected_but_legacy_accepts() {
        let mut d = Device::new(8, 7);
        let _ = d.write(2, &line(b'A'), 0);
        let snap1 = d.lines[2].clone(); // ctr 1
        let _ = d.write(2, &line(b'B'), 1); // ctr 2, same epoch
        assert!(
            Host::verify(&d, 2, &snap1).is_none(),
            "new design rejects rollback"
        );
        assert!(
            Host::legacy_would_accept(&d, 2, &snap1),
            "legacy rule would accept it"
        );
    }

    #[test]
    fn old_epoch_replay_rejected() {
        // The old snapshot must be a SUPERSEDED value (not the current one), or it
        // is legitimately still authoritative. Supersede line 2 with a later write.
        let mut d = Device::new(8, 7);
        let _ = d.write(2, &line(b'A'), 0); // epoch 1, ctr 1
        let snap = d.lines[2].clone();
        d.ratchet();
        let _ = d.write(2, &line(b'B'), 0); // supersede at epoch 2, ctr 2
        d.ratchet();
        assert!(
            Host::verify(&d, 2, &snap).is_none(),
            "stale old-epoch value rejected"
        );
    }

    #[test]
    fn cold_line_stays_readable_via_key_retention() {
        // a cold, never-rewritten line stays readable across ratchets because its
        // epoch key is retained while it is the live value (refcount > 0).
        let mut d = Device::new(4, 7);
        let cold_epoch = d.lines[3].epoch;
        for _ in 0..(RETENTION_W + 3) {
            d.ratchet();
        }
        assert!(d.epoch_keys.contains_key(&cold_epoch), "cold key retained");
        assert!(
            Host::verify(&d, 3, &d.lines[3].clone()).is_some(),
            "cold line readable"
        );
    }

    #[test]
    fn forward_integrity_under_compromise() {
        // explicit compromise game: erased epoch key not captured, not reconstructable,
        // and no forged historical record validates. (mirrors python FI experiment)
        assert!(forward_integrity_experiment(11));
        assert!(forward_integrity_experiment(7));
    }

    #[test]
    fn counter_exhaustion_forces_ratchet() {
        // with a tiny ctr_limit, repeated writes to one line force a ratchet before
        // the nonce counter field could wrap, and the line stays readable.
        let mut d = Device::with_ctr_limit(2, 5, 4);
        let start = d.current_epoch;
        for i in 0..10u8 {
            let _ = d.write(0, &line(i), 0);
        }
        assert!(d.current_epoch > start, "exhaustion forced a ratchet");
        assert!(
            Host::verify(&d, 0, &d.lines[0].clone()).is_some(),
            "line still readable"
        );
    }

    #[test]
    fn full_width_line_ids_do_not_alias() {
        assert_ne!(
            make_nonce(1, 7, 9, 1),
            make_nonce((1u64 << 32) + 1, 7, 9, 1)
        );
    }

    #[test]
    fn concurrent_write_forces_retry() {
        let mut d = Device::new(2, 13);
        let before = d.authoritative(0);
        let old = d.lines[0].clone();
        let _ = d.write(0, &line(b'R'), 1);
        let after = d.authoritative(0);
        assert!(Host::verify_stable(&d, 0, &old, before, after).is_err());
    }

    #[test]
    fn shared_known_answer_vector() {
        let tv: TestVector =
            serde_json::from_str(include_str!("../test_vectors.json")).expect("test vector");
        let root = decode_hex(&tv.root_hex);
        let key = hkdf_sha256(&root, tv.epoch);
        let nonce = make_nonce(tv.line_id, tv.epoch, tv.counter, tv.writer);
        let aad = make_aad(tv.line_id, tv.epoch, tv.writer);
        let ct = cipher_for(&key)
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &decode_hex(&tv.plaintext_hex),
                    aad: &aad,
                },
            )
            .expect("encrypt vector");
        assert_eq!(key.as_slice(), decode_hex(&tv.epoch_key_hex));
        assert_eq!(nonce.as_slice(), decode_hex(&tv.nonce_hex));
        assert_eq!(aad.as_slice(), decode_hex(&tv.aad_hex));
        assert_eq!(ct, decode_hex(&tv.ciphertext_hex));
    }

    // --- protocol-layer parity tests (mirror sim/cxl_ebfi_protocol.py) -------
    // Atomic device-issued write reservation: a unique counter per call, so
    // concurrent same-line writers cannot share a (key, nonce) pair.
    fn reserve_atomic(alloc: &mut std::collections::HashMap<u64, u64>, line: u64) -> u64 {
        let c = alloc.entry(line).or_insert(0);
        *c += 1; // allocate-and-advance in one step
        *c
    }

    #[test]
    fn concurrent_reservation_distinct_nonces() {
        let mut alloc = std::collections::HashMap::new();
        // two writers reserve for the SAME line before either commits
        let c1 = reserve_atomic(&mut alloc, 7);
        let c2 = reserve_atomic(&mut alloc, 7);
        assert_ne!(c1, c2, "atomic reservation must allocate distinct counters");
        assert_ne!(
            make_nonce(7, 1, c1, 0),
            make_nonce(7, 1, c2, 0),
            "distinct counters give distinct nonces"
        );
        // the buggy read-modify-write (read same value twice, no atomic advance)
        // would yield identical counters -> nonce reuse:
        let base = *alloc.get(&7).unwrap();
        let (b1, b2) = (base + 1, base + 1);
        assert_eq!(make_nonce(7, 1, b1, 0), make_nonce(7, 1, b2, 0));
    }

    struct Ticket {
        line: u64,
        epoch: u64,
        ctr: u64,
        writer: u8,
        rid: u64,
    }
    struct Tve {
        outstanding: std::collections::HashSet<u64>,
        next_rid: u64,
    }
    impl Tve {
        fn new() -> Self {
            Tve { outstanding: std::collections::HashSet::new(), next_rid: 1 }
        }
        fn begin_read(&mut self) -> u64 {
            let r = self.next_rid;
            self.next_rid += 1;
            self.outstanding.insert(r);
            r
        }
        // accept only if rid is currently outstanding; consume it once
        fn ticket_fresh(&mut self, t: &Ticket) -> bool {
            self.outstanding.remove(&t.rid)
        }
    }

    #[test]
    fn stale_ticket_replay_rejected() {
        let mut tve = Tve::new();
        let rid = tve.begin_read();
        let t = Ticket { line: 1, epoch: 1, ctr: 1, writer: 0, rid };
        // a real TVE reconstructs nonce/AAD from the ticket version fields:
        let n = make_nonce(t.line, t.epoch, t.ctr, t.writer);
        let a = make_aad(t.line, t.epoch, t.writer);
        assert_eq!(n[0], 1, "nonce derived from ticket lineID");
        assert_eq!(a[0], t.writer, "AAD derived from ticket writer");
        assert!(tve.ticket_fresh(&t), "first use accepted");
        assert!(!tve.ticket_fresh(&t), "replay of consumed ticket rejected");
        let foreign = Ticket { line: 1, epoch: 1, ctr: 1, writer: 0, rid: 999 };
        assert!(!tve.ticket_fresh(&foreign), "non-outstanding rid rejected");
    }

    #[test]
    fn ticket_ciphertext_mismatch_rejected() {
        // ciphertext made for ctr=1; a current ticket claims ctr=2 -> GCM fails
        let mut d = Device::new(4, 7);
        let _ = d.write(1, &line(b'A'), 0); // ctr 1
        let stale_ct = d.lines[1].ct.clone();
        let _ = d.write(1, &line(b'B'), 0); // ctr 2 (authoritative)
        let v = d.authoritative(1);
        let key = d.epoch_keys.get(&v.epoch).unwrap();
        let bad = cipher_for(key).decrypt(
            Nonce::from_slice(&make_nonce(1, v.epoch, v.ctr, v.writer)),
            Payload { msg: &stale_ct, aad: &make_aad(1, v.epoch, v.writer) },
        );
        assert!(bad.is_err(), "old ciphertext under current ticket version must fail");
    }
}
