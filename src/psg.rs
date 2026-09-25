//! MSX の PSG（AY-3-8910 相当）と PLAY 文（MML）の簡易エミュレーション
//!
//! - SOUND r,v はレジスタ書き込みとしてそのまま再現する（エンジン音・爆発音）
//! - PLAY 文は 1/60 秒単位で進むシーケンサとして再現する（MSX の PLAY も割り込みで動く）

use std::sync::{Arc, Mutex};

/// MSX の PSG クロック（3.579545MHz / 2）
const CLOCK: f64 = 1_789_772.5;
pub const SAMPLE_RATE: usize = 44_100;

/// PSG の音量テーブル（1段 約3dB）
const VOL: [f32; 16] = [
    0.0, 0.0078, 0.011, 0.016, 0.023, 0.033, 0.047, 0.067, 0.095, 0.134, 0.19, 0.27, 0.38,
    0.54, 0.76, 1.0,
];

#[derive(Clone, Copy)]
enum Ev {
    Note { period: u16, ticks: u32, vol: u8, env: Option<u8> },
    Rest { ticks: u32 },
    EnvPeriod(u16),
}

#[derive(Default)]
struct Track {
    events: Vec<Ev>,
    pos: usize,
    left: u32,
    active: bool,
}

/// PLAY 文のチャンネルごとの設定（MSX では PLAY をまたいで引き継がれる）
#[derive(Clone, Copy)]
struct MmlState {
    octave: i32,
    length: u32,
    tempo: u32,
    volume: u8,
    env: Option<u8>,
}

impl Default for MmlState {
    fn default() -> Self {
        Self { octave: 4, length: 4, tempo: 120, volume: 8, env: None }
    }
}

pub struct Psg {
    regs: [u8; 16],
    tone_phase: [f64; 3],
    noise_phase: f64,
    lfsr: u32,
    noise_out: bool,
    env_phase: f64,
    env_step: i32,
    env_holding: bool,
    tracks: [Track; 3],
    mml: [MmlState; 3],
    tick_acc: f64,
    dc: f32,
}

impl Psg {
    fn new() -> Self {
        let mut regs = [0u8; 16];
        regs[7] = 0xB8;
        Self {
            regs,
            tone_phase: [0.0; 3],
            noise_phase: 0.0,
            lfsr: 1,
            noise_out: false,
            env_phase: 0.0,
            env_step: 0,
            env_holding: false,
            tracks: Default::default(),
            mml: [MmlState::default(); 3],
            tick_acc: 0.0,
            dc: 0.0,
        }
    }

    /// SOUND r,v
    pub fn write(&mut self, r: usize, v: u8) {
        self.regs[r & 15] = v;
        if r == 13 {
            self.env_step = 0;
            self.env_phase = 0.0;
            self.env_holding = false;
        }
    }

    /// PLAY "a","b","c"（空文字のチャンネルは何もしない）
    pub fn play(&mut self, mml: [&str; 3]) {
        for (ch, s) in mml.iter().enumerate() {
            if s.is_empty() {
                continue;
            }
            let events = parse_mml(s, &mut self.mml[ch]);
            let t = &mut self.tracks[ch];
            t.events.extend(events);
            if !t.active {
                t.active = true;
                t.left = 0;
            }
        }
    }

    /// PLAY(0): どれかのチャンネルが演奏中なら true
    pub fn playing(&self) -> bool {
        self.tracks.iter().any(|t| t.active)
    }

    /// 1/60 秒ごとの PLAY シーケンサ
    fn tick(&mut self) {
        for ch in 0..3 {
            if !self.tracks[ch].active {
                continue;
            }
            if self.tracks[ch].left > 0 {
                self.tracks[ch].left -= 1;
                if self.tracks[ch].left > 0 {
                    continue;
                }
            }
            loop {
                let t = &mut self.tracks[ch];
                if t.pos >= t.events.len() {
                    t.active = false;
                    t.events.clear();
                    t.pos = 0;
                    self.regs[8 + ch] = 0;
                    break;
                }
                let ev = t.events[t.pos];
                t.pos += 1;
                match ev {
                    Ev::EnvPeriod(m) => {
                        self.regs[11] = (m & 0xFF) as u8;
                        self.regs[12] = (m >> 8) as u8;
                    }
                    Ev::Rest { ticks } => {
                        self.regs[8 + ch] = 0;
                        self.tracks[ch].left = ticks.max(1);
                        break;
                    }
                    Ev::Note { period, ticks, vol, env } => {
                        self.regs[ch * 2] = (period & 0xFF) as u8;
                        self.regs[ch * 2 + 1] = (period >> 8) as u8;
                        match env {
                            Some(shape) => {
                                self.regs[8 + ch] = 16;
                                self.write(13, shape);
                            }
                            None => self.regs[8 + ch] = vol,
                        }
                        self.tracks[ch].left = ticks.max(1);
                        break;
                    }
                }
            }
        }
    }

    fn env_level(&self) -> u8 {
        let shape = self.regs[13];
        let attack = shape & 4 != 0;
        let step = self.env_step.clamp(0, 15) as u8;
        if self.env_holding {
            // 1周期後の保持レベル
            let cont = shape & 8 != 0;
            if !cont {
                return 0;
            }
            let hold = shape & 1 != 0;
            let alt = shape & 2 != 0;
            if hold {
                return if attack ^ alt { 15 } else { 0 };
            }
        }
        if attack {
            step
        } else {
            15 - step
        }
    }

    fn next_sample(&mut self) -> f32 {
        let dt = 1.0 / SAMPLE_RATE as f64;
        // PLAY シーケンサ（60Hz）
        self.tick_acc += dt * 60.0;
        while self.tick_acc >= 1.0 {
            self.tick_acc -= 1.0;
            self.tick();
        }
        // エンベロープ
        let ep = ((self.regs[12] as u32) << 8 | self.regs[11] as u32).max(1) as f64;
        self.env_phase += dt * CLOCK / (16.0 * ep);
        while self.env_phase >= 1.0 {
            self.env_phase -= 1.0;
            if !self.env_holding {
                self.env_step += 1;
                if self.env_step > 15 {
                    let shape = self.regs[13];
                    let cont = shape & 8 != 0;
                    let hold = shape & 1 != 0;
                    if !cont || hold {
                        self.env_holding = true;
                        self.env_step = 15;
                    } else {
                        self.env_step = 0;
                        if shape & 2 != 0 {
                            self.regs[13] ^= 4;
                        }
                    }
                }
            }
        }
        // ノイズ
        let np = (self.regs[6] & 31).max(1) as f64;
        self.noise_phase += dt * CLOCK / (16.0 * np);
        while self.noise_phase >= 1.0 {
            self.noise_phase -= 1.0;
            let bit = (self.lfsr ^ (self.lfsr >> 3)) & 1;
            self.lfsr = (self.lfsr >> 1) | (bit << 16);
            self.noise_out = self.lfsr & 1 != 0;
        }
        // 3チャンネル
        let mixer = self.regs[7];
        let env = self.env_level();
        let mut out = 0.0f32;
        for ch in 0..3 {
            let tp = (((self.regs[ch * 2 + 1] & 15) as u32) << 8 | self.regs[ch * 2] as u32).max(1);
            let freq = CLOCK / (16.0 * tp as f64);
            self.tone_phase[ch] = (self.tone_phase[ch] + freq * dt).fract();
            let tone_on = mixer & (1 << ch) == 0;
            let noise_on = mixer & (8 << ch) == 0;
            // 可聴域を超える高さは平均値として扱う（MSX でも実質無音になる）
            let tone = if !tone_on || freq > 20_000.0 { true } else { self.tone_phase[ch] < 0.5 };
            let noise = if noise_on { self.noise_out } else { true };
            let v = self.regs[8 + ch];
            let level = if v & 16 != 0 { env } else { v & 15 };
            if tone && noise {
                out += VOL[level as usize];
            }
        }
        // 直流分を取り除く
        self.dc += (out - self.dc) * 0.001;
        (out - self.dc) * 0.25
    }
}

/// 音名（半音）と PLAY の O から PSG の周期を求める（O4A = 440Hz）
fn period_of(octave: i32, semitone: i32) -> u16 {
    let f = 440.0 * 2f64.powf((octave - 4) as f64 + (semitone - 9) as f64 / 12.0);
    (CLOCK / (16.0 * f)).round().clamp(1.0, 4095.0) as u16
}

/// 音の長さ（1/60 秒単位）。MSX の PLAY と同じく 14400/(T×L)
fn ticks_of(tempo: u32, length: u32, dots: u32) -> u32 {
    let base = 14400.0 / (tempo as f64 * length as f64);
    let mut t = base;
    let mut add = base;
    for _ in 0..dots {
        add /= 2.0;
        t += add;
    }
    t as u32
}

fn parse_mml(s: &str, st: &mut MmlState) -> Vec<Ev> {
    let b: Vec<u8> = s.bytes().map(|c| c.to_ascii_uppercase()).collect();
    let mut i = 0;
    let mut out = Vec::new();
    let num = |i: &mut usize| -> Option<u32> {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i > start {
            std::str::from_utf8(&b[start..*i]).ok()?.parse().ok()
        } else {
            None
        }
    };
    let dots = |i: &mut usize| -> u32 {
        let mut d = 0;
        while *i < b.len() && b[*i] == b'.' {
            d += 1;
            *i += 1;
        }
        d
    };
    while i < b.len() {
        let c = b[i];
        i += 1;
        match c {
            b'A'..=b'G' => {
                let mut semi = match c {
                    b'C' => 0,
                    b'D' => 2,
                    b'E' => 4,
                    b'F' => 5,
                    b'G' => 7,
                    b'A' => 9,
                    _ => 11,
                };
                let mut oct = st.octave;
                if i < b.len() && (b[i] == b'+' || b[i] == b'#') {
                    semi += 1;
                    i += 1;
                } else if i < b.len() && b[i] == b'-' {
                    semi -= 1;
                    i += 1;
                }
                if semi < 0 {
                    semi += 12;
                    oct -= 1;
                } else if semi > 11 {
                    semi -= 12;
                    oct += 1;
                }
                let len = num(&mut i).unwrap_or(st.length);
                let d = dots(&mut i);
                out.push(Ev::Note {
                    period: period_of(oct, semi),
                    ticks: ticks_of(st.tempo, len, d),
                    vol: st.volume,
                    env: st.env,
                });
            }
            b'N' => {
                let n = num(&mut i).unwrap_or(0) as i32;
                let d = dots(&mut i);
                let ticks = ticks_of(st.tempo, st.length, d);
                if n == 0 {
                    out.push(Ev::Rest { ticks });
                } else {
                    // N36 = O4C
                    let (oct, semi) = (n / 12 + 1, n % 12);
                    out.push(Ev::Note { period: period_of(oct, semi), ticks, vol: st.volume, env: st.env });
                }
            }
            b'R' => {
                let len = num(&mut i).unwrap_or(4);
                let d = dots(&mut i);
                out.push(Ev::Rest { ticks: ticks_of(st.tempo, len, d) });
            }
            b'O' => st.octave = num(&mut i).unwrap_or(4) as i32,
            b'L' => st.length = num(&mut i).unwrap_or(4).max(1),
            b'T' => st.tempo = num(&mut i).unwrap_or(120).max(32),
            b'V' => {
                st.volume = num(&mut i).unwrap_or(8).min(15) as u8;
                st.env = None;
            }
            b'S' => st.env = Some(num(&mut i).unwrap_or(1).min(15) as u8),
            b'M' => out.push(Ev::EnvPeriod(num(&mut i).unwrap_or(255).max(1) as u16)),
            b'>' => st.octave += 1,
            b'<' => st.octave -= 1,
            _ => {}
        }
    }
    out
}

/// 音を鳴らすデバイス。作れなければ無音で動く
pub struct Audio {
    pub psg: Arc<Mutex<Psg>>,
    _device: Option<tinyaudio::OutputDevice>,
}

impl Audio {
    pub fn start() -> Self {
        let psg = Arc::new(Mutex::new(Psg::new()));
        let p = psg.clone();
        let device = tinyaudio::run_output_device(
            tinyaudio::OutputDeviceParameters {
                sample_rate: SAMPLE_RATE,
                channels_count: 1,
                channel_sample_count: 1024,
            },
            move |data: &mut [f32]| {
                let mut psg = p.lock().unwrap();
                for s in data.iter_mut() {
                    *s = psg.next_sample();
                }
            },
        )
        .ok();
        Self { psg, _device: device }
    }

    pub fn sound(&self, r: usize, v: u8) {
        self.psg.lock().unwrap().write(r, v);
    }

    pub fn play(&self, a: &str, b: &str, c: &str) {
        self.psg.lock().unwrap().play([a, b, c]);
    }

    pub fn playing(&self) -> bool {
        self.psg.lock().unwrap().playing()
    }

    /// 音声デバイスが無い環境でも PLAY の終了待ちが進むように、時間を手動で進める
    pub fn advance_if_silent(&self, seconds: f64) {
        if self._device.is_none() {
            let mut psg = self.psg.lock().unwrap();
            let n = (seconds * SAMPLE_RATE as f64) as usize;
            for _ in 0..n {
                psg.next_sample();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_music_length_and_sound() {
        let mut p = Psg::new();
        p.write(7, 56);
        p.play([
            "V14T163L8O4FV15GV14GV15GV14GV15GV14FV15GV14GV15GV14GV15GV14GA",
            "S0M8000T163L8O4CD2DCD2DDE",
            "S0M8000T163L8O3FG4G4G8FG4G4GGA",
        ]);
        let mut n = 0usize;
        let mut energy = 0.0f64;
        while p.playing() && n < SAMPLE_RATE * 10 {
            let s = p.next_sample();
            energy += (s * s) as f64;
            n += 1;
        }
        let sec = n as f64 / SAMPLE_RATE as f64;
        // 8分音符14個 × 60/163/2 秒 ≒ 2.58 秒（1/60 秒単位に丸める）
        assert!((2.4..2.8).contains(&sec), "{sec}");
        assert!(energy > 1.0);
    }

    #[test]
    fn engine_tone() {
        let mut p = Psg::new();
        p.write(7, 56);
        p.write(1, 2);
        p.write(0, 100);
        p.write(8, 13);
        let e: f32 = (0..4410).map(|_| p.next_sample().abs()).sum();
        assert!(e > 10.0);
    }
}
