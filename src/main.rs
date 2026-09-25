//! DRIVE GAME2 (MSX・FAN ファンダム掲載 / BY HASEMAKO) の Rust 移植
//!
//! 誌面に掲載された原作 BASIC リストを書き起こし、行番号ごとに追って再現している。
//! - 画面は MSX の SCREEN 1（32×24文字 = 256×192ドット）を小さな VDP として持ち、
//!   ESC L で道を1行ずつ下に流し、VRAM を読んで当たり判定する原作の作りのまま動かす。
//! - 音は PSG（SOUND 文）と PLAY 文をエミュレートして鳴らす（psg.rs）。
//! - 1周の時間は実機（HB-F1XV, MSX-BASIC）で測った値に合わせている。
//! - 文字フォントは MSX の ROM フォントではなく、このために描いたもの。
//!   車・道・じゃま車の形は原作プログラム内のデータをそのまま使っている。

mod psg;

use macroquad::prelude::*;
use psg::Audio;

// ---------------------------------------------------------------------------
// 実機で測った時間
// ---------------------------------------------------------------------------

/// メインループ（行100〜140）1周の時間。HB-F1XV で約0.154秒だった
const LOOP_TIME: f64 = 0.154;
/// じゃま車を1台 PRINT した周はそのぶん遅くなる（実測 +0.036秒）
const OBSTACLE_TIME: f64 = 0.036;
/// クラスライン（64文字）を PRINT した周の追加時間（見積もり）
const CLASS_LINE_TIME: f64 = 0.12;
/// FOR I=0 TO n:NEXT の1回ぶん（FOR 4500 で 139/60 秒）
const FOR_STEP: f64 = 139.0 / 60.0 / 4501.0;
/// BEEP の長さ（実測 3/60 秒）
const BEEP_TIME: f64 = 3.0 / 60.0;

static SNAP_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const SCALE: f32 = 3.0;
const BORDER: f32 = 16.0;

/// MSX2 の初期パレット（0〜7 の3ビット RGB）
const PALETTE: [(u8, u8, u8); 16] = [
    (0, 0, 0),
    (0, 0, 0),
    (1, 6, 1),
    (3, 7, 3),
    (1, 1, 7),
    (2, 3, 7),
    (5, 1, 1),
    (2, 6, 7),
    (7, 1, 1),
    (7, 3, 3),
    (6, 6, 1),
    (6, 6, 4),
    (1, 4, 1),
    (6, 2, 5),
    (5, 5, 5),
    (7, 7, 7),
];

fn msx_color(i: u8) -> Color {
    let (r, g, b) = PALETTE[i as usize & 15];
    Color::from_rgba((r as u32 * 255 / 7) as u8, (g as u32 * 255 / 7) as u8, (b as u32 * 255 / 7) as u8, 255)
}

// MSX の文字コード
const ESC: u8 = 27;
const DIAMOND: u8 = 0x83; // ♦
const FUN: [u8; 2] = [0x01, 0x4B]; // 分（グラフィック文字）
const BYOU: [u8; 2] = [0x01, 0x4C]; // 秒

// ---------------------------------------------------------------------------
// フォント（このために描いた 5×7 ドット。MSX の ROM フォントは使っていない）
// ---------------------------------------------------------------------------

const GLYPHS: &[(u8, [&str; 7])] = &[
    (b'0', [".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."]),
    (b'1', ["..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."]),
    (b'2', [".###.", "#...#", "....#", "..##.", ".#...", "#....", "#####"]),
    (b'3', ["#####", "...#.", "..#..", "...#.", "....#", "#...#", ".###."]),
    (b'4', ["...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."]),
    (b'5', ["#####", "#....", "####.", "....#", "....#", "#...#", ".###."]),
    (b'6', ["..##.", ".#...", "#....", "####.", "#...#", "#...#", ".###."]),
    (b'7', ["#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."]),
    (b'8', [".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."]),
    (b'9', [".###.", "#...#", "#...#", ".####", "....#", "...#.", ".##.."]),
    (b'A', ["..#..", ".#.#.", "#...#", "#...#", "#####", "#...#", "#...#"]),
    (b'B', ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."]),
    (b'C', [".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."]),
    (b'D', ["####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."]),
    (b'E', ["#####", "#....", "#....", "####.", "#....", "#....", "#####"]),
    (b'F', ["#####", "#....", "#....", "####.", "#....", "#....", "#...."]),
    (b'G', [".###.", "#...#", "#....", "#.###", "#...#", "#...#", ".####"]),
    (b'H', ["#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"]),
    (b'I', [".###.", "..#..", "..#..", "..#..", "..#..", "..#..", ".###."]),
    (b'J', ["..###", "...#.", "...#.", "...#.", "...#.", "#..#.", ".##.."]),
    (b'K', ["#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"]),
    (b'L', ["#....", "#....", "#....", "#....", "#....", "#....", "#####"]),
    (b'M', ["#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"]),
    (b'N', ["#...#", "#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#"]),
    (b'O', [".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."]),
    (b'P', ["####.", "#...#", "#...#", "####.", "#....", "#....", "#...."]),
    (b'Q', [".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"]),
    (b'R', ["####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"]),
    (b'S', [".###.", "#...#", "#....", ".###.", "....#", "#...#", ".###."]),
    (b'T', ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."]),
    (b'U', ["#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."]),
    (b'V', ["#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."]),
    (b'W', ["#...#", "#...#", "#...#", "#.#.#", "#.#.#", "##.##", "#...#"]),
    (b'X', ["#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"]),
    (b'Y', ["#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."]),
    (b'Z', ["#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"]),
    (b'[', [".###.", ".#...", ".#...", ".#...", ".#...", ".#...", ".###."]),
    (b']', [".###.", "...#.", "...#.", "...#.", "...#.", "...#.", ".###."]),
    (b'<', ["...#.", "..#..", ".#...", "#....", ".#...", "..#..", "...#."]),
    (b'>', [".#...", "..#..", "...#.", "....#", "...#.", "..#..", ".#..."]),
];

fn build_patterns() -> Vec<[u8; 8]> {
    let mut pat = vec![[0u8; 8]; 256];
    for (code, rows) in GLYPHS {
        for (y, row) in rows.iter().enumerate() {
            pat[*code as usize][y] =
                row.bytes().enumerate().fold(0u8, |b, (x, c)| if c == b'#' { b | 0x80 >> x } else { b });
        }
    }
    // ♦（このために描いたもの）
    pat[DIAMOND as usize] = [0x10, 0x38, 0x7C, 0xFE, 0x7C, 0x38, 0x10, 0x00];
    // 分・秒（グラフィック文字。VRAM 上は 0Bh / 0Ch。このために描いたもの）
    pat[0x0B] = [0x24, 0x42, 0x81, 0x7E, 0x22, 0x22, 0x42, 0x8C];
    pat[0x0C] = [0x44, 0xEA, 0x55, 0xE4, 0x41, 0xC2, 0x4C, 0x00];
    pat
}

// ---------------------------------------------------------------------------
// 小さな VDP（SCREEN 1 相当）とテキスト出力
// ---------------------------------------------------------------------------

struct Screen1 {
    name: [u8; 768],
    patterns: Vec<[u8; 8]>,
    colors: [u8; 32],
    backdrop: u8,
    sprite_pat: [[u8; 8]; 2],
    /// スプライト 0, 1 の (x, y, 色)
    sprites: [(i32, i32, u8); 2],
    cx: usize,
    cy: usize,
}

impl Screen1 {
    fn new() -> Self {
        Self {
            name: [b' '; 768],
            patterns: build_patterns(),
            colors: [0x1F; 32],
            backdrop: 14,
            sprite_pat: [[0; 8]; 2],
            sprites: [(0, 209, 15), (0, 209, 1)],
            cx: 0,
            cy: 0,
        }
    }

    fn cls(&mut self) {
        self.name = [b' '; 768];
        self.cx = 0;
        self.cy = 0;
    }

    fn locate(&mut self, x: i32, y: i32) {
        self.cx = x.clamp(0, 31) as usize;
        self.cy = y.clamp(0, 23) as usize;
    }

    fn newline(&mut self) {
        self.cx = 0;
        if self.cy == 23 {
            self.name.copy_within(32.., 0);
            self.name[736..].fill(b' ');
        } else {
            self.cy += 1;
        }
    }

    fn insert_line(&mut self) {
        let y = self.cy;
        self.name.copy_within(y * 32..736, (y + 1) * 32);
        self.name[y * 32..(y + 1) * 32].fill(b' ');
        self.cx = 0;
    }

    fn put(&mut self, ch: u8) {
        self.name[self.cy * 32 + self.cx] = ch;
        self.cx += 1;
        if self.cx >= 32 {
            self.newline();
        }
    }

    /// PRINT の文字列部分（ESC Y / ESC L と、01h で始まるグラフィック文字を解釈）
    fn print(&mut self, s: &[u8]) {
        let mut i = 0;
        while i < s.len() {
            match s[i] {
                ESC if s.get(i + 1) == Some(&b'L') => {
                    self.insert_line();
                    i += 2;
                }
                ESC if s.get(i + 1) == Some(&b'Y') && i + 3 < s.len() => {
                    self.locate(s[i + 3] as i32 - 32, s[i + 2] as i32 - 32);
                    i += 4;
                }
                0x01 if i + 1 < s.len() => {
                    self.put(s[i + 1] - 0x40);
                    i += 2;
                }
                c => {
                    self.put(c);
                    i += 1;
                }
            }
        }
    }

    fn println(&mut self, s: &[u8]) {
        self.print(s);
        self.newline();
    }

    fn render(&self, img: &mut Image) {
        let back = msx_color(self.backdrop);
        for (i, &ch) in self.name.iter().enumerate() {
            let (col, row) = (i % 32, i / 32);
            let pat = &self.patterns[ch as usize];
            let c = self.colors[ch as usize / 8];
            let fg = if c >> 4 == 0 { back } else { msx_color(c >> 4) };
            let bg = if c & 15 == 0 { back } else { msx_color(c & 15) };
            for (y, bits) in pat.iter().enumerate() {
                for x in 0..8 {
                    let on = bits & (0x80 >> x) != 0;
                    img.set_pixel((col * 8 + x) as u32, (row * 8 + y) as u32, if on { fg } else { bg });
                }
            }
        }
        // 番号の小さいスプライトほど手前。表示は Y+1 の位置（MSX の仕様）
        for n in (0..2).rev() {
            let (sx, sy, color) = self.sprites[n];
            if color == 0 || sy >= 208 {
                continue;
            }
            for (y, bits) in self.sprite_pat[n].iter().enumerate() {
                for x in 0..8 {
                    if bits & (0x80 >> x) != 0 {
                        let (px, py) = (sx + x, sy + 1 + y as i32);
                        if (0..256).contains(&px) && (0..192).contains(&py) {
                            img.set_pixel(px as u32, py as u32, msx_color(color));
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BASIC の実行環境（画面・音・入力・時間）
// ---------------------------------------------------------------------------

struct Machine {
    scr: Screen1,
    audio: Audio,
    img: Image,
    tex: Texture2D,
    time_zero: f64,
    seed: u64,
    last_frame: f64,
    // 動作確認用
    snapshot: Option<(String, Vec<f64>)>,
    /// Some(true)=自動で走る, Some(false)=自動でタイトルを進めるだけ（わざとクラッシュさせる）
    autoplay: Option<bool>,
    started: f64,
}

impl Machine {
    fn new() -> Self {
        let img = Image::gen_image_color(256, 192, BLACK);
        let tex = Texture2D::from_image(&img);
        tex.set_filter(FilterMode::Nearest);
        let snapshot = std::env::var("DRIVE2_SNAPSHOT").ok().map(|p| {
            // カンマ区切りで複数の時刻を指定できる（out.rgba → out.0.rgba, out.1.rgba ...）
            let at: Vec<f64> = std::env::var("DRIVE2_SNAPSHOT_AT")
                .unwrap_or_else(|_| "12".into())
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            (p, at)
        });
        Self {
            scr: Screen1::new(),
            audio: Audio::start(),
            img,
            tex,
            time_zero: get_time(),
            seed: macroquad::miniquad::date::now().to_bits() | 1,
            last_frame: get_time(),
            snapshot,
            autoplay: std::env::var("DRIVE2_AUTOPLAY").ok().map(|v| v != "crash"),
            started: get_time(),
        }
    }

    /// 0 以上 1 未満の乱数（RND(1)）
    fn rnd(&mut self) -> f64 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        (self.seed >> 11) as f64 / (1u64 << 53) as f64
    }

    /// TIME（1/60 秒ごとに増える）
    fn time(&self) -> i32 {
        ((get_time() - self.time_zero) * 60.0).min(32767.0) as i32
    }

    fn reset_time(&mut self) {
        self.time_zero = get_time();
    }

    /// STICK(0) OR STICK(1)
    fn stick(&self) -> usize {
        if self.autoplay == Some(true) {
            return self.auto_stick();
        }
        let (u, r, d, l) = (
            is_key_down(KeyCode::Up),
            is_key_down(KeyCode::Right),
            is_key_down(KeyCode::Down),
            is_key_down(KeyCode::Left),
        );
        match (u, r, d, l) {
            (true, false, false, false) => 1,
            (true, true, false, false) => 2,
            (false, true, false, false) => 3,
            (false, true, true, false) => 4,
            (false, false, true, false) => 5,
            (false, false, true, true) => 6,
            (false, false, false, true) => 7,
            (true, false, false, true) => 8,
            _ => 0,
        }
    }

    /// STRIG(0) OR STRIG(1)
    fn strig(&self) -> bool {
        self.autoplay == Some(true) || is_key_down(KeyCode::Space) || is_key_down(KeyCode::Z)
    }

    /// 自動操作（動作確認用）: 道の真ん中へ寄せる
    fn auto_stick(&self) -> usize {
        let (x, y, _) = self.scr.sprites[0];
        let row = ((y / 8) - 2).clamp(0, 23) as usize;
        let line = &self.scr.name[row * 32..row * 32 + 32];
        let left = line.iter().position(|&c| c == b'a').unwrap_or(12) as i32;
        let target = (left + 4) * 8 - 4;
        if x < target - 4 {
            3
        } else if x > target + 4 {
            7
        } else {
            0
        }
    }

    /// 1フレーム描画して次のフレームへ
    async fn frame(&mut self) {
        if is_key_pressed(KeyCode::Escape) {
            std::process::exit(0);
        }
        let now = get_time();
        self.audio.advance_if_silent(now - self.last_frame);
        self.last_frame = now;

        self.scr.render(&mut self.img);
        self.tex.update(&self.img);
        clear_background(msx_color(self.scr.backdrop));
        draw_texture_ex(
            &self.tex,
            BORDER * SCALE,
            BORDER * SCALE,
            WHITE,
            DrawTextureParams { dest_size: Some(vec2(256.0 * SCALE, 192.0 * SCALE)), ..Default::default() },
        );
        if let Some((path, at)) = &mut self.snapshot {
            if let Some(&t) = at.first() {
                if now - self.started >= t {
                    let n = SNAP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    std::fs::write(format!("{path}.{n}.rgba"), &self.img.bytes).ok();
                    at.remove(0);
                }
            } else {
                std::process::exit(0);
            }
        }
        next_frame().await;
    }

    /// 指定秒数、画面を出しながら待つ
    async fn wait(&mut self, sec: f64) {
        let end = get_time() + sec;
        loop {
            self.frame().await;
            if get_time() >= end {
                break;
            }
        }
    }

    /// FOR I=0 TO n:NEXT の空ループ
    async fn for_loop(&mut self, n: i32) {
        self.wait((n + 1) as f64 * FOR_STEP).await;
    }

    /// FOR I=0 TO 0:I=PLAY(0):NEXT（演奏が終わるまで待つ）
    async fn wait_play(&mut self) {
        while self.audio.playing() {
            self.frame().await;
        }
    }

    async fn beep(&mut self) {
        self.audio.play("V15T255L64O6C", "", "");
        self.wait(BEEP_TIME).await;
    }
}

/// PRINT USING の # 部分を数値で埋める（桁あふれは先頭に %）
fn using(fmt: &[u8], vals: &[i32]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut vi = 0;
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] == b'#' {
            let start = i;
            while i < fmt.len() && fmt[i] == b'#' {
                i += 1;
            }
            let w = i - start;
            let s = vals.get(vi).copied().unwrap_or(0).to_string();
            vi += 1;
            if s.len() > w {
                out.push(b'%');
                out.extend_from_slice(s.as_bytes());
            } else {
                out.extend(std::iter::repeat_n(b' ', w - s.len()));
                out.extend_from_slice(s.as_bytes());
            }
        } else {
            out.push(fmt[i]);
            i += 1;
        }
    }
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// ---------------------------------------------------------------------------
// ゲーム本体（原作の変数名をそのまま使う）
// ---------------------------------------------------------------------------

struct Vars {
    ch: [i32; 256],      // CH(n): 1=道 2=安全地帯 3=じゃま車 4=クラスライン
    w_str: Vec<Vec<u8>>, // W$(n): 道の1行（1行挿入のエスケープシーケンス付き）
    hi: i32,
    c: i32,
    f: bool,
    t: i32,
    x: i32,
    y: i32,
    w: i32,
    xx: i32,
    sp: i32,
}

enum Next {
    Main,      // GOTO100
    Safety,    // 行160
    Crash,     // 行170
    ClassLine, // 行190
}

/// S(STICK): 右=+1 左=-1
fn s_tab(s: usize) -> i32 {
    match s {
        3 => 1,
        7 => -1,
        _ => 0,
    }
}

async fn run(m: &mut Machine) {
    // 行10: KEYOFF:SCREEN1,0:COLOR1,15,14:WIDTH32:PRINTSPC(203)"PLEASE WAIT"
    m.scr.colors = [0x1F; 32];
    m.scr.backdrop = 14;
    m.scr.cls();
    m.scr.print(&[b' '; 203]);
    m.scr.println(b"PLEASE WAIT");

    // 行20: 文字ごとの当たり判定表
    let mut v = Vars {
        ch: [0; 256],
        w_str: Vec::new(),
        hi: 10800,
        c: 1,
        f: true,
        t: 0,
        x: 0,
        y: 0,
        w: 11,
        xx: 0,
        sp: 0,
    };
    for i in 33..=99 {
        v.ch[i] = if (65..91).contains(&i) { 4 } else { 1 };
    }
    for i in (161..=255).step_by(8) {
        v.ch[i] = 3;
    }
    v.ch[32] = 3;
    v.ch[131] = 2;
    v.ch[133] = 2;

    // 行30: 自車のスプライトと道の文字列
    // SPRITE$(0)=CHR$(255)+"けけ"+CHR$(255)+CHR$(255)+"くくく"  （け=99h く=98h）
    m.scr.sprite_pat[0] = [0xFF, 0x99, 0x99, 0xFF, 0xFF, 0x98, 0x98, 0x98];
    // SPRITE$(1)="BffBBﾃﾃﾃ"  （ﾃ=C3h）
    m.scr.sprite_pat[1] = [0x42, 0x66, 0x66, 0x42, 0x42, 0xC3, 0xC3, 0xC3];
    for i in 0..23usize {
        let mut s = vec![ESC, b'L'];
        s.extend(std::iter::repeat_n(DIAMOND, i + 1));
        s.extend_from_slice(b"a%%%%%%b");
        s.extend(std::iter::repeat_n(DIAMOND, 23 - i));
        v.w_str.push(s);
    }

    // 行40: 文字の形と色（原作の DATA）
    m.scr.patterns[b'a' as usize] = [0x80, 0x80, 0xC0, 0xC0, 0xC0, 0xC0, 0x80, 0x80];
    m.scr.patterns[b'b' as usize] = [0x01, 0x01, 0x03, 0x03, 0x03, 0x03, 0x01, 0x01];
    m.scr.patterns[161] = [0xFF, 0x99, 0x99, 0xFF, 0xFF, 0x3C, 0x3C, 0x3C];
    m.scr.patterns[b'%' as usize] = [0xFF; 8];
    for i in 0..12 {
        m.scr.patterns[161 + i * 8] = m.scr.patterns[161];
        m.scr.colors[20 + i] = ((i as u8 + 2) << 4) | 1;
    }
    m.scr.colors[4] = 240; // VPOKE8196,240: 文字32〜39（空白と %）を白/透明
    m.scr.colors[12] = 222; // VPOKE8204,222: 文字96〜103（a b）を紫/灰
    m.wait(1.0).await; // 定義処理にかかる時間

    loop {
        // 行50: タイトル
        v.t = 0;
        v.c = 1;
        v.f = true;
        hide_sprites(m);
        m.scr.cls();
        m.scr.print(&[b' '; 202]);
        m.scr.println(b"[DRIVE%GAME]");
        gosub220(m, &v).await;

        // 行60: 道を敷いて GO
        m.scr.locate(0, 0);
        for _ in 0..=24 {
            let s = v.w_str[11].clone();
            m.scr.print(&s);
        }
        m.scr.locate(13, 3);
        m.scr.println(b"<%GO%>");
        m.audio.sound(7, 56);

        // 行70: スタートの曲
        m.audio.play(
            "V14T163L8O4FV15GV14GV15GV14GV15GV14FV15GV14GV15GV14GV15GV14GA",
            "S0M8000T163L8O4CD2DCD2DDE",
            "S0M8000T163L8O3FG4G4G8FG4G4GGA",
        );
        m.wait_play().await;

        // 行80: 初期化とエンジン音
        v.x = 128;
        v.y = 170;
        v.w = 11;
        v.xx = 0;
        v.sp = 0;
        v.t = 3000;
        m.for_loop(999).await;
        m.audio.sound(1, 2);
        m.audio.sound(8, 13);
        m.reset_time();

        // 行100〜140: メインループ
        let crashed = 'main: loop {
            let mut next = main_step(m, &mut v).await;
            loop {
                match next {
                    Next::Main => continue 'main,
                    Next::Safety => {
                        // 行160: 安全地帯に入ると押し戻される
                        v.y += 16;
                        continue 'main;
                    }
                    Next::Crash => break 'main true,
                    Next::ClassLine => {
                        // 行190: クラスライン通過
                        if v.f {
                            next = Next::Main;
                        } else if v.c < 5 {
                            m.scr.colors[16] = (m.rnd() * 256.0) as u8;
                            v.c += 1;
                            v.f = true;
                            next = Next::Main;
                        } else {
                            break 'main false;
                        }
                    }
                }
            }
        };

        if crashed {
            // 行170: クラッシュ（ノイズの爆発音と道の点滅）
            m.audio.sound(8, 0);
            m.audio.sound(6, 30);
            m.audio.sound(7, 40);
            m.audio.play("", "S0M2000O1C2", "");
            while m.audio.playing() {
                m.scr.colors[4] = if m.rnd() < 0.5 { (m.rnd() * 256.0) as u8 } else { 240 };
                m.frame().await;
            }
            m.scr.colors[4] = 240;
            // 行180
            m.audio.sound(7, 56);
            m.audio.play("T180L4O4FR8B-", "S0M5000T180L4O4CR8F", "S0T180L4O3FR8B-R1");
            m.for_loop(4500).await;
            m.scr.cls();
            hide_sprites(m);
            m.scr.locate(12, 4);
            m.scr.println(b"[CRUSH]");
            m.scr.locate(11, 8);
            m.scr.println(&cat(&[b"[CLASS%", &[(71 - v.c) as u8], b"%]"]));
            gosub220(m, &v).await;
        } else {
            // 行190〜210: 全クラスクリア
            let ti = m.time();
            if v.hi > ti {
                v.hi = ti;
            }
            m.audio.sound(8, 0);
            m.audio.play(
                "S0T180L8O4R8BR8G+R8BR8BA",
                "S0T180L8O3EBG+BEBG+BA",
                "S0M6000T180L8O4BBBAG+G+F+G+AR1",
            );
            m.for_loop(4000).await;
            hide_sprites(m);
            m.scr.cls();
            m.scr.locate(6, 5);
            let msg = b"<ALL%CLEAR%[CLASS%A]>";
            for i in 0..=21usize {
                let n = if matches!(i, 3 | 9 | 16) {
                    200
                } else if i == 0 {
                    2000
                } else {
                    0
                };
                m.for_loop(n).await;
                if let Some(&c) = msg.get(i) {
                    m.scr.put(c);
                }
                m.beep().await;
            }
            m.scr.locate(10, 8);
            let fmt = cat(&[b"[TIME%#", &FUN, b"##", &BYOU, b"]"]);
            m.scr.println(&using(&fmt, &[ti / 3600, (ti / 60) % 60]));
            gosub220(m, &v).await;
        }
    }
}

/// 行100〜140 を1周し、行140 の ON CH(...) GOTO の行き先を返す
async fn main_step(m: &mut Machine, v: &mut Vars) -> Next {
    let mut cost = LOOP_TIME;

    // 行100: 道を左右にゆらす
    v.w = (v.w as f64 + m.rnd() * 3.0 - 1.0) as i32;
    if v.w == 23 {
        v.w = 22;
    } else if v.w == -1 {
        v.w = 0;
    }

    // 行110: 1行挿入で道を下へ流す。距離を足し、クラスラインかじゃま車を置く
    m.scr.locate(0, 0);
    let s = v.w_str[v.w as usize].clone();
    m.scr.println(&s);
    v.t += (160 - v.y) * (160 - v.y) / 80;
    if v.t > 9999 {
        v.t = 0;
        v.f = false;
        m.scr.locate(0, 0);
        m.scr.print(&[(70 - v.c) as u8; 64]);
        cost += CLASS_LINE_TIME;
    } else if m.rnd() * (v.c + 7) as f64 > 6.0 {
        let x = (v.w as f64 + 2.0 + m.rnd() * 6.0) as i32;
        m.scr.locate(x, 0);
        let car = 161 + (m.rnd() * 12.0) as u8 * 8;
        m.scr.print(&[car]);
        cost += OBSTACLE_TIME;
    }

    // 行120: トリガーで加速（SP が小さいほど速い）
    v.sp = v.sp + 1 + if m.strig() { -2 } else { 0 };
    if v.sp < 0 {
        v.sp = 0;
    } else if v.sp > 6 {
        v.sp = 5;
    }

    // 行130: 横方向は慣性つき
    v.xx += s_tab(m.stick());
    v.xx = v.xx.clamp(-4, 4);

    // 行140: 移動・表示・当たり判定
    v.y = v.y + v.sp - v.y.signum();
    v.x += v.xx;
    m.scr.sprites[0].0 = v.x;
    m.scr.sprites[0].1 = v.y;
    m.scr.sprites[1].0 = v.x;
    m.scr.sprites[1].1 = v.y;

    m.wait(cost).await;

    if v.y / 190 != 0 {
        return Next::Crash;
    }
    m.audio.sound(0, v.y as u8);
    let pos = (v.x + 4) / 8 + (v.y / 8) * 32;
    let code = if (0..768).contains(&pos) { m.scr.name[pos as usize] } else { 0 };
    match v.ch[code as usize] {
        1 => Next::Main,
        3 => Next::Crash,
        4 => Next::ClassLine,
        _ => Next::Safety, // 2 と、0（どれにも当たらず次の行へ進む）は行160
    }
}

/// 行220: PUSH SPACE KEY とハイスコア表示、トリガー待ち
async fn gosub220(m: &mut Machine, v: &Vars) {
    m.scr.locate(8, 12);
    m.scr.println(b"[PUSH%SPACE%KEY]");
    m.scr.locate(7, 18);
    let fmt = cat(&[b"<HI%SCORE%[#", &FUN, b"##", &BYOU, b"]>"]);
    m.scr.println(&using(&fmt, &[v.hi / 3600, (v.hi / 60) % 60]));
    if m.autoplay.is_some() {
        m.wait(3.0).await;
        return;
    }
    while !m.strig() {
        m.frame().await;
    }
}

/// 行230: スプライトを画面外へ（色もここで決まる）
fn hide_sprites(m: &mut Machine) {
    m.scr.sprites[0] = (0, -31, 15);
    m.scr.sprites[1] = (0, -31, 1);
}

fn window_conf() -> Conf {
    Conf {
        window_title: "DRIVE GAME2".to_owned(),
        window_width: ((256.0 + BORDER * 2.0) * SCALE) as i32,
        window_height: ((192.0 + BORDER * 2.0) * SCALE) as i32,
        window_resizable: false,
        ..Default::default()
    }
}

#[macroquad::main(window_conf)]
async fn main() {
    let mut m = Machine::new();
    run(&mut m).await;
}
