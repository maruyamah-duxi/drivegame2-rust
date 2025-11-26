use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    style::{self, Color, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType},
    ExecutableCommand,
};
use rand::Rng;
use std::{
    collections::VecDeque,
    io::{stdout, Write},
    time::{Duration, Instant},
};

// --- 定数定義 (MSX BASICのパラメータを参考に調整) ---
const SCREEN_WIDTH: u16 = 32;   // SCREEN 1, WIDTH 32
const SCREEN_HEIGHT: u16 = 24;
const ROAD_WIDTH: u16 = 12;     // 道路の幅
const MAX_SPEED: u64 = 30;      // 更新間隔(ms) - 小さいほど速い
const MIN_SPEED: u64 = 100;     // 更新間隔(ms) - 大きいほど遅い

// --- ゲームの状態管理 ---
struct GameState {
    player_x: f32,      // プレイヤーのX座標 (MSX: X)
    velocity_x: f32,    // 横方向の慣性 (MSX: XX)
    speed_level: u64,   // 現在のスピード (MSX: SP)
    distance: u32,      // 走行距離 (MSX: T / TIME)
    road_center: i32,   // 道路の中心位置 (MSX: W)
    road_buffer: VecDeque<(u16, u16)>, // 画面上の道路データ (左壁X, 右壁X)
    game_over: bool,
    score: u32,
    high_score: u32,
}

impl GameState {
    fn new() -> Self {
        let mut road = VecDeque::new();
        // 初期道路生成
        for _ in 0..SCREEN_HEIGHT {
            road.push_back((10, 10 + ROAD_WIDTH));
        }

        Self {
            player_x: (SCREEN_WIDTH / 2) as f32,
            velocity_x: 0.0,
            speed_level: MIN_SPEED,
            distance: 0,
            road_center: (SCREEN_WIDTH / 2) as i32,
            road_buffer: road,
            game_over: false,
            score: 0,
            high_score: 10800, // MSX: HI=10800
        }
    }

    // MSX Line 100-110: 道路生成ロジック
    fn update_road(&mut self) {
        let mut rng = rand::thread_rng();

        // 道を左右に振る (W=W+RND(1)*3-1)
        let delta: i32 = rng.gen_range(-1..=1);
        self.road_center += delta;

        // 画面端の制限 (MSX: IF W=23 ... IF W=-1 ...)
        if self.road_center < 2 { self.road_center = 2; }
        if self.road_center > (SCREEN_WIDTH as i32 - 2 - ROAD_WIDTH as i32) {
             self.road_center = SCREEN_WIDTH as i32 - 2 - ROAD_WIDTH as i32;
        }

        let left_wall = self.road_center as u16;
        let right_wall = left_wall + ROAD_WIDTH;

        // 新しい行を追加し、古い行を削除（スクロール）
        self.road_buffer.push_back((left_wall, right_wall));
        if self.road_buffer.len() > SCREEN_HEIGHT as usize {
            self.road_buffer.pop_front();
        }
    }

    // MSX Line 120-140: 移動と衝突判定
    fn update_player(&mut self, input_x: f32, accelerate: bool) {
        // 加速 (MSX: SP calc)
        if accelerate {
            if self.speed_level > MAX_SPEED {
                self.speed_level -= 5;
            }
        } else {
            if self.speed_level < MIN_SPEED {
                self.speed_level += 2;
            }
        }

        // 慣性移動 (MSX: XX calc)
        // 入力があれば加速、なければ減速
        if input_x != 0.0 {
            self.velocity_x += input_x * 0.5;
        } else {
            self.velocity_x *= 0.8; // 摩擦
        }

        // 速度制限 (MSX: IF XX<-4 ... XX>4)
        self.velocity_x = self.velocity_x.clamp(-2.0, 2.0);
        self.player_x += self.velocity_x;

        // 衝突判定 (MSX: VPEEK logic の代替)
        // プレイヤーのY座標は画面下部固定とする（MSX版も基本は下部にいる）
        let player_y_idx = (SCREEN_HEIGHT - 4) as usize;
        if let Some((l_wall, r_wall)) = self.road_buffer.get(player_y_idx) {
            let p_x = self.player_x as u16;
            // 壁に当たったか？
            if p_x <= *l_wall || p_x >= *r_wall {
                self.game_over = true;
            }
        }

        self.score += 1;
    }
}

fn main() -> std::io::Result<()> {
    // --- 初期化 (Line 10) ---
    let mut stdout = stdout();
    terminal::enable_raw_mode()?; // 行入力を無効化（リアルタイム入力）
    stdout.execute(cursor::Hide)?;
    stdout.execute(terminal::SetSize(SCREEN_WIDTH, SCREEN_HEIGHT))?;

    let mut state = GameState::new();
    let mut last_tick = Instant::now();

    // --- メインループ (Line 90 'MAIN') ---
    'game_loop: loop {
        // 1. 入力処理 (Line 120-130: STRIG, STICK)
        let mut input_x = 0.0;
        let mut accelerate = false;

        if event::poll(Duration::from_millis(5))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Esc => break 'game_loop,
                        KeyCode::Left => input_x = -1.0,
                        KeyCode::Right => input_x = 1.0,
                        KeyCode::Char(' ') => accelerate = true, // Spaceで加速
                        _ => {}
                    }
                }
            }
        }

        // ゲームオーバー時はリセット待ち
        if state.game_over {
            draw_game_over(&mut stdout, &state)?;
            // 何かキーを押したらリセット (Line 220)
            loop {
                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind == KeyEventKind::Press {
                             if key.code == KeyCode::Esc { break 'game_loop; }
                             // リセット処理
                             let hi = state.high_score.max(state.score);
                             state = GameState::new();
                             state.high_score = hi;
                             break;
                        }
                    }
                }
            }
            continue;
        }

        // 2. 更新処理 (Line 100-140)
        // 設定されたスピードに応じて更新頻度を変える
        if last_tick.elapsed() >= Duration::from_millis(state.speed_level) {
            state.update_road();
            state.update_player(input_x, accelerate);
            last_tick = Instant::now();

            // 3. 描画処理 (Line 110, 140)
            draw_screen(&mut stdout, &state)?;
        }
    }

    // --- 終了処理 ---
    stdout.execute(cursor::Show)?;
    terminal::disable_raw_mode()?;
    println!("Bye!");
    Ok(())
}

// 画面描画関数
fn draw_screen(stdout: &mut std::io::Stdout, state: &GameState) -> std::io::Result<()> {
    stdout.execute(Clear(ClearType::All))?;

    // 道路と壁の描画
    for (y, (l_wall, r_wall)) in state.road_buffer.iter().enumerate() {
        if y >= SCREEN_HEIGHT as usize { break; }

        // 左の壁 (MSX: ◆)
        stdout.execute(cursor::MoveTo(*l_wall, y as u16))?;
        stdout.execute(SetForegroundColor(Color::DarkGreen))?;
        write!(stdout, "#")?; // 壁文字

        // 路面 (MSX: a%%%%%%b の部分)
        // 簡易的に空白にするか、点線を描く
        if y % 4 == 0 {
             let center = (l_wall + r_wall) / 2;
             stdout.execute(cursor::MoveTo(center, y as u16))?;
             stdout.execute(SetForegroundColor(Color::Grey))?;
             write!(stdout, "|")?;
        }

        // 右の壁
        stdout.execute(cursor::MoveTo(*r_wall, y as u16))?;
        stdout.execute(SetForegroundColor(Color::DarkGreen))?;
        write!(stdout, "#")?;
    }

    // プレイヤーの描画 (MSX: PUT SPRITE 0)
    let player_screen_y = (SCREEN_HEIGHT - 4) as u16;
    let p_x = state.player_x as u16;

    stdout.execute(cursor::MoveTo(p_x, player_screen_y))?;
    stdout.execute(SetForegroundColor(Color::Red))?;
    // 車のスプライトの代わりに文字を表示
    write!(stdout, "A")?;

    // スコア表示
    stdout.execute(cursor::MoveTo(0, 0))?;
    stdout.execute(SetForegroundColor(Color::White))?;
    stdout.execute(SetBackgroundColor(Color::Blue))?;
    write!(stdout, "SCORE: {:05}  HI: {:05}", state.score, state.high_score)?;
    stdout.execute(style::ResetColor)?;

    stdout.flush()?;
    Ok(())
}

// ゲームオーバー画面 (Line 180 [CRUSH])
fn draw_game_over(stdout: &mut std::io::Stdout, state: &GameState) -> std::io::Result<()> {
    let center_x = SCREEN_WIDTH / 2 - 5;
    let center_y = SCREEN_HEIGHT / 2;

    stdout.execute(cursor::MoveTo(center_x, center_y))?;
    stdout.execute(SetForegroundColor(Color::Red))?;
    write!(stdout, "[CRUSH!]")?; // MSX: [CRUSH]

    stdout.execute(cursor::MoveTo(center_x - 2, center_y + 1))?;
    stdout.execute(SetForegroundColor(Color::Yellow))?;
    write!(stdout, "PUSH KEY RESTART")?; // MSX: [PUSH SPACE KEY]

    stdout.flush()?;
    Ok(())
}

