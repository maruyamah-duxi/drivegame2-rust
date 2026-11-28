#!/usr/bin/env bash
# Claude Code の PreToolUse フック（.claude/settings.json から呼ばれる）。
#
# Claude が `git commit` / `git push` を実行する直前に gitleaks でシークレット混入を検査し、
# 見つかればコマンドを止める（exit 2。理由は Claude に返る）。GHAS の push protection の代わり。
#   * commit 前: コミットされうる変更すべて（ステージ済み・未ステージ・未追跡の新規ファイル）。
#                `git add new.py && git commit` のように同じコマンドで追加するファイルも、
#                フックの時点ではまだ未追跡なので、一時的なインデックスに全部載せて検査する
#                （本物のインデックスには触らない）
#   * push 前  : push しようとしているコミットのうち、push 先のリモートにまだ無いもの
#                （push 先が URL などで特定できなければ、push する全コミット）
# 検査する場所は、コマンド中の `cd <dir>`・`git -C <dir>`・`--git-dir` / `--work-tree`
# （GIT_DIR / GIT_WORK_TREE 環境変数を含む。前の文での export・代入・unset、env コマンドも追う）を追って決める
# （別の worktree や別のリポジトリでのコミットを、プロジェクトのディレクトリと取り違えない）。
# 変数で組み立てたパスなど解決できない場所は、検査できないので止める。
# 限界: eval や別スクリプトの中で実行される git は追えない（git と commit / push の文字が
#       コマンド中にあれば、作業ディレクトリでの commit / push として検査はする）。
#       git のエイリアス（git config alias.ci commit で `git ci` など）も追えない。
# 除外は .gitleaks.toml / .gitleaksignore（security.yml と共通）。
#
# gitleaks は版を固定する。PATH にあっても版が違えば使わず、版と SHA-256 を固定した公式バイナリを
# 取得してキャッシュする（版は .github/workflows/security.yml の GITLEAKS_VERSION と揃える。更新時は両方）。
# 検査できない状態（取得失敗、gitleaks のエラー、コマンドを解析できないなど）では、安全側に倒してコマンドを止める。
# フック自体がタイムアウトすると Claude Code はコマンドを通してしまうので、取得には
# フックのタイムアウト（settings.json の 120 秒）より短い上限を付ける。
set -uo pipefail

GITLEAKS_VERSION=8.30.1
LEAK_EXIT=99   # gitleaks が「検出あり」で返す終了コード。これ以外の失敗はエラーとして扱う
# macOS 標準の bash 3.2 でも動くよう、連想配列は使わない
gitleaks_sha256() {
  case "$1" in
    linux_x64)    echo 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
    linux_arm64)  echo e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
    darwin_x64)   echo dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709 ;;
    darwin_arm64) echo b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
  esac
}

block() { echo "secret-guard: $*" >&2; exit 2; }

# フックが想定外に落ちると（set -u の未定義変数など）終了コード 1 になり、Claude Code は
# コマンドを通してしまう。0（通す）と 2（止める）以外で終わったら、止める側に寄せる。
tmp_index=""
on_exit() {
  local rc=$?
  [ -n "$tmp_index" ] && rm -f "$tmp_index"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    echo "secret-guard: フックが異常終了（終了コード ${rc}）したため、念のため止めました。" >&2
    exit 2
  fi
}
trap on_exit EXIT

input=$(cat)

# 手早く絞る: git と commit / push の両方を含まないコマンドは対象外
printf '%s' "$input" | grep -Eq 'git' && printf '%s' "$input" | grep -Eq '(commit|push)' || exit 0

command -v python3 >/dev/null 2>&1 || block "python3 が無いため、コマンドを解析できず念のため止めました。"

# コマンドを解析して、検査対象を 1 行 1 件で出す:
#   commit<TAB><work tree><TAB><git dir（指定なしは -）>
#   push<TAB><work tree><TAB><git dir><TAB><push する元の ref（空白区切り）><TAB><push 先（リモート名 / URL / 指定なしは -）>
#   unresolved<TAB><解決できなかったパス>
targets=$(printf '%s' "$input" | python3 -c '
import json, os, re, shlex, sys

data = json.load(sys.stdin)
cmd = (data.get("tool_input") or {}).get("command") or ""
cwd = data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
out = []

VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

def resolve(base, path, env=None):
    """パスの $VAR と ~ を展開する。コマンドの中で代入・export された値（env / shell_env）を優先し、
    無ければフック自身の環境変数を使う（HOME=/x && cd $HOME をフックの実 HOME と取り違えない）。
    決められない変数（$(...) で作った値、未定義など）が残れば unresolved として止める"""
    vals = dict(os.environ)
    vals.update(shell_env)
    vals.update(env or {})
    def sub(m):
        name = m.group(1) or m.group(2)
        return vals[name] if name in vals else m.group(0)
    p = VAR.sub(sub, path)
    if p == "~" or p.startswith("~/"):
        p = vals.get("HOME", "~") + p[1:]
    if "$" in p or p.startswith("~"):
        out.append("unresolved\t" + path)
    return os.path.normpath(os.path.join(base, p))

# git のグローバルオプションのうち、値を次の引数で取るもの
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path"}
# git push のオプションのうち、値を次の引数で取るもの
PUSH_OPTS_WITH_ARG = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}

def push_sources(args):
    positional, refs, i, repo, delete = [], [], 0, "", False
    while i < len(args):
        a = args[i]
        if a in ("--delete", "-d"):           # ブランチの削除。何も転送しない
            delete = True
        elif a == "--mirror":                 # ブランチだけでなくタグ・notes なども全部送る
            refs.append("--all")
        elif a in ("--all", "--branches"):
            refs.append("--branches")
        elif a == "--tags":
            refs.append("--tags")
        elif a == "--repo" and i + 1 < len(args):
            repo = args[i + 1]; i += 1
        elif a.startswith("--repo="):
            repo = a.split("=", 1)[1]
        elif a in PUSH_OPTS_WITH_ARG:
            i += 1
        elif not a.startswith("-"):
            positional.append(a)
        i += 1
    for spec in positional[1:]:            # 先頭はリモート名
        src = spec.lstrip("+").split(":", 1)[0]
        if src:                            # ":branch"（削除）は検査するものが無い
            refs.append(src)
    # 位置引数がある場合は、--repo より位置引数の先頭が push 先になる（git の仕様。--repo=x main は main が宛先）
    remote = positional[0] if positional else repo
    if delete:
        return [], remote                  # 検査するものが無い
    return (refs or ["HEAD"]), remote

# git の向き先を変える環境変数。コマンドの前の文で export / 代入されたものも、後の git に効くので追う
# （サブシェルの範囲は区別しない。効きすぎる側に倒れるだけで、検査が漏れる側には倒れない）
GIT_ENV_KEYS = ("GIT_DIR", "GIT_WORK_TREE")
shell_env = {k: os.environ[k] for k in GIT_ENV_KEYS if os.environ.get(k)}
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

def heredoc_words(line):
    """行の中で本当に始まっているヒアドキュメントの終端語を返す。
    shlex で字句に分けるので、引用符の中や # コメントの `<<WORD` はヒアドキュメント扱いしない。
    行だけでは字句に分けられない（引用符が次の行へ続くなど）ときは、ヒアドキュメント無しとみなす
    （本文を除かないだけなので、検査が漏れる側には倒れない）"""
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        toks = list(lex)
    except ValueError:
        return []
    words = []
    for k, t in enumerate(toks):
        if t == "<<" and k + 1 < len(toks):          # <<< はヒアストリングで別の字句になる
            w = toks[k + 1]
            dash = w.startswith("-")
            w = w[1:] if dash else w
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", w or ""):
                words.append((dash, w))
    return words

def strip_heredocs(text):
    """ヒアドキュメント（<<EOF … EOF）の本文を除く。本文はコマンドではないので、
    コミットメッセージ中の `cd …` や `git push` を文として解釈しないようにする"""
    out, pending = [], []
    for line in text.split("\n"):
        if pending:
            dash, word = pending[0]
            if (line.lstrip("\t") if dash else line) == word:
                pending.pop(0)
            continue
        out.append(line)
        pending = heredoc_words(line)
    return "\n".join(out)

def parse(text):
    found = False
    # 改行は文の区切り。改行そのものも残す（# コメントは改行で終わるので、消すと後ろの行まで
    # コメント扱いになり、`# メモ` の次の行の cd / git commit を見落とす）
    lex = shlex.shlex(strip_heredocs(text).replace("\n", " ;\n"), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    tokens = list(lex)
    here, seg = cwd, []
    for tok in tokens + [";"]:
        if tok and set(tok) <= set(";&|()"):
            if seg:
                here, hit = segment(seg, here)
                found = found or hit
            seg = []
        else:
            seg.append(tok)
    return found

def segment(seg, here):
    # export GIT_DIR=... / declare -x ... / typeset -x ... / unset GIT_DIR は以降の文に効く
    if seg[0] in ("export", "declare", "typeset", "readonly", "local"):
        for a in seg[1:]:
            if ASSIGN.match(a):
                k, v = a.split("=", 1)
                shell_env[k] = v
        return here, False
    if seg[0] == "unset":
        for a in seg[1:]:
            shell_env.pop(a, None)
        return here, False
    env = dict(shell_env)
    # `env [-i] [-u NAME] K=V ... git ...` は env を読み飛ばす
    if seg[0] in ("env", "/usr/bin/env"):
        seg = seg[1:]
        while seg and seg[0].startswith("-"):
            if seg[0] in ("-u", "--unset") and len(seg) > 1:
                env.pop(seg[1], None); seg = seg[2:]
            else:
                seg = seg[1:]
    prefix = {}
    while seg and ASSIGN.match(seg[0]):   # 先頭の環境変数の代入
        k, v = seg[0].split("=", 1)
        prefix[k] = v
        seg = seg[1:]
    if not seg:
        # 代入だけの文（GIT_DIR=... ;）は以降の文に効く（export 済みの変数なら git にも渡る）
        shell_env.update(prefix)
        return here, False
    env.update(prefix)
    if seg[0] in ("cd", "pushd") and len(seg) > 1 and seg[1] != "-":
        return resolve(here, seg[1], env), False
    if os.path.basename(seg[0]) != "git":
        return here, False
    d, i = here, 1
    gd = resolve(here, env["GIT_DIR"], env) if "GIT_DIR" in env else ""
    if "GIT_WORK_TREE" in env:
        d = resolve(here, env["GIT_WORK_TREE"], env)
    while i < len(seg) and seg[i].startswith("-"):
        opt = seg[i]
        if opt in GIT_OPTS_WITH_ARG and i + 1 < len(seg):
            if opt == "-C":
                d = resolve(d, seg[i + 1], env)
            elif opt == "--work-tree":
                d = resolve(d, seg[i + 1], env)
            elif opt == "--git-dir":
                gd = resolve(d, seg[i + 1], env)
            i += 2
        else:
            if opt.startswith("--work-tree="):
                d = resolve(d, opt.split("=", 1)[1], env)
            elif opt.startswith("--git-dir="):
                gd = resolve(d, opt.split("=", 1)[1], env)
            i += 1
    if i >= len(seg):
        return here, False
    sub = seg[i]
    if sub == "commit":
        out.append("commit\t" + d + "\t" + (gd or "-"))
        return here, True
    if sub == "push":
        refs, remote = push_sources(seg[i + 1:])
        out.append("push\t" + d + "\t" + (gd or "-") + "\t" + (" ".join(refs) or "-") + "\t" + (remote or "-"))
        return here, True
    return here, False

try:
    found = parse(cmd)
except ValueError:
    found = False
# 解析で拾えなかったが commit / push らしき記述はある（bash -c "..." の中など）:
# 安全側に倒して、作業ディレクトリでの commit / push として検査する
# （`g=git; $g commit` のように git を変数経由で呼ぶ書き方も、文字が両方あればここで拾う）
if not found and re.search(r"\bgit\b", cmd):
    if re.search(r"\bcommit\b", cmd):
        out.append("commit\t" + cwd + "\t-")
    if re.search(r"\bpush\b", cmd):
        out.append("push\t" + cwd + "\t-\tHEAD\t-")
print("\n".join(dict.fromkeys(out)))
') || block "コマンドを解析できなかったため、念のため止めました。"
[ -z "$targets" ] && exit 0

find_gitleaks() {
  if command -v gitleaks >/dev/null 2>&1 \
     && [ "$(gitleaks version 2>/dev/null | sed 's/^v//')" = "$GITLEAKS_VERSION" ]; then
    echo gitleaks; return 0
  fi
  local os arch key cache bin tgz
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) return 1 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) return 1 ;; esac
  key="${os}_${arch}"
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/secret-guard/gitleaks-${GITLEAKS_VERSION}-${key}"
  bin="$cache/gitleaks"
  if [ ! -x "$bin" ]; then
    mkdir -p "$cache" || return 1
    tgz="$cache/gitleaks.tar.gz"
    curl -fsSL --connect-timeout 15 --max-time 60 -o "$tgz" \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${key}.tar.gz" || { rm -f "$tgz"; return 1; }
    if command -v sha256sum >/dev/null 2>&1; then
      echo "$(gitleaks_sha256 "$key")  $tgz" | sha256sum -c - >/dev/null || { rm -f "$tgz"; return 1; }
    else
      echo "$(gitleaks_sha256 "$key")  $tgz" | shasum -a 256 -c - >/dev/null || { rm -f "$tgz"; return 1; }
    fi
    tar -xzf "$tgz" -C "$cache" gitleaks && rm -f "$tgz" || return 1
  fi
  echo "$bin"
}

GL=""

# gitleaks を $dir で実行する。検出ありなら理由付きで止め、gitleaks 自体の失敗も止める（別の文言で）
run() {
  local dir=$1; shift
  local out rc
  out=$(cd "$dir" && "$GL" git --redact --verbose --no-banner --no-color --exit-code "$LEAK_EXIT" "$@" . 2>&1)
  rc=$?
  case "$rc" in
    0) ;;
    "$LEAK_EXIT")
      block "シークレットらしき値を検出したため止めました（${dir}）。値を取り除いてから実行し直してください（誤検知なら .gitleaks.toml に理由付きで除外を追加）。
$(printf '%s\n' "$out" | grep -E '^(RuleID|File|Line|Commit|Finding):|leaks found' | head -40)" ;;
    *)
      block "gitleaks の実行に失敗したため、念のため止めました（${dir}、終了コード ${rc}）。
$(printf '%s\n' "$out" | tail -20)" ;;
  esac
}

scan_dir() {
  local dir=$1 out rc
  out=$("$GL" dir --redact --verbose --no-banner --no-color --exit-code "$LEAK_EXIT" "$dir" 2>&1)
  rc=$?
  case "$rc" in
    0) ;;
    "$LEAK_EXIT")
      block "シークレットらしき値を検出したため止めました（${dir}）。値を取り除いてから実行し直してください（誤検知なら .gitleaks.toml に理由付きで除外を追加）。
$(printf '%s\n' "$out" | grep -E '^(RuleID|File|Line|Finding):|leaks found' | head -40)" ;;
    *)
      block "gitleaks の実行に失敗したため、念のため止めました（${dir}、終了コード ${rc}）。
$(printf '%s\n' "$out" | tail -20)" ;;
  esac
}

scan_commit() {
  local dir=$1 real
  # 未追跡のファイルも含めて「全部 add した状態」を一時インデックスに作り、それをステージ済みとして検査する
  real=$(cd "$dir" && git rev-parse --path-format=absolute --git-path index) || block "インデックスの場所を取得できませんでした（${dir}）。"
  tmp_index=$(mktemp "${TMPDIR:-/tmp}/secret-guard-index.XXXXXX") || block "一時ファイルを作れませんでした。"
  if [ -f "$real" ]; then cp "$real" "$tmp_index" || block "インデックスを複製できませんでした（${dir}）。"; else rm -f "$tmp_index"; fi
  (cd "$dir" && GIT_INDEX_FILE="$tmp_index" git add -A) >/dev/null 2>&1 || block "検査用のインデックスを作れませんでした（${dir}）。"
  GIT_INDEX_FILE="$tmp_index" run "$dir" --pre-commit --staged
  rm -f "$tmp_index"; tmp_index=""
}

scan_push() {
  local dir=$1 refs=$2 remote=$3 r ok="" not
  [ -n "$refs" ] || return 0   # ブランチの削除など、転送するコミットが無い
  # ref が解決できない（push 先で作る名前など）ものは除き、何も残らなければ HEAD を見る
  for r in $refs; do
    case "$r" in
      --*) ok="$ok $r" ;;
      *) (cd "$dir" && git rev-parse --verify -q "$r^{commit}") >/dev/null 2>&1 && ok="$ok $r" ;;
    esac
  done
  [ -z "$ok" ] && ok=" HEAD"
  # push 先が設定済みのリモート名なら、そのリモートにまだ無いコミットだけを見る。
  # 指定が無ければ、上流（なければ origin）。URL など特定できない宛先なら、push する全コミットを見る。
  if [ -z "$remote" ]; then
    remote=$(cd "$dir" && git rev-parse --abbrev-ref --symbolic-full-name '@{push}' 2>/dev/null | cut -d/ -f1)
    [ -n "$remote" ] || remote=origin
  fi
  if (cd "$dir" && git remote) 2>/dev/null | grep -Fxq -- "$remote"; then
    not="--not --remotes=$remote"
  else
    not=""
  fi
  # 「push する新規コミットが無い」と「rev-list 自体の失敗」を取り違えないよう、終了コードを見る
  local pending rc
  # shellcheck disable=SC2086
  pending=$(cd "$dir" && git rev-list $ok $not -n 1 2>&1)
  rc=$?
  [ "$rc" -eq 0 ] || block "push するコミットを特定できなかったため、念のため止めました（${dir}、git rev-list の終了コード ${rc}）。
$(printf '%s\n' "$pending" | tail -5)"
  if [ -n "$pending" ]; then
    # 末尾に空白が残ると gitleaks は 0 バイトしか検査せず「検出なし」になるので、空白を付けない
    local lo="${ok# }"
    [ -n "$not" ] && lo="$lo $not"
    run "$dir" --log-opts="$lo"
  fi
}

while IFS="$(printf '\t')" read -r kind dir gitdir refs remote; do
  [ -z "$kind" ] && continue
  # 空の欄は "-"（タブ区切りの空欄は read で詰められてしまうため）
  [ "$gitdir" = "-" ] && gitdir=""
  [ "$remote" = "-" ] && remote=""
  [ "$refs" = "-" ] && refs=""
  if [ "$kind" = unresolved ]; then
    block "コマンド中のパス（${dir}）が変数を含んでいて、どこを commit / push するのか決められないため止めました。パスを直接書いて実行し直してください。"
  fi
  # --git-dir / GIT_DIR の指定があれば、以降の git（gitleaks の中の git も）をそのリポジトリに向ける
  if [ -n "$gitdir" ]; then export GIT_DIR="$gitdir" GIT_WORK_TREE="$dir"; else unset GIT_DIR GIT_WORK_TREE; fi
  [ -n "$GL" ] || GL=$(find_gitleaks) || block "gitleaks を用意できなかったため、念のため止めました（シークレット検査ができない状態です）。"
  # まだ git リポジトリでない場所（同じコマンドの中で git init する場合など）は、push するものは無いが、
  # commit なら最初のコミットに入るファイルを、ディレクトリごと検査する
  if ! (cd "$dir" 2>/dev/null && git rev-parse --git-dir) >/dev/null 2>&1; then
    [ "$kind" = commit ] || continue
    [ -d "$dir" ] || block "commit する場所（${dir}）がまだ無く、検査できないため止めました。ディレクトリを作るコマンドと commit するコマンドを分けて実行してください。"
    scan_dir "$dir"
    continue
  fi
  case "$kind" in
    commit) scan_commit "$dir" ;;
    push)   scan_push "$dir" "$refs" "$remote" ;;
  esac
done <<EOF
$targets
EOF
exit 0
