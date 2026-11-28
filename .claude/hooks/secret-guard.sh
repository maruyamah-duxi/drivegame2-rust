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
#       git のエイリアス（git config alias.ci commit で `git ci` など）や、別名でコピーした git の
#       実行ファイル（cp /usr/bin/git /tmp/vcs など）も追えない（最後の砦は CI の security.yml）。
# また、フックと検査設定（.claude/settings.json、.claude/hooks/、.gitleaks.toml、.gitleaksignore）を
# Bash で書き換える・消すコマンドは、確認を求める（settings.json の ask は Edit ツールにしか効かないため）。
# 除外は .gitleaks.toml / .gitleaksignore（security.yml と共通）。
#
# gitleaks は版を固定する。PATH にあっても版が違えば使わず、版と SHA-256 を固定した公式バイナリを
# 取得してキャッシュする（版は .github/workflows/security.yml の GITLEAKS_VERSION と揃える。更新時は両方）。
# 検査できない状態（取得失敗、gitleaks のエラー、コマンドを解析できないなど）では、安全側に倒してコマンドを止める。
# フック自体がタイムアウトすると Claude Code はコマンドを通してしまうので、取得と検査の全体に
# フックのタイムアウト（settings.json の 120 秒）より短い期限（100 秒）を付け、超えたら止める。
set -uo pipefail
DEADLINE=$((SECONDS + 100))

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
tmp_out=""
tmp_cmd=""
on_exit() {
  local rc=$?
  [ -n "$tmp_index" ] && rm -f "$tmp_index"
  [ -n "$tmp_out" ] && rm -f "$tmp_out"
  [ -n "$tmp_cmd" ] && rm -f "$tmp_cmd"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    echo "secret-guard: フックが異常終了（終了コード ${rc}）したため、念のため止めました。" >&2
    exit 2
  fi
}
trap on_exit EXIT

input=$(cat) || block "フックへの入力を読み取れなかったため、念のため止めました。"

# 通す。フックや検査設定を書き換えうるコマンドなら、通す代わりに確認を求める（検査で止める場合は block が優先）
ASK=""
allow() {
  if [ -n "$ASK" ]; then
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"secret-guard: フックまたはシークレット検査の設定（.claude/settings.json、.claude/hooks/、.gitleaks.toml、.gitleaksignore）を書き換える・消す可能性があるコマンドです。内容を確認してから許可してください。"}}'
  fi
  exit 0
}
if printf '%s' "$input" | grep -Eq '\.claude/(settings(\.local)?\.json|hooks)|\.gitleaks(\.toml|ignore)'; then
  # 読むだけのコマンド（cat / grep / git diff など）は確認しない。書き込み・削除・実行系の語や、
  # /dev/null と 2>&1 以外のリダイレクトがあれば確認を求める
  w=$(printf '%s' "$input" | sed -E 's/[0-9]*>[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9]//g')
  if printf '%s' "$w" | grep -Eq '>|(^|[^A-Za-z0-9_.-])(rm|mv|cp|tee|truncate|ln|chmod|chown|install|dd|unlink|rsync|python3?|perl|ruby|node|sh|bash|zsh|ed|ex|vi|vim|nano)([^A-Za-z0-9_.-]|$)|sed[^|;&]*[[:space:]](-[A-Za-z]*i|--in-place)|git[^|;&]*[[:space:]](rm|mv|checkout|restore|reset|apply|stash|clean|switch)([^A-Za-z0-9_.-]|$)'; then
    ASK=1
  fi
fi

# 手早く絞る: git と commit / push の両方を含まないコマンドは対象外
printf '%s' "$input" | grep -Eq 'git' && printf '%s' "$input" | grep -Eq '(commit|push)' || allow

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
    vals.update(shell_vars)
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

# git の向き先を変える環境変数。コマンドの前の文で export されたものは、後の git に効くので追う。
# export していない代入（GIT_DIR=x だけの文、-x の無い declare など）は、その変数が既に export
# されていれば git に効き、されていなければ効かない。フックからはどちらか確かめられないので、
# 両方の場所を検査する（maybe_env）。$VAR の展開には export の有無に関係なく使う（shell_vars）
GIT_ENV_KEYS = ("GIT_DIR", "GIT_WORK_TREE")
shell_env = {k: os.environ[k] for k in GIT_ENV_KEYS if os.environ.get(k)}
shell_vars, maybe_env = {}, {}

def assign(k, v, exported):
    shell_vars[k] = v
    if k not in GIT_ENV_KEYS:
        return
    if exported or k in shell_env:   # export 済みの変数への代入は、そのまま git に効く
        shell_env[k] = v
        maybe_env.pop(k, None)
    else:
        maybe_env[k] = v
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

def heredoc_words(line, arith=0):
    """行の中で本当に始まっているヒアドキュメントの終端語を返す（正規表現では判定しない）。
    shlex で字句に分けるので、引用符の中や # コメントの `<<WORD` はヒアドキュメント扱いしない。
    行だけでは字句に分けられない（引用符が次の行へ続くなど）ときは、ヒアドキュメント無しとみなす
    （本文を除かないだけなので、検査が漏れる側には倒れない）"""
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        toks = list(lex)
    except ValueError:
        return [], arith
    words = []
    for k, t in enumerate(toks):
        # $(( … )) / (( … )) の中の << は算術の左シフトで、ヒアドキュメントではない
        arith += t.count("((") - t.count("))")
        if t == "<<" and k + 1 < len(toks) and arith <= 0:   # <<< はヒアストリングで別の字句になる
            w = toks[k + 1]
            dash = w.startswith("-")
            w = w[1:] if dash else w
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", w or ""):
                words.append((dash, w))
    return words, arith

def strip_heredocs(text):
    """ヒアドキュメント（<<EOF … EOF）の本文を除く。本文はコマンドではないので、
    コミットメッセージ中の `cd …` や `git push` を文として解釈しないようにする"""
    out, pending, arith = [], [], 0
    for line in text.split("\n"):
        if pending:
            dash, word = pending[0]
            if (line.lstrip("\t") if dash else line) == word:
                pending.pop(0)
            continue
        out.append(line)
        # $(( … )) が複数行にまたがっても、中の << をヒアドキュメントと取り違えないよう、深さは行をまたいで数える
        pending, arith = heredoc_words(line, arith)
    if pending:
        # 終端語が最後まで現れない（本当はヒアドキュメントではなかった疑い）: 除いた行も検査の保険に回す
        unterminated.append(text)
    return "\n".join(out)

found = {"commit": False, "push": False}
seen = []   # 検査対象にできなかった文の字句（ヒアドキュメント本文と # コメントは除く）
unterminated = []
cdhist = []
GITWORD = re.compile(r"\bgit\b")
KINDS = re.compile(r"\b(commit|push)\b")

def parse(text, start=None):
    # 改行は文の区切り。改行そのものも残す（# コメントは改行で終わるので、消すと後ろの行まで
    # コメント扱いになり、`# メモ` の次の行の cd / git commit を見落とす）
    lex = shlex.shlex(strip_heredocs(text).replace("\n", " ;\n"), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    tokens = list(lex)
    here, seg, stack = (start or cwd), [], []
    for tok in tokens + [";"]:
        if tok and set(tok) <= set(";&|()"):
            if seg:
                n = len(out)
                here = segment(seg, here)
                # 検査対象にできた文（git commit / push）の引数（コミットメッセージなど）は、保険の判定に使わない
                if len(out) == n:
                    seen.extend(seg)
            seg = []
            # ( … ) はサブシェル。中の cd は外に効かないので、閉じたら元の場所に戻す
            for ch in tok:
                if ch == "(":
                    stack.append(here)
                elif ch == ")" and stack:
                    here = stack.pop()
        else:
            seg.append(tok)

def segment(seg, here):
    # export GIT_DIR=... / declare -x ... / typeset -x ... / unset GIT_DIR は以降の文に効く
    # if / while / { などの予約語は読み飛ばす（{ cd x; } の cd は実際に効く）
    while seg and seg[0] in ("{", "}", "!", "if", "then", "else", "elif", "fi", "while", "until", "do", "done", "time"):
        seg = seg[1:]
    if not seg:
        return here
    if seg[0] in ("export", "declare", "typeset", "readonly", "local"):
        exported = seg[0] == "export" or any(a.startswith("-") and "x" in a for a in seg[1:])
        for a in seg[1:]:
            if ASSIGN.match(a):
                k, v = a.split("=", 1)
                assign(k, v, exported)
            elif exported and a in GIT_ENV_KEYS and a in maybe_env:   # export GIT_DIR（値は前の代入）
                shell_env[a] = maybe_env.pop(a)
        return here
    if seg[0] == "unset":
        for a in seg[1:]:
            shell_env.pop(a, None); maybe_env.pop(a, None); shell_vars.pop(a, None)
        return here
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
        for k, v in prefix.items():
            assign(k, v, False)
        return here
    env.update(prefix)
    if seg[0] in ("cd", "pushd"):
        args = [a for a in seg[1:] if a not in ("-L", "-P", "-e", "-@")]
        if not args:
            return resolve(here, "~", env)                  # 引数なしの cd はホームへ
        if args[0] == "-":
            prev = cdhist[-1] if cdhist else here           # cd - は直前の場所へ
            cdhist.append(here)
            return prev
        cdhist.append(here)
        return resolve(here, args[0], env)
    # bash -c "…" / sh -c "…" は、中のコマンドをその場所から解析する
    if os.path.basename(seg[0]) in ("bash", "sh", "zsh", "dash") and "-c" in seg[1:-1]:
        parse(seg[seg.index("-c", 1) + 1], here)
        return here
    if os.path.basename(seg[0]) != "git":
        # git 以外の文の中の git commit / push（bash -c "git push"、$g push など）は、
        # 他の文で git を解析できていても見逃さないよう、この場所での commit / push として検査する
        text = " ".join(seg)
        if GITWORD.search(text) or seg[0].startswith("$"):
            for kind in dict.fromkeys(KINDS.findall(text)):
                out.append("commit\t" + here + "\t-" if kind == "commit" else "push\t" + here + "\t-\t--branches\t-")
                found[kind] = True
        return here
    # git は先に -C で移動してから、--git-dir / --work-tree と GIT_DIR / GIT_WORK_TREE の
    # 相対パスをその場所から解釈する
    c, i, gd_opt, wt_opt = here, 1, None, None
    while i < len(seg) and seg[i].startswith("-"):
        opt = seg[i]
        if opt in GIT_OPTS_WITH_ARG and i + 1 < len(seg):
            if opt == "-C":
                c = resolve(c, seg[i + 1], env)
            elif opt == "--work-tree":
                wt_opt = seg[i + 1]
            elif opt == "--git-dir":
                gd_opt = seg[i + 1]
            i += 2
        else:
            if opt.startswith("--work-tree="):
                wt_opt = opt.split("=", 1)[1]
            elif opt.startswith("--git-dir="):
                gd_opt = opt.split("=", 1)[1]
            i += 1
    gd_opt_given, wt_opt_given = gd_opt is not None, wt_opt is not None
    if gd_opt is None:
        gd_opt = env.get("GIT_DIR")
    if wt_opt is None:
        wt_opt = env.get("GIT_WORK_TREE")
    gd = resolve(c, gd_opt, env) if gd_opt else ""
    d = resolve(c, wt_opt, env) if wt_opt else c
    if i >= len(seg):
        return here
    sub = seg[i]
    if sub == "add":
        # git add -f / --force は .gitignore に一致するファイルも足す。フックの時点ではまだ実行前なので、
        # 検査用の一時インデックスにも同じファイルを -f で足す（.env を -f で取り込むのを見逃さない）
        args = seg[i + 1:]
        if any(a in ("-f", "--force") or (a.startswith("-") and not a.startswith("--") and "f" in a) for a in args):
            paths, opts_done = [], False
            for a in args:
                if a == "--":
                    opts_done = True
                elif opts_done or not a.startswith("-"):
                    paths.append(a)
            out.append("forceadd\t" + d + "\t" + (gd or "-") + "\t" + "\x1f".join(paths or ["."]))
        return here
    if sub not in ("commit", "push"):
        return here
    places = [(d, gd)]
    # export されたか分からない GIT_DIR / GIT_WORK_TREE の代入があれば、効いた場合の場所も検査する
    # （GIT_DIR と GIT_WORK_TREE は別々に判断する。片方をコマンドラインで指定していても、もう片方は曖昧なまま）
    gd_maybe = "GIT_DIR" in maybe_env and not gd_opt_given and "GIT_DIR" not in prefix
    wt_maybe = "GIT_WORK_TREE" in maybe_env and not wt_opt_given and "GIT_WORK_TREE" not in prefix
    if gd_maybe or wt_maybe:
        e2 = dict(env)
        if gd_maybe: e2["GIT_DIR"] = maybe_env["GIT_DIR"]
        if wt_maybe: e2["GIT_WORK_TREE"] = maybe_env["GIT_WORK_TREE"]
        g2 = gd if gd_opt_given else (resolve(c, e2["GIT_DIR"], e2) if e2.get("GIT_DIR") else "")
        d2 = d if wt_opt_given else (resolve(c, e2["GIT_WORK_TREE"], e2) if e2.get("GIT_WORK_TREE") else c)
        if (d2, g2) != (d, gd):
            places.append((d2, g2))
    for pd, pg in places:
        if sub == "commit":
            out.append("commit\t" + pd + "\t" + (pg or "-"))
        else:
            refs, remote = push_sources(seg[i + 1:])
            out.append("push\t" + pd + "\t" + (pg or "-") + "\t" + (" ".join(refs) or "-") + "\t" + (remote or "-"))
    found[sub] = True
    return here

try:
    parse(cmd)
    rest = " ".join(seen + unterminated)
except ValueError:
    rest = cmd   # 字句に分けられない: 生のコマンド全体で判断する
# コマンド置換（$( … ) / `…`）の中の git commit / push は、どこで何を対象に実行されるかを
# 決められない（無引用のヒアドキュメント本文の中の置換も、実際に実行される）ので止める
SUBST = re.compile(r"\$\([^()]*\bgit\b[^()]*\b(?:commit|push)\b[^()]*\)|`[^`]*\bgit\b[^`]*\b(?:commit|push)\b[^`]*`")
# 引用付きのヒアドキュメント（<<\x27EOF\x27 / <<"EOF" / <<\\EOF）の本文は $( … ) が展開されないので見ない
# （git commit -m "$(cat <<\x27EOF\x27 … git push の説明 … EOF)" のようなコミットメッセージで止めない）
def strip_quoted_heredocs(text):
    res, word = [], None
    for line in text.split("\n"):
        if word is not None:
            if line.strip("\t") == word:
                word = None
            continue
        res.append(line)
        # <<\x27EOF\x27 / <<"EOF" / <<\\EOF はどれも本文を展開しない
        m = re.search(r"<<-?\s*(?:([\x27\"])([A-Za-z_][A-Za-z0-9_]*)\1|\\([A-Za-z_][A-Za-z0-9_]*))", line)
        if m:
            word = m.group(2) or m.group(3)
    return "\n".join(res)
if SUBST.search(strip_quoted_heredocs(cmd)):
    out.append("subst\t-")
# 解析で拾えなかったが commit / push らしき記述はある（解析の失敗、変数経由の git など）:
# 安全側に倒して、拾えなかった種類ごとに作業ディレクトリでの commit / push として検査する
# （どのブランチを push するか分からないので、push はまだ送っていない全ブランチのコミットを見る）
# （commit を解析できていても、push を拾えていなければ push も検査する）
# ヒアドキュメント本文と # コメントの中の文字は見ない（コミットメッセージ中の「git push」で誤って止めない）
if GITWORD.search(rest):
    if not found["commit"] and re.search(r"\bcommit\b", rest):
        out.append("commit\t" + cwd + "\t-")
    if not found["push"] and re.search(r"\bpush\b", rest):
        out.append("push\t" + cwd + "\t-\t--branches\t-")
print("\n".join(dict.fromkeys(out)))
') || block "コマンドを解析できなかったため、念のため止めました。"
[ -z "$targets" ] && allow

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
    # 同時に複数のフックが取得しても壊れないよう、プロセスごとの一時ディレクトリに取得・展開してから置き換える
    local dl
    dl=$(mktemp -d "$cache/dl.XXXXXX") || return 1
    tgz="$dl/gitleaks.tar.gz"
    local left=$((DEADLINE - SECONDS - 10))
    [ "$left" -gt 60 ] && left=60
    [ "$left" -gt 0 ] || return 1
    curl -fsSL --connect-timeout 15 --max-time "$left" -o "$tgz" \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${key}.tar.gz" || { rm -rf "$dl"; return 1; }
    if command -v sha256sum >/dev/null 2>&1; then
      echo "$(gitleaks_sha256 "$key")  $tgz" | sha256sum -c - >/dev/null || { rm -rf "$dl"; return 1; }
    else
      echo "$(gitleaks_sha256 "$key")  $tgz" | shasum -a 256 -c - >/dev/null || { rm -rf "$dl"; return 1; }
    fi
    tar -xzf "$tgz" -C "$dl" gitleaks && mv -f "$dl/gitleaks" "$bin" || { rm -rf "$dl"; return 1; }
    rm -rf "$dl"
  fi
  echo "$bin"
}

GL=""
# 除外設定（.gitleaks.toml / .gitleaksignore）は、検査する場所のリポジトリのルートから読む
# （gitleaks は検査対象のディレクトリしか探さないので、サブディレクトリで commit すると読まれない）
gl_cfg() {
  GLCFG=()
  local root
  root=$(cd "$1" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null) || root=$1
  [ -n "$root" ] || root=$1
  [ -f "$root/.gitleaks.toml" ] && GLCFG+=(--config "$root/.gitleaks.toml")
  [ -f "$root/.gitleaksignore" ] && GLCFG+=(--gitleaks-ignore-path "$root/.gitleaksignore")
  return 0
}
tmp_out=$(mktemp "${TMPDIR:-/tmp}/secret-guard-out.XXXXXX") || block "一時ファイルを作れませんでした。"

# 期限までの残り秒数で "$@" を実行する（macOS には timeout コマンドが無いので自前で見張る）。
# 期限を過ぎて打ち切ったら 124 を返す
deadline_run() {
  local left=$((DEADLINE - SECONDS)) pid w rc
  [ "$left" -gt 0 ] || return 124
  # 標準入力を渡すときは DR_IN にファイルを指定する（& で起動すると標準入力は /dev/null になるため）
  if [ -n "${DR_IN:-}" ]; then "$@" <"$DR_IN" & else "$@" & fi
  pid=$!
  # 見張りの出力は捨てる（$( … ) の中で呼ぶので、開いたままだと sleep の終わりまで待たされる）
  # 先に終わったら見張りを止める。見張りの中の sleep も一緒に止める（残すと最大 100 秒残る）
  ( sleep "$left" & s=$!
    trap 'kill "$s" 2>/dev/null; exit 0' TERM
    wait "$s"
    kill -TERM "$pid" 2>/dev/null; sleep 2; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  w=$!
  wait "$pid"; rc=$?
  kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  [ "$((DEADLINE - SECONDS))" -le 0 ] && [ "$rc" -ne 0 ] && [ "$rc" -ne "$LEAK_EXIT" ] && return 124
  return "$rc"
}

too_slow() {
  block "シークレット検査がフックの制限時間内に終わらなかったため、念のため止めました（${1}）。push するコミットを分ける、または手元で gitleaks を実行して確認してください。"
}

# gitleaks を $dir で実行する。検出ありなら理由付きで止め、gitleaks 自体の失敗も止める（別の文言で）
run() {
  local dir=$1; shift
  local out rc
  # 出力は $( … ) ではなくファイルで受ける（打ち切った gitleaks の子プロセスが出力を開いたままだと、
  # $( … ) はそれが終わるまで戻らず、期限が効かなくなる）
  gl_cfg "$dir"
  (cd "$dir" && deadline_run "$GL" git "${GLCFG[@]+"${GLCFG[@]}"}" --redact --verbose --no-banner --no-color --exit-code "$LEAK_EXIT" "$@" .) >"$tmp_out" 2>&1
  rc=$?
  out=$(cat "$tmp_out")
  [ "$rc" -eq 124 ] && too_slow "$dir"
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
  gl_cfg "$dir"
  deadline_run "$GL" dir "${GLCFG[@]+"${GLCFG[@]}"}" --redact --verbose --no-banner --no-color --exit-code "$LEAK_EXIT" "$dir" >"$tmp_out" 2>&1
  rc=$?
  out=$(cat "$tmp_out")
  [ "$rc" -eq 124 ] && too_slow "$dir"
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
  # 同じコマンドの git add -f で足されるファイル（.gitignore に一致するものも）を一時インデックスに足す
  local k d g p
  while IFS="$(printf '\t')" read -r k d g p; do
    [ "$k" = forceadd ] && [ "$d" = "$dir" ] || continue
    local IFS_SAVE=$IFS; IFS="$(printf '\037')"
    # shellcheck disable=SC2086
    set -- $p
    IFS=$IFS_SAVE
    (cd "$dir" && GIT_INDEX_FILE="$tmp_index" git add -f -- "$@") >/dev/null 2>&1 \
      || block "git add -f で足すファイル（$*）を検査用のインデックスに載せられなかったため、念のため止めました（${dir}）。"
  done <<FA
$targets
FA
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
  if [ "$kind" = subst ]; then
    block "コマンド置換（\$( … ) や \`…\`）の中に git commit / push があり、検査先を決められないため止めました。置換の外に出して実行し直してください。"
  fi
  [ "$kind" = forceadd ] && continue   # commit の検査のときに使う
  if [ "$kind" = unresolved ]; then
    block "コマンド中のパス（${dir}）が変数を含んでいて、どこを commit / push するのか決められないため止めました。パスを直接書いて実行し直してください。"
  fi
  # --git-dir / GIT_DIR の指定があれば、以降の git（gitleaks の中の git も）をそのリポジトリに向ける
  if [ -n "$gitdir" ]; then export GIT_DIR="$gitdir" GIT_WORK_TREE="$dir"; else unset GIT_DIR GIT_WORK_TREE; fi
  [ -n "$GL" ] || GL=$(find_gitleaks) || block "gitleaks を用意できなかったため、念のため止めました（シークレット検査ができない状態です）。"
  # まだ git リポジトリでない場所（同じコマンドの中で git init する場合など）は、push するものは無いが、
  # commit なら最初のコミットに入るファイルを、ディレクトリごと検査する
  if ! (cd "$dir" 2>/dev/null && git rev-parse --git-dir) >/dev/null 2>&1; then
    # push するのにリポジトリでない（存在しない場所への cd など）: 実際の bash では cd が失敗して
    # 別の場所で push されうるので、検査を飛ばさず止める
    [ "$kind" = commit ] || block "push する場所（${dir}）が git リポジトリと確認できないため止めました。リポジトリのディレクトリで実行し直してください。"
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

# commit するなら、コマンドの文字列そのもの（-m のコミットメッセージ、ヒアドキュメントの本文など）も検査する。
# ファイルの検査ではコミットメッセージは見えないため
if printf '%s\n' "$targets" | grep -q '^commit'; then
  [ -n "$GL" ] || GL=$(find_gitleaks) || block "gitleaks を用意できなかったため、念のため止めました（シークレット検査ができない状態です）。"
  tmp_cmd=$(mktemp "${TMPDIR:-/tmp}/secret-guard-cmd.XXXXXX") || block "一時ファイルを作れませんでした。"
  printf '%s' "$input" | python3 -c 'import json,sys; sys.stdout.write((json.load(sys.stdin).get("tool_input") or {}).get("command") or "")' >"$tmp_cmd" \
    || block "コマンドを取り出せなかったため、念のため止めました。"
  gl_cfg "${CLAUDE_PROJECT_DIR:-$PWD}"
  DR_IN="$tmp_cmd" deadline_run "$GL" stdin "${GLCFG[@]+"${GLCFG[@]}"}" --redact --verbose --no-banner --no-color --exit-code "$LEAK_EXIT" >"$tmp_out" 2>&1
  rc=$?
  [ "$rc" -eq 124 ] && too_slow "コマンドの文字列"
  case "$rc" in
    0) ;;
    "$LEAK_EXIT")
      block "コマンドの文字列（コミットメッセージなど）にシークレットらしき値があるため止めました。値を取り除いてから実行し直してください。
$(grep -E '^(RuleID|Line|Finding):|leaks found' "$tmp_out" | head -20)" ;;
    *)
      block "gitleaks の実行に失敗したため、念のため止めました（コマンドの文字列、終了コード ${rc}）。
$(tail -20 "$tmp_out")" ;;
  esac
fi
allow
