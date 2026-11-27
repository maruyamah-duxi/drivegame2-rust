#!/usr/bin/env bash
# Claude Code の PreToolUse フック（.claude/settings.json から呼ばれる）。
#
# Claude が `git commit` / `git push` を実行する直前に gitleaks でシークレット混入を検査し、
# 見つかればコマンドを止める（exit 2。理由は Claude に返る）。GHAS の push protection の代わり。
#   * commit 前: 作業ツリーとステージ済みの差分
#   * push 前  : まだどのリモートにも無いコミット（全ローカルブランチ）
# 除外は .gitleaks.toml / .gitleaksignore（security.yml と共通）。
#
# gitleaks が PATH に無ければ、版と SHA-256 を固定した公式バイナリを取得してキャッシュする
# （版は .github/workflows/security.yml の GITLEAKS_VERSION と揃える。更新時は両方）。
# 検査できない状態（取得失敗など）では、安全側に倒してコマンドを止める。
set -uo pipefail

GITLEAKS_VERSION=8.30.1
# macOS 標準の bash 3.2 でも動くよう、連想配列は使わない
gitleaks_sha256() {
  case "$1" in
    linux_x64)    echo 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
    linux_arm64)  echo e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
    darwin_x64)   echo dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709 ;;
    darwin_arm64) echo b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
  esac
}

input=$(cat)

# git commit / git push を含むコマンドだけを対象にする（git -C dir / git -c k=v も拾う）
want=""
if printf '%s' "$input" | grep -Eq 'git( +-[Cc] +[^ ]+)* +commit([^-a-z]|$)'; then want="commit"; fi
if printf '%s' "$input" | grep -Eq 'git( +-[Cc] +[^ ]+)* +push([^-a-z]|$)'; then want="$want push"; fi
[ -z "$want" ] && exit 0

block() { echo "secret-guard: $*" >&2; exit 2; }

repo="${CLAUDE_PROJECT_DIR:-$PWD}"
cd "$repo" 2>/dev/null && git rev-parse --git-dir >/dev/null 2>&1 || exit 0

find_gitleaks() {
  if command -v gitleaks >/dev/null 2>&1; then echo gitleaks; return 0; fi
  local os arch key cache bin tgz
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) return 1 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) return 1 ;; esac
  key="${os}_${arch}"
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/secret-guard/gitleaks-${GITLEAKS_VERSION}-${key}"
  bin="$cache/gitleaks"
  if [ ! -x "$bin" ]; then
    mkdir -p "$cache" || return 1
    tgz="$cache/gitleaks.tar.gz"
    curl -fsSLo "$tgz" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${key}.tar.gz" || return 1
    if command -v sha256sum >/dev/null 2>&1; then
      echo "$(gitleaks_sha256 "$key")  $tgz" | sha256sum -c - >/dev/null || { rm -f "$tgz"; return 1; }
    else
      echo "$(gitleaks_sha256 "$key")  $tgz" | shasum -a 256 -c - >/dev/null || { rm -f "$tgz"; return 1; }
    fi
    tar -xzf "$tgz" -C "$cache" gitleaks && rm -f "$tgz" || return 1
  fi
  echo "$bin"
}

GL=$(find_gitleaks) || block "gitleaks を用意できなかったため、念のため止めました（シークレット検査ができない状態です）。"

run() {
  local out
  if ! out=$("$GL" git --redact --verbose --no-banner --no-color "$@" . 2>&1); then
    block "シークレットらしき値を検出したため止めました。値を取り除いてから実行し直してください（誤検知なら .gitleaks.toml に理由付きで除外を追加）。
$(printf '%s\n' "$out" | grep -E '^(RuleID|File|Line|Commit|Finding):|leaks found' | head -40)"
  fi
}

case "$want" in
  *commit*)
    run --pre-commit
    run --pre-commit --staged
    ;;
esac
case "$want" in
  *push*)
    # まだどのリモートにも無いコミットを検査する
    if [ -n "$(git rev-list --branches --not --remotes -n 1 2>/dev/null)" ]; then
      run --log-opts="--branches --not --remotes"
    fi
    ;;
esac
exit 0
