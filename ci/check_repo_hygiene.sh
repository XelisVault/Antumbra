#!/usr/bin/env bash
# ANTUMBRA repository hygiene gate.
#
# The mechanical floor under the zero-defect method: no conflict
# markers, no trailing whitespace, a final newline in every text
# file, valid UTF-8 everywhere, parseable shell, parseable Python,
# parseable YAML. None of these catch a consensus fault by
# themselves; all of them catch the review-destroying noise that
# hides one. Runs in CI ("Repository hygiene") and locally:
#   bash ci/check_repo_hygiene.sh
# Exit code 0 is the only acceptable outcome.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

fail=0
checked=0
err() {
  printf 'HYGIENE FAIL: %s\n' "$1" >&2
  fail=1
}

# ── tracked files ────────────────────────────────────────────────
mapfile -t all_files < <(git ls-files)

# Extensions treated as text. Everything else (pdf, png, ico, the
# Cargo.lock) is left alone: binary or churn-only.
is_text() {
  case "$1" in
    *.rs|*.py|*.toml|*.yml|*.yaml|*.sh|*.tex|*.md|*.json|*.txt|*.css|*.html|*.js|*.ts|*.mjs)
      return 0 ;;
    *)
      return 1 ;;
  esac
}

# ── per-file checks ──────────────────────────────────────────────
for f in "${all_files[@]}"; do
  is_text "$f" || continue
  checked=$((checked + 1))

  # 1. conflict markers — a file merged with conflicts left in it
  if grep -qE '^(<{7} |>{7} )' "$f"; then
    err "conflict markers in $f"
  fi

  # 2. trailing whitespace (markdown hard line breaks are exempt)
  case "$f" in
    *.md) ;;
    *)
      if grep -qE '[[:blank:]]+$' "$f"; then
        err "trailing whitespace in $f"
      fi
      ;;
  esac

  # 3. final newline
  if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then
    err "missing final newline in $f"
  fi

  # 4. UTF-8 validity
  if ! iconv -f UTF-8 -t UTF-8 "$f" >/dev/null 2>&1; then
    err "not valid UTF-8: $f"
  fi
done

# ── shell syntax ─────────────────────────────────────────────────
for f in "${all_files[@]}"; do
  case "$f" in
    *.sh)
      bash -n "$f" || err "bash syntax error in $f"
      ;;
  esac
done

# ── shellcheck, when available (GitHub runners ship it) ──────────
if command -v shellcheck >/dev/null 2>&1; then
  for f in "${all_files[@]}"; do
    case "$f" in
      *.sh)
        shellcheck "$f" || err "shellcheck findings in $f"
        ;;
    esac
  done
fi

# ── python syntax ────────────────────────────────────────────────
python3 -m compileall -q code simulations docs 2>/dev/null || true
py_failed=0
for f in "${all_files[@]}"; do
  case "$f" in
    *.py)
      python3 -m py_compile "$f" || py_failed=1
      ;;
  esac
done
[ "$py_failed" -eq 0 ] || err "python syntax errors (see py_compile above)"

# ── YAML sanity (workflows, dependabot) ──────────────────────────
python3 - <<'PYEOF'
import glob
import sys

try:
    import yaml
except ImportError:
    print("yaml check: pyyaml not installed, skipped")
    sys.exit(0)

targets = (
    glob.glob(".github/workflows/*.yml")
    + glob.glob(".github/workflows/*.yaml")
    + glob.glob(".github/*.yml")
    + glob.glob("ci/*.yml")
    + glob.glob("ci/*.yaml")
)
if not targets:
    print("yaml check: no yaml files found (unexpected)")
    sys.exit(1)
for path in targets:
    with open(path, encoding="utf-8") as handle:
        yaml.safe_load(handle)
print(f"yaml check: {len(targets)} files parse")
PYEOF

if [ "$fail" -ne 0 ]; then
  printf 'HYGIENE: FAILED (%s text files checked)\n' "$checked" >&2
  exit 1
fi

printf 'HYGIENE: OK (%s text files checked)\n' "$checked"
