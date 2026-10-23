#!/bin/bash
# Stop hook：非 VMP 混淆达到生产级之前不允许停下。
# 退出码 0 = 允许停止；退出码 2 = 阻止，stdout 的 reason 注入对话。
set -u
cd "$(dirname "$0")/../.." || exit 0

# 逃生口：换了机器 / 还没构建过时 .tmp 是空的，门禁项永远无法满足，
# 此时不该把会话锁死。显式创建 .tmp/.gate-off 或设 OBORO_GATE=off 即放行。
if [ "${OBORO_GATE:-on}" = "off" ] || [ -f .tmp/.gate-off ]; then
  echo '{"reason":"gate disabled by .tmp/.gate-off or OBORO_GATE=off"}'
  exit 0
fi

STATE=".tmp/.goal-state"
mkdir -p .tmp
COUNT=$(cat "$STATE" 2>/dev/null || echo 0)
COUNT=$((COUNT + 1))
echo "$COUNT" > "$STATE"

# 硬上限，避免无限循环烧 token。
if [ "$COUNT" -gt 60 ]; then
  echo '{"reason":"turn limit (60) reached; stopping"}'
  exit 0
fi

MISSING=""

# 1) 编译产物存在
if [ ! -f .tmp/bin/opt-current.exe ]; then
  MISSING="$MISSING compile"
fi

# 2) lit 全绿（数量不硬编码，但必须有通过且没有失败）
if ! grep -qE 'Passed: +[0-9]+' .tmp/last-lit.log 2>/dev/null; then
  MISSING="$MISSING lit"
elif grep -qE 'Failed: +[1-9]' .tmp/last-lit.log 2>/dev/null; then
  MISSING="$MISSING lit-fail"
fi

# 3) 语义矩阵 0 失败
if ! grep -q 'sem_fail=0' .tmp/last-semantic.log 2>/dev/null; then
  MISSING="$MISSING semantic"
fi

# 4) 真实项目往返一致
if ! grep -q 'realworld_ok=1' .tmp/last-realworld.log 2>/dev/null; then
  MISSING="$MISSING realworld"
fi

# 5) 每个 pass 必须真的改变 IR（防止静默空转）
if ! grep -q 'smoke_fail=0' .tmp/last-smoke.log 2>/dev/null; then
  MISSING="$MISSING smoke"
fi

# 6) 文档与 CLI 一致：文档里不能残留已删除的选项名
if grep -qE 'irobf-bcf_prob|level-indbr|irobf-fwrap|irobf-indbr-dual|irobf-probe-symbol' USAGE.md USAGE_en.md README.md README.zh-CN.md 2>/dev/null; then
  MISSING="$MISSING docs-stale"
fi

if [ -z "$MISSING" ]; then
  echo '{"reason":"all gates green"}'
  exit 0
fi

echo "{\"reason\":\"未完成:${MISSING}。继续推进：编译 -> lit -> 语义矩阵 -> 真实项目 -> 修文档。轮次 ${COUNT}/60。\"}"
exit 2
