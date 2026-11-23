#!/bin/bash
# freshlens GitHub 发布脚本（token 存钥匙串 GH_TOKEN）
set -e
REPO="freshlens"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
TOKEN=$(security find-generic-password -s GH_TOKEN -a tomlen045 -w 2>/dev/null) || { echo "NO GH_TOKEN IN KEYCHAIN"; exit 1; }

# 建仓（存在则 422 跳过）
code=$(curl -s -o /tmp/fl_gh_create.json -w '%{http_code}' -X POST https://api.github.com/user/repos \
  -H "Authorization: token $TOKEN" -H "Accept: application/vnd.github+json" \
  -d "{\"name\":\"$REPO\",\"description\":\"freshlens - baseline-free file anomaly lens (zero-dep, single-file, 12 verdicts)\",\"private\":false}")
echo "create: $code"

git branch -M main 2>/dev/null || true
git remote remove gh-origin 2>/dev/null || true
git remote add gh-origin "https://tomlen045:$TOKEN@github.com/tomlen045/$REPO.git"
GIT_TERMINAL_PROMPT=0 git push -q -u gh-origin main
echo "pushed (main)"

echo "--- anonymous readback ---"
echo "api: $(curl -s -o /dev/null -w '%{http_code}' -m 15 https://api.github.com/repos/tomlen045/$REPO)"
echo "raw: $(curl -s -o /dev/null -w '%{http_code}' -L -m 15 https://raw.githubusercontent.com/tomlen045/$REPO/main/README.md)"
SHA=$(git rev-parse HEAD)
echo "sha: $SHA"
echo "cdn: $(curl -s -o /dev/null -w '%{http_code}' -L -m 20 https://gcore.jsdelivr.net/gh/tomlen045/freshlens@$SHA/freshlens.py)"
