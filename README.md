# freshlens · 无基线文件异动透镜

**这台机器上，最近有哪些文件被动了？它们长得像不像不速之客？**

不装aide、不建可信基线库、不做全盘哈希——freshlens 只靠
「时间窗 × 文件形态」一次扫描给出 12 类判决，
帮你回答一个应急响应时最先要问的问题：**最近被动过的文件里，哪些不像好东西。**

[English](README_EN.md) | 简体中文

```
$ python3 freshlens.py --demo
[demo] 沙箱已建: /tmp/freshlens-demo（3 处植入 + 2 个正常老文件）
freshlens v1.0.1 · 无基线文件异动透镜
时间窗: 24h · 扫描根: 1 个 · 条目: 11
------------------------------------------------------------------------
[P0 FJ-01]  /tmp/freshlens-demo/tmpd/kworker
        临时目录新落地可执行文件（2.0小时前出现）
[P0 FJ-02]  /tmp/freshlens-demo/tmpd/sshd
        可执行文件伪装系统服务名「sshd」却不在系统目录
[P1 FJ-04]  /tmp/freshlens-demo/www/uploads/cache.php
        webroot 下新增 0KB 的 .php 脚本（webshell 常见形态）
------------------------------------------------------------------------
判决统计: P0=4  P1=1  P2=0  →  退出码 3
[demo] 植入 3/3 命中、正常文件 0 误报: YES
```

## 为什么是「无基线」

aide / tripwire 式基线工具很好，但它们有一个共同前提：
**你得先有一台干净机器，先建库，再等人来动文件。**

现实经常是反过来的——告警响了你才登上那台没人管过的服务器，
基线不存在、快照没做过，你只有「现在」。freshlens 就是为这一刻准备的：

| | aide/tripwire 式基线 | freshlens |
|---|---|---|
| 前提 | 先有干净机器 + 先建库 | 无，上来就扫 |
| 回答的问题 | 「谁改了已知状态？」 | 「最近被动过的东西里谁可疑？」 |
| 扫描成本 | 全盘哈希，库随盘涨 | stat 元数据，分钟级 |
| 首次可用 | 建库后 | 立刻 |
| 数据库 | 需要保管（本身可被篡改） | 无库可篡改 |

两者是互补不是替代：freshlens 负责「没有基线时的第一时间」，
基线工具负责「长期受控环境」。正经的持久化审计请上 auditd——
freshlens 的价值是**零部署成本的第一层可见性**。

## 安装

零依赖单文件，Python 3.8+，直接跑：

```bash
curl -O https://gitee.com/tomlen/freshlens/raw/main/freshlens.py
# GitHub:
# curl -O https://raw.githubusercontent.com/tomlen045/freshlens/main/freshlens.py
chmod +x freshlens.py
python3 freshlens.py --version   # freshlens 1.0.1
python3 freshlens.py --demo      # 60 秒看懂它能抓什么
```

## 用法

```bash
python3 freshlens.py                    # 默认按操作系统扫敏感路径，24h 时间窗
python3 freshlens.py --since 72         # 时间窗扩到 72 小时
python3 freshlens.py /data/www /app     # 只扫指定根（替换默认，不叠加）
python3 freshlens.py --ignore .DS_Store # 噪声豁免（是过滤器，不是基线）
python3 freshlens.py --json             # 机器可读，接 cron/webhook
python3 freshlens.py --quiet            # 只出判决行，适合管道
python3 freshlens.py --no-color         # 无 ANSI 颜色
python3 freshlens.py --demo             # 内置演示：造沙箱现场抓给你看
```

Linux 与 macOS 都能跑。默认扫描根（可被位置参数替换）：

- **Linux**：`/tmp` `/var/tmp` `/dev/shm` `/var/log` `/etc` `/usr/local/{bin,sbin}` `/root` `/home` `/var/spool/cron` `/var/spool/at` `/srv`
- **macOS**：`/tmp` `/private/var/tmp` `/var/log` `/private/etc` `/usr/local/{bin,sbin}` `/Library/Launch{Agents,Daemons}` `~/{Library/LaunchAgents,.ssh,tmp}`

cron 接法（退出码 0/1/2/3 = 干净/仅P2/含P1/含P0）：

```cron
17 * * * * python3 /opt/freshlens.py --quiet --json >> /var/log/freshlens.jsonl
```

## 12 类判决（FJ-01 ~ FJ-12）

| ID | 级别 | 判决 |
|---|---|---|
| FJ-01 | P0 | 临时目录新落地可执行文件 |
| FJ-02 | P0 | 可执行文件伪装系统服务名（sshd/systemd/kworker…）却不在系统目录 |
| FJ-05 | P0/P2 | 敏感目录（etc 等）新文件；带「其他人可写」位升 P0 |
| FJ-10 | P0 | `/etc/ld.so.preload` 存在且有内容（LD_PRELOAD 投毒标配） |
| FJ-11 | P0 | 时间窗内变动的 SUID 文件 |
| FJ-03 | P1 | 隐藏目录里的新可执行（.git/node_modules 等正常目录已豁免） |
| FJ-04 | P1 | webroot 下新增小体积 `.php/.jsp/.asp`（webshell 形态） |
| FJ-07 | P1 | `authorized_keys` 时间窗内被改动 |
| FJ-08 | P1 | cron.d / cron.hourly / spool / LaunchDaemon 出现新任务文件 |
| FJ-09 | P1 | 同目录批量落地（≥10 个新文件，或 ≥5 个新点文件） |
| FJ-06 | P2 | 日志目录出现非日志后缀新文件 |
| FJ-12 | P2 | 临时目录可执行长期驻留未被清理 |

退出码分级：`0` 干净 / `1` 仅 P2 / `2` 含 P1 / `3` 含 P0——直接接 cron 和告警网关。

## 设计边界（说在前面）

- **只读**：全程 `os.scandir/os.stat`，不写不删不动任何被扫对象
- **mtime 可被倒填**：这是零基线模式的物理边界。攻击者若用 `touch -r` 伪造时间，
  freshlens 会漏——正经对抗请上 auditd/inotify 持久化审计。freshlens 抓的是
  「没打算隐藏的绝大多数」（挖矿木马、批量投放、webshell、误部署）
- **`--since 0` 是冒烟模式**：只走扫描流程，不给任何判决（用于连通性自检）
- **启发式不是取证**：判决是「优先看一眼」的排序器，不是法律证据

## 自测

```bash
python3 selftest.py
# TOTAL 21 | PASS 21 | FAIL 0 — ALL GREEN
```

覆盖：12 类判决逐一真实触发、偏态真实文件年龄分布（绝大多数老文件）零误报、
退出码分级、时间窗闸门、JSON 结构、内置 demo 命中率 3/3。

## 哨兵套件

[**porteye**](https://github.com/tomlen045/porteye) 管「谁在听」→
[**suidhunt**](https://github.com/tomlen045/suidhunt) 管「谁能提权」→
[**authguard**](https://github.com/tomlen045/authguard) 管「谁想进来」→
[**callhome**](https://github.com/tomlen045/callhome) 管「谁在偷偷打电话回家」→
**freshlens 管「什么文件被动了」**——落地面补齐，第五件凑齐。

## License

MIT
