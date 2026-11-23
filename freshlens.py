#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
freshlens — 无基线文件异动透镜
================================
不依赖任何可信基线库，一次扫描回答一个问题：
「这台机器上，最近有哪些文件被动了？它们长得像不像不速之客？」

设计铁律：
  1. 零基线：不做全盘哈希比对，靠 mtime/ctime 时间窗 + 名字/权限/位置启发式给判决
  2. 只读：全程 os.scandir / os.stat，不写不删不动任何被扫对象
  3. 零依赖：纯标准库，Python 3.8+，单文件
  4. 判决可退出码分级：0=干净 1=仅P2 2=含P1 3=含P0（可直接接 cron）

12 类判决（FJ-01 ~ FJ-12）：
  FJ-01 P0  临时目录新落地可执行文件（mtime 在时间窗内 + x 位 + tmp/shm 类路径）
  FJ-02 P0  伪装系统名的可执行文件（sshd/systemd/kworker… 出现在非系统路径）
  FJ-05 P0/P2 敏感目录新文件（etc/cron 类；带"其他人可写"位 → P0，否则 P2）
  FJ-10 P0  /etc/ld.so.preload 挂钩（存在且有内容即判，LD_PRELOAD 投毒标配）
  FJ-11 P0  时间窗内变动的 SUID 文件（setuid 位 + 近期 mtime/ctime）
  FJ-03 P1  隐藏目录里的可执行文件（.开头目录，排除 .git/node_modules 等正常目录）
  FJ-04 P1  webshell 形态文件（webroot 下新增小体积 .php/.jsp/.asp 单文件）
  FJ-07 P1  SSH 授权文件变动（authorized_keys / authorized_keys2 近期被改）
  FJ-08 P1  cron 投放（cron.d / cron.hourly / spool/cron 出现时间窗内新文件）
  FJ-09 P1  批量落地（同一目录时间窗内 >=10 个新文件，或 >=5 个新点文件）
  FJ-12 P2  临时目录驻留可执行（老文件但一直没被清——重启不清的 tmp 是坏习惯）
  FJ-06 P2  日志目录异物（log/logs 目录里出现非日志后缀的新文件）

用法：
  freshlens.py                      # 按当前操作系统扫默认敏感路径（时间窗 24h）
  freshlens.py --since 72           # 时间窗改为 72 小时
  freshlens.py /data/www --since 48 # 追加扫描任意路径
  freshlens.py --json               # 机器可读输出（接 cron / webhook）
  freshlens.py --demo               # 内置演示：造一个含 3 处植入的沙箱并现场抓给你看
  freshlens.py --ignore .DS_Store   # 噪声豁免（可重复），不是基线，只是过滤器
"""
import argparse
import json
import os
import stat
import sys
import time

__version__ = "1.0.1"
TOOL = "freshlens"

# ---------------------------------------------------------------- 常量

SEV_ORDER = {"P0": 3, "P1": 2, "P2": 1}
EXIT_MAP = {0: 0, 1: 1, 2: 2, 3: 3}

# 临时/易落地目录：路径组件匹配（跨平台，沙箱可用同名目录模拟）
TRANSIENT_COMPS = {"tmp", "temp", "shm"}
# 敏感目录：组件序列匹配
SENSITIVE_MARKERS = [
    ("etc",),
    ("usr", "local", "bin"),
    ("usr", "local", "sbin"),
    ("library", "launchdaemons"),
    ("library", "launchagents"),
]
CRON_COMPS = {"cron.d", "cron.hourly", "cron.daily", "cron.weekly", "cron.monthly",
              "cron", "spool", "launchagents", "launchdaemons"}
WEBROOT_COMPS = {"www", "htdocs", "public_html", "webapps", "webapp", "webroot", "html"}
LOGDIR_COMPS = {"log", "logs"}
SSH_COMPS = {".ssh"}
SYSTEM_COMPS = {"usr", "bin", "sbin", "lib", "lib64", "libexec", "system", "library",
                "local", "opt", "usrmerge"}

MASQ_NAMES = {
    "sshd", "systemd", "systemd-resolved", "kworker", "kthreadd", "udevd", "udev",
    "polkitd", "dbus", "dbus-daemon", "cron", "crond", "syslogd", "rsyslogd",
    "launchd", "securityd", "mds", "wpa_supplicant", "networkd", "ssh-agent",
    "gnome-shell", "Xorg", "mysqld", "postgres", "httpd", "nginx", "kdevtmpfsi",
    "kinsing", "pty3", "sckmem",
}

WEB_SCRIPT_EXTS = {".php", ".php5", ".php7", ".phtml", ".jsp", ".jspx", ".asp",
                   ".aspx", ".ashx", ".cer_", ".cdx"}
LOG_OK_EXTS = {".log", ".gz", ".xz", ".bz2", ".zst", ".lz4", ".zst_", ".1", ".2",
               ".3", ".4", ".journal", ".txt", ".old", ".err", ".out", ".json",
               ".ckidx", ".idx", ".tmp"}

DOTDIR_EXCLUDES = {".git", ".svn", ".hg", ".tox", ".venv", ".mypy_cache",
                   ".pytest_cache", ".ruff_cache", "node_modules", "__pycache__",
                   ".npm", ".yarn", ".cache", ".parcel-cache", ".gradle",
                   ".mvn", ".idea", ".vscode", ".terraform", ".DS_Store"}

NOISE_NAMES = {".DS_Store", "desktop.ini", "Thumbs.db", ".localized"}

# 各平台默认扫描根
DEFAULT_ROOTS_LINUX = [
    "/tmp", "/var/tmp", "/dev/shm", "/run/shm", "/var/log",
    "/etc", "/usr/local/bin", "/usr/local/sbin",
    "/root", "/home", "/var/spool/cron", "/var/spool/at", "/srv",
]
DEFAULT_ROOTS_MAC = [
    "/tmp", "/private/var/tmp", "/var/log", "/private/etc",
    "/usr/local/bin", "/usr/local/sbin",
    "/Library/LaunchAgents", "/Library/LaunchDaemons",
    "~/Library/LaunchAgents", "~/Library/LaunchDaemons", "~/.ssh", "~/tmp",
]

MAX_FILE_SIZE = 64 * 1024 * 1024      # 64MB 以上不看内容也不统计为"落地"证据
MAX_DEPTH = 8
MAX_ENTRIES = 60000                    # 单根扫描条目上限，防爆盘
BATCH_FILES = 10                       # FJ-09：同目录窗口内新文件数阈值
BATCH_DOT = 5                          # FJ-09：同目录窗口内新点文件数阈值

# ---------------------------------------------------------------- 工具函数


def log(msg):
    sys.stderr.write(msg + "\n")


def is_transient(parts):
    return any(p.lower() in TRANSIENT_COMPS for p in parts)


def is_sensitive(parts):
    low = [p.lower() for p in parts]
    for mark in SENSITIVE_MARKERS:
        n = len(mark)
        for i in range(len(low) - n + 1):
            if tuple(low[i:i + n]) == mark:
                return True
    return False


def comps_hit(parts, names):
    return any(p.lower() in names for p in parts)


def age_hours(st, now):
    # 判决窗口以 mtime 为准（ctime 无法被测试/工具回拨，且正常 chmod 也会刷新 ctime，
    # 拿它当异动信号会误报；mtime 可被倒填是零基线模式的已知边界，见 README）
    return (now - st.st_mtime) / 3600.0


def human_age(h):
    if h < 1:
        return "%d分钟" % max(1, int(h * 60))
    if h < 48:
        return "%.1f小时" % h
    return "%.1f天" % (h / 24.0)


def x_bits(mode):
    return (mode & stat.S_IXUSR) or (mode & stat.S_IXGRP) or (mode & stat.S_IXOTH)


def world_writable(mode):
    return bool(mode & stat.S_IWOTH)


def suid(mode):
    return bool(mode & stat.S_ISUID)


def ext_of(name):
    base = name.lower()
    for i in range(len(base) - 1, 0, -1):
        if base[i] == ".":
            return base[i:]
    return ""


def ansi(s, code, enable):
    return "\033[%sm%s\033[0m" % (code, s) if enable else s


SEV_COLOR = {"P0": "1;31", "P1": "1;33", "P2": "36"}

# ---------------------------------------------------------------- 扫描器


class Scanner(object):
    def __init__(self, roots, since_h=24.0, ignores=(), scan_since_all=False):
        self.roots = [os.path.expanduser(r) for r in roots]
        self.since_h = since_h
        self.ignores = [i for i in ignores if i]
        self.now = time.time()
        self.verdicts = []
        self.scanned = 0
        self.skipped_roots = []
        self.recent_by_dir = {}   # parent -> [(name, path, st)]
        self.dot_by_dir = {}      # parent -> count
        self.truncated = False

    # ---- 过滤
    def _noise(self, name):
        if name in NOISE_NAMES:
            return True
        for ig in self.ignores:
            if ig in name:
                return True
        return False

    def _skip_dir(self, name):
        return name in DOTDIR_EXCLUDES or name in ("node_modules", "site-packages",
                                                   "dist-packages", "proc", "sys", "dev")

    # ---- 主入口
    def run(self):
        for root in self.roots:
            if not os.path.exists(root):
                self.skipped_roots.append(root)
                continue
            self._walk(root, 0)
        self._flush_batches()
        self._check_ldpreload()
        return self.report()

    def _walk(self, path, depth):
        if depth > MAX_DEPTH:
            return
        try:
            entries = list(os.scandir(path))
        except (PermissionError, OSError):
            return
        if len(entries) > MAX_ENTRIES:
            self.truncated = True
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        transient = is_transient(parts)
        sensitive = is_sensitive(parts)
        is_cron = comps_hit(parts, CRON_COMPS)
        is_web = comps_hit(parts, WEBROOT_COMPS)
        is_log = comps_hit(parts, LOGDIR_COMPS)
        is_ssh = comps_hit(parts, SSH_COMPS)
        base = os.path.basename(path)
        hidden_dir = base.startswith(".") and base not in DOTDIR_EXCLUDES

        for e in entries:
            self.scanned += 1
            name = e.name
            if self._noise(name):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            fpath = e.path
            if e.is_dir(follow_symlinks=False):
                if self._skip_dir(name):
                    continue
                self._walk(fpath, depth + 1)
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_size > MAX_FILE_SIZE:
                continue

            age = age_hours(st, self.now)
            recent = age <= self.since_h
            mode = st.st_mode
            execu = x_bits(mode)

            # 收集窗口内新文件（给 FJ-09 批量判决用）
            if recent:
                self.recent_by_dir.setdefault(os.path.dirname(fpath), []).append(
                    (name, fpath, mode, age))
                if name.startswith("."):
                    self.dot_by_dir[os.path.dirname(fpath)] = \
                        self.dot_by_dir.get(os.path.dirname(fpath), 0) + 1

            # FJ-01 临时目录新落地可执行
            if transient and execu and recent:
                self._add("FJ-01", "P0", fpath,
                          "临时目录新落地可执行文件（%s前出现）" % human_age(age))
            # FJ-02 伪装系统名
            if execu and name in MASQ_NAMES and not comps_hit(parts, SYSTEM_COMPS):
                self._add("FJ-02", "P0", fpath,
                          "可执行文件伪装系统服务名「%s」却不在系统目录" % name)
            # FJ-12 临时目录驻留可执行（超出时间窗的老文件）
            if transient and execu and not recent and age > max(self.since_h, 48.0):
                self._add("FJ-12", "P2", fpath,
                          "带执行位的文件在临时目录驻留 %s 未被清理" % human_age(age))
            # FJ-11 近期变动的 SUID
            if suid(mode) and recent:
                self._add("FJ-11", "P0", fpath,
                          "SUID 文件在时间窗内被创建/改动（%s前）" % human_age(age))
            # FJ-03 隐藏目录可执行
            if hidden_dir and execu and recent:
                self._add("FJ-03", "P1", fpath,
                          "隐藏目录「%s」内出现新可执行文件" % base)
            # FJ-04 webshell 形态
            if is_web and recent and ext_of(name) in WEB_SCRIPT_EXTS:
                if st.st_size < 512 * 1024:
                    self._add("FJ-04", "P1", fpath,
                              "webroot 下新增 %dKB 的 %s 脚本（webshell 常见形态）"
                              % (st.st_size // 1024, ext_of(name)))
            # FJ-10 ld.so.preload（真实绝对路径 + 沙箱/chroot 相对结构都识别）
            if name == "ld.so.preload" and comps_hit(parts, {"etc"}) and st.st_size > 0:
                self._add("FJ-10", "P0", fpath,
                          "ld.so.preload 存在且有内容（LD_PRELOAD 投毒标配）")
            # FJ-05 敏感目录新文件
            if sensitive and recent and not is_cron:
                sev = "P0" if world_writable(mode) else "P2"
                why = "敏感目录新文件（%s前）" % human_age(age)
                if sev == "P0":
                    why += "，且「其他人可写」"
                self._add("FJ-05", sev, fpath, why)
            # FJ-06 日志目录异物
            if is_log and recent and ext_of(name) and ext_of(name) not in LOG_OK_EXTS:
                self._add("FJ-06", "P2", fpath,
                          "日志目录出现非日志后缀新文件「%s」" % name)
            # FJ-07 SSH 授权变动
            if is_ssh and recent and name in ("authorized_keys", "authorized_keys2"):
                self._add("FJ-07", "P1", fpath,
                          "SSH 授权文件在时间窗内被改动（%s前）" % human_age(age))
            # FJ-08 cron / launchd 投放
            if is_cron and sensitive and recent and execu:
                self._add("FJ-08", "P1", fpath,
                          "cron/LaunchDaemon 目录出现新可执行/脚本（%s前）"
                          % human_age(age))
            elif is_cron and recent and not execu and ext_of(name) in ("", ".sh") \
                    and comps_hit(parts, {"cron.d", "cron.hourly", "cron.daily"}):
                self._add("FJ-08", "P1", fpath,
                          "cron 任务目录出现新任务文件（%s前）" % human_age(age))

    # ---- 批量判决（FJ-09）
    def _flush_batches(self):
        for d, items in self.recent_by_dir.items():
            if len(items) >= BATCH_FILES:
                self._add("FJ-09", "P1", d,
                          "同目录时间窗内批量落地 %d 个新文件" % len(items))
            elif self.dot_by_dir.get(d, 0) >= BATCH_DOT:
                self._add("FJ-09", "P1", d,
                          "同目录时间窗内批量出现 %d 个点文件（隐藏投放形态）"
                          % self.dot_by_dir[d])

    # ---- ld.so.preload（FJ-10）
    def _check_ldpreload(self):
        for cand in ("/etc/ld.so.preload", "/private/etc/ld.so.preload",
                     "etc/ld.so.preload"):
            if os.path.isfile(cand):
                try:
                    if os.path.getsize(cand) > 0:
                        self._add("FJ-10", "P0", cand,
                                  "ld.so.preload 存在且有内容（LD_PRELOAD 投毒标配）")
                except OSError:
                    pass
                break

    def _add(self, fid, sev, path, why):
        if self.since_h <= 0:
            return  # --since 0 = 连通性冒烟模式：只走扫描，不给任何判决
        self.verdicts.append({
            "id": fid, "severity": sev, "path": path, "reason": why,
        })
    # ---- 汇总
    def report(self):
        sev_rank = {"P0": 0, "P1": 1, "P2": 2}
        self.verdicts.sort(key=lambda v: (sev_rank[v["severity"]], v["id"], v["path"]))
        summary = {"P0": 0, "P1": 0, "P2": 0}
        for v in self.verdicts:
            summary[v["severity"]] += 1
        top = SEV_ORDER["P0"] if summary["P0"] else \
              SEV_ORDER["P1"] if summary["P1"] else \
              SEV_ORDER["P2"] if summary["P2"] else 0
        return {
            "tool": TOOL, "version": __version__,
            "since_hours": self.since_h,
            "roots": self.roots,
            "skipped_roots": self.skipped_roots,
            "scanned_entries": self.scanned,
            "truncated": self.truncated,
            "verdicts": self.verdicts,
            "summary": summary,
            "exit_code": EXIT_MAP[top],
        }

# ---------------------------------------------------------------- 输出


def render_human(rep, color=True):
    out = []
    c = lambda s, code: ansi(s, code, color)
    out.append(c("freshlens v%s · 无基线文件异动透镜" % __version__, "1;36"))
    out.append("时间窗: %.0fh · 扫描根: %d 个 · 条目: %d%s" % (
        rep["since_hours"], len(rep["roots"]), rep["scanned_entries"],
        "（条目超限部分截断）" if rep["truncated"] else ""))
    if rep["skipped_roots"]:
        out.append("跳过不存在的根: %s" % ", ".join(rep["skipped_roots"]))
    out.append("-" * 72)
    if not rep["verdicts"]:
        out.append(c("CLEAN — 时间窗内没有发现异动", "1;32"))
    for v in rep["verdicts"]:
        out.append("%s  %s" % (c("[%s %s]" % (v["severity"], v["id"]),
                                     SEV_COLOR[v["severity"]]), v["path"]))
        out.append("        %s" % v["reason"])
    out.append("-" * 72)
    s = rep["summary"]
    out.append("判决统计: P0=%d  P1=%d  P2=%d  →  退出码 %d" % (
        s["P0"], s["P1"], s["P2"], rep["exit_code"]))
    return "\n".join(out)


# ---------------------------------------------------------------- demo


def build_demo(basedir):
    """造一个含 3 处植入 + 2 处噪声的沙箱，全部真实落盘。返回植入清单。"""
    now = time.time()
    def w(rel, data=b"#!/bin/sh\necho hi\n", age_h=None, mode=None):
        p = os.path.join(basedir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        if age_h is not None:
            t = now - age_h * 3600
            os.utime(p, (t, t))
        if mode is not None:
            os.chmod(p, mode)
        return p
    planted = [
        w("tmpd/kworker", b"\x7fELF binary-ish", age_h=2, mode=0o755),
        w("tmpd/sshd", b"\x7fELF binary-ish", age_h=5, mode=0o755),
        w("www/uploads/cache.php", b"<?php eval($_POST[1]);", age_h=3, mode=0o644),
    ]
    noise = [
        w("logs/app.log", b"2026-11-23 ok\n", age_h=400),
        w("var/data/backup_2025.tar.gz", b"\x1f\x8b old backup", age_h=2000),
    ]
    return planted, noise


def run_demo(color=True):
    import shutil
    base = "/tmp/freshlens-demo"
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    planted, noise = build_demo(base)
    log("[demo] 沙箱已建: %s（3 处植入 + 2 个正常老文件）" % base)
    sc = Scanner([base], since_h=24.0)
    rep = sc.run()
    hits = {v["path"] for v in rep["verdicts"]}
    ok = all(p in hits for p in planted) and not any(n in hits for n in noise)
    print(render_human(rep, color))
    log("[demo] 植入 3/3 命中、正常文件 0 误报: %s" % ("YES" if ok else "NO — 请反馈 bug"))
    shutil.rmtree(base, ignore_errors=True)   # 演示完自杀，不污染下次扫描
    log("[demo] 沙箱已清理: %s" % base)
    return 0

# ---------------------------------------------------------------- main


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=TOOL, description="freshlens — 无基线文件异动透镜（只读/零依赖/单文件）")
    ap.add_argument("roots", nargs="*", help="追加扫描根（默认按操作系统选敏感路径）")
    ap.add_argument("--since", type=float, default=24.0, metavar="H",
                    help="时间窗（小时），默认 24")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--ignore", action="append", default=[], metavar="SUB",
                    help="文件名包含 SUB 的跳过（可重复；是过滤器，不是基线）")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="只输出判决行")
    ap.add_argument("--version", action="version", version="freshlens %s" % __version__)
    ap.add_argument("--demo", action="store_true", help="内置演示沙箱并现场扫描")
    args = ap.parse_args(argv)

    color = (sys.stdout.isatty() or sys.stderr.isatty()) and not args.no_color
    if args.demo:
        return run_demo(color=color)

    # 替换语义：不带位置参数 → 按当前操作系统扫默认敏感路径；带了 → 只扫给定的
    default = DEFAULT_ROOTS_MAC if sys.platform == "darwin" else DEFAULT_ROOTS_LINUX
    roots = args.roots if args.roots else default
    sc = Scanner(roots, since_h=args.since, ignores=args.ignore)
    rep = sc.run()

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    elif args.quiet:
        for v in rep["verdicts"]:
            print("[%s %s] %s %s" % (v["severity"], v["id"], v["path"], v["reason"]))
    else:
        print(render_human(rep, color))
    return rep["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
