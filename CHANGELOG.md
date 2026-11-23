# Changelog

## v1.0.1（2026-11-23）

狗粮驱动的修复版：v1.0.0 首跑自测 20/21，真机扫描再暴露 2 个实战问题，立案全部修完。

- **FIX** 平台判断 `os.name != "mac"` 恒真（macOS 的 os.name 是 posix），
  Linux 用户会被喂 macOS 默认根 → 改 `sys.platform == "darwin"`
- **FIX** FJ-10（ld.so.preload）只查绝对路径，沙箱/chroot 内永远不触发 →
  改为扫描中识别 etc 组件下的 ld.so.preload，真实路径与相对结构都覆盖
- **FIX** `age_hours` 用 max(mtime, ctime)：ctime 无法回拨（测试无法构造安静老文件）
  且正常 chmod 也会刷新 → 判决窗口以 mtime 为准，倒填局限写进 README 边界
- **FIX** `--since 0` 冒烟模式下 FJ-10/FJ-12 仍会误报真机残留 → 加判决静音闸
- **FIX** FJ-12 把 0755 权限的 `.ts` 源码念成「可执行文件」→ 措辞改「带执行位的文件」
- **FIX** demo 沙箱跑完残留 /tmp，污染下次扫描 → 演示完自动清理
- **FIX** 默认根从「叠加」改「替换」语义（带位置参数 = 只扫给定根，测试确定性）
- **TEST** selftest 21 项全绿：12 判决逐案触发 + 点文件变体 + 偏态真实年龄分布
  （232 文件，绝大多数为老文件）P0/P1 零误报 + 退出码分级 + 冒烟闸门 + demo 3/3

## v1.0.0（2026-11-23）

- 12 类判决 FJ-01~12（P0×5 / P1×5 / P2×2）
- 零基线设计：不建库、不存哈希，时间窗 × 形态启发式，一次扫描出判决
- 只读扫描（os.scandir/os.stat，不写不删不动被扫对象）
- 退出码分级 0/1/2/3 接 cron；--json/--quiet/--ignore/--demo
- Linux / macOS 双平台默认敏感根
