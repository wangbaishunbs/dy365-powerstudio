# -*- coding: utf-8 -*-
"""对比两个 APK 版本差异:文件级 → 业务 JS 模块级 → 差异字符级,输出兼容性结论。

用法:
    python apk_diff.py <旧APK或目录> <新APK或目录> [--workdir DIR] [--max-diff 6]

对比层次:
    1. 全 APK 文件 MD5 快照:新增/删除/变化;变化中区分"重签名/资源混淆改名"等非功能差异
    2. uni-app 业务 JS(app-service.js / app-view.js):按 webpack 模块 ID 逐个比对
    3. 变化模块逐个做字符级定位(difflib),并甄别"边界位移误报"(内容实际相同)
结论:
    列出发生真实逻辑变化的模块,协议/功能是否兼容一目了然。
仅用标准库。对比 3MB 级压缩 JS 只需数秒(勿对整文件用 difflib,会卡 O(n²))。
"""
import argparse
import hashlib
import os
import re
import shutil
import sys
import tempfile
import zipfile
import difflib

UNI_WWW_RE = re.compile(r"assets/apps/([^/]+)/www/")


def extract_to(apk, workdir, tag):
    if os.path.isdir(apk):
        return apk
    out = os.path.join(workdir, tag)
    os.makedirs(out, exist_ok=True)
    with zipfile.ZipFile(apk) as z:
        z.extractall(out)
    return out


def md5_file(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root):
    files = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            files[rel] = md5_file(p)
    return files


def split_modules(text):
    bounds = [(m.start(1), m.group(1)) for m in
              re.finditer(r'(?:^|[,{}])"?([0-9a-zA-Z_]{2,6})"?:function\(', text)]
    mods = []
    for idx, (pos, mid) in enumerate(bounds):
        end = bounds[idx + 1][0] if idx + 1 < len(bounds) else len(text)
        mods.append((mid, pos, end))
    return mods


def module_groups(text):
    """按模块 ID 分组 → {id: [源码, ...](保持出现顺序)}。
    注意: bundle 里可能存在两段 webpack 打包段,同一 ID 会出现多次;字典会丢实例,必须用列表。"""
    g = {}
    for mid, s, e in split_modules(text):
        g.setdefault(mid, []).append(text[s:e])
    return g


def first_tail_diff(a, b):
    """(前缀相同长度, 后缀相同长度) —— 用于粗定位大文件的差异区。"""
    n = min(len(a), len(b))
    p = 0
    while p < n and a[p] == b[p]:
        p += 1
    s = 0
    while s < n - p and a[len(a) - 1 - s] == b[len(b) - 1 - s]:
        s += 1
    return p, s


def main():
    ap = argparse.ArgumentParser(description="APK 版本对比")
    ap.add_argument("old", help="旧 APK 路径或已解包目录")
    ap.add_argument("new", help="新 APK 路径或已解包目录")
    ap.add_argument("--workdir", default=None, help="解包工作目录(默认临时目录,结束保留并打印路径)")
    ap.add_argument("--max-diff", type=int, default=6, help="每个变化模块最多展示的差异块数")
    args = ap.parse_args()

    workdir = args.workdir or tempfile.mkdtemp(prefix="apk_diff_")
    old_root = extract_to(args.old, workdir, "old")
    new_root = extract_to(args.new, workdir, "new")

    # ---------- 1. 文件级 ----------
    f_old, f_new = snapshot(old_root), snapshot(new_root)
    added = sorted(set(f_new) - set(f_old))
    removed = sorted(set(f_old) - set(f_new))
    changed = sorted(f for f in set(f_old) & set(f_new) if f_old[f] != f_new[f])

    print("=" * 60)
    print("1. 文件级对比")
    print(f"   文件数: {len(f_old)} -> {len(f_new)} | 新增 {len(added)} | 删除 {len(removed)} | 变化 {len(changed)}")
    for f in added[:20]:
        print(f"     + {f}")
    for f in removed[:20]:
        print(f"     - {f}")

    # 资源混淆改名识别: 内容哈希多重集相同的改名文件
    if added and removed:
        from collections import Counter
        add_content = Counter(f_new[f] for f in added)
        rem_content = Counter(f_old[f] for f in removed)
        rename_hits = sum((add_content & rem_content).values())
        if rename_hits and rename_hits >= min(len(added), len(removed)) * 0.9:
            print(f"     (提示: {rename_hits} 个增删文件内容哈希互相对应 —— 疑似构建期资源改名,非功能变化)")

    print("   变化文件:")
    for f in changed:
        print(f"     ~ {f}")

    # ---------- 2. 业务 JS 模块级 ----------
    print("=" * 60)
    print("2. uni-app 业务 JS 模块级对比")
    www_old = {os.path.basename(dp): dp for dp, _, fs in os.walk(old_root)
               for f in fs if f == "manifest.json" and os.path.basename(dp) == "www"}
    www_new = {os.path.basename(dp): dp for dp, _, fs in os.walk(new_root)
               for f in fs if f == "manifest.json" and os.path.basename(dp) == "www"}

    real_changes = []   # (app, js, mod_id, a, b) 内容确有差异
    false_pos = []      # 边界位移误报
    for app_id in sorted(set(www_old) & set(www_new)):
        for jsname in ("app-service.js", "app-view.js"):
            po, pn = os.path.join(www_old[app_id], jsname), os.path.join(www_new[app_id], jsname)
            if not (os.path.exists(po) and os.path.exists(pn)):
                continue
            to, tn = open(po, encoding="utf-8", errors="replace").read(), open(pn, encoding="utf-8", errors="replace").read()
            if to == tn:
                print(f"   [{app_id}/{jsname}] 完全相同")
                continue
            go, gn = module_groups(to), module_groups(tn)
            ids = sorted(set(go) | set(gn))
            diff_ids = [i for i in ids if go.get(i) != gn.get(i)]
            print(f"   [{app_id}/{jsname}] {len(to)} -> {len(tn)} 字符, 模块 {sum(len(v) for v in go.values())} 个, "
                  f"有差异 {len(diff_ids)} 个 ID: " + (" ".join(diff_ids[:40]) or "(无)"))
            from collections import Counter
            for mid in diff_ids:
                lo, ln = go.get(mid, []), gn.get(mid, [])
                # 多重集匹配: 先配对内容完全相同的实例(与出现顺序无关),剩余的才可能真实变化
                common = Counter(ln) & Counter(lo)
                rest_o, rest_n = Counter(lo) - common, Counter(ln) - common
                pair_o, pair_n = [], []
                for t in lo:
                    if rest_o[t] > 0:
                        pair_o.append(t); rest_o[t] -= 1
                for t in ln:
                    if rest_n[t] > 0:
                        pair_n.append(t); rest_n[t] -= 1
                multi = max(len(lo), len(ln)) > 1
                for t in sorted(rest_n - Counter(pair_n)):
                    real_changes.append((app_id, jsname, mid + "[新增实例]", "", t))
                for t in sorted(rest_o - Counter(pair_o)):
                    real_changes.append((app_id, jsname, mid + "[删除实例]", t, ""))
                for k in range(min(len(pair_o), len(pair_n))):
                    a, b = pair_o[k], pair_n[k]
                    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
                    ops = [o for o in sm.get_opcodes() if o[0] != "equal"]
                    if ops:
                        tag = f"{mid}[实例{k}]" if multi else mid
                        real_changes.append((app_id, jsname, tag, a, b, ops))

    if not real_changes:
        print("   (两版业务 JS 无真实内容差异)")

    # ---------- 3. 差异定位 ----------
    print("=" * 60)
    print("3. 真实差异定位")
    for item in real_changes:
        if len(item) == 5:
            app_id, jsname, mid, a, b = item
            tag = "新增模块" if not a else "删除模块"
            print(f"   [{app_id}/{jsname}] {mid}: {tag} ({len(b) or len(a)} 字符)")
            body = (b or a)[:300]
            print(f"      内容预览: {body!r}")
            continue
        app_id, jsname, mid, a, b, ops = item
        print(f"   [{app_id}/{jsname}] {mid}: {len(ops)} 个差异块")
        for tag, i1, i2, j1, j2 in ops[:args.max_diff]:
            ctx = 60
            frag_o = a[max(0, i1 - ctx):i2 + ctx].replace("\n", " ")
            frag_n = b[max(0, j1 - ctx):j2 + ctx].replace("\n", " ")
            print(f"      {tag} 旧[{i1}:{i2}] 新[{j1}:{j2}]")
            print(f"        旧: …{frag_o}…")
            print(f"        新: …{frag_n}…")
        if len(ops) > args.max_diff:
            print(f"      …另有 {len(ops) - args.max_diff} 块省略")

    # ---------- 结论 ----------
    print("=" * 60)
    print("4. 结论摘要")
    biz_changed = [i for i in real_changes if i[1] == "app-service.js"]
    print(f"   变化文件: {', '.join(changed) if changed else '无'}")
    print(f"   业务逻辑(app-service.js): {'无真实差异' if not biz_changed else str(len(biz_changed)) + ' 个模块实例真实变化'}")
    print(f"   解包目录(保留供深入分析): {workdir}")


if __name__ == "__main__":
    main()
