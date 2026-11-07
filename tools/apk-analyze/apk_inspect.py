# -*- coding: utf-8 -*-
"""APK 单包分析:结构识别、uni-app 清单摘要、业务 JS 模块清单、关键词线索扫描。

用法:
    python apk_inspect.py <APK路径或已解包目录> [--keywords 蓝牙,gatt,0xA5] [--list-modules]

输出:
    1. 应用类型判定(uni-app/DCloud / 其他)
    2. 文件清单概况(体积最大/最值得关注的文件)
    3. uni-app www:manifest.json 摘要(版本/页面/权限)
    4. 业务 JS 的 webpack 模块清单(--list-modules 列出全部;默认只列数量)
    5. 关键词命中位置及上下文(协议帧常量、设备名、API 调用等线索)
仅用标准库。
"""
import argparse
import json
import os
import re
import sys
import tempfile
import zipfile

DEFAULT_KEYWORDS = "bluetooth,ble,gatt,serial,uart,protocol,socket,encrypt,aes,crc"

UNI_WWW_GLOB = re.compile(r"assets/apps/[^/]+/www/")


def extract(apk_path, workdir):
    if os.path.isdir(apk_path):
        return apk_path, False
    out = os.path.join(workdir, os.path.splitext(os.path.basename(apk_path))[0].replace(" ", "_"))
    if os.path.isdir(out) and os.listdir(out):
        return out, True  # 已解包,复用
    os.makedirs(out, exist_ok=True)
    with zipfile.ZipFile(apk_path) as z:
        z.extractall(out)
    return out, True


def md5_file(p):
    import hashlib
    h = hashlib.md5()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def find_www_roots(root):
    return [os.path.dirname(p) for p in
            [os.path.join(dp, f) for dp, _, fs in os.walk(root) for f in fs if f == "manifest.json"]
            if os.path.basename(os.path.dirname(p)) == "www"]


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


def split_modules(text):
    """按 webpack 模块边界切分。返回 {id: (start, end)};边界有两种形式。"""
    bounds = [(m.start(1), m.group(1)) for m in
              re.finditer(r'(?:^|[,{}])"?([0-9a-zA-Z_]{2,6})"?:function\(', text)]
    mods = []
    for idx, (pos, mid) in enumerate(bounds):
        end = bounds[idx + 1][0] if idx + 1 < len(bounds) else len(text)
        mods.append((mid, pos, end))
    return mods


def main():
    ap = argparse.ArgumentParser(description="APK 单包分析")
    ap.add_argument("apk", help="APK 文件路径或已解包目录")
    ap.add_argument("--keywords", default=DEFAULT_KEYWORDS, help="逗号分隔的线索关键词")
    ap.add_argument("--list-modules", action="store_true", help="列出业务 JS 的全部 webpack 模块")
    ap.add_argument("--context", type=int, default=70, help="关键词上下文字符数")
    args = ap.parse_args()

    workdir = tempfile.mkdtemp(prefix="apk_inspect_")
    root, _ = extract(args.apk, workdir)
    print(f"解包目录: {root}")

    # ---- 类型判定 ----
    uni = bool(find_www_roots(root))
    has_dex = os.path.exists(os.path.join(root, "classes.dex"))
    print(f"应用类型: {'uni-app / DCloud 混合应用(业务逻辑在 JS 层)' if uni else '其他(存在 classes.dex: ' + str(has_dex) + ')'}")

    # ---- 文件概况 ----
    all_files = []
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            all_files.append((os.path.getsize(p), os.path.relpath(p, root)))
    all_files.sort(reverse=True)
    total = sum(s for s, _ in all_files)
    print(f"文件总数: {len(all_files)} | 总体积: {human(total)}")
    print("最大的 8 个文件:")
    for s, rel in all_files[:8]:
        print(f"    {human(s):>9}  {rel}")

    # ---- uni-app www 分析 ----
    if uni:
        for www in find_www_roots(root):
            app_id = os.path.basename(os.path.dirname(www))
            print(f"\n== uni-app {app_id} ==")
            mf = os.path.join(www, "manifest.json")
            if os.path.exists(mf):
                try:
                    m = json.load(open(mf, encoding="utf-8"))
                    v = m.get("version", {})
                    print(f"  应用名: {m.get('name')} | 版本: {v.get('name')} (code {v.get('code')})")
                    pages = (m.get("plus", {}).get("tabBar", {}) or {}).get("list", [])
                    if pages:
                        print("  标签页:", " / ".join(p.get("text", p.get("pagePath", "?")) for p in pages))
                    perms = m.get("permissions", {})
                    if perms:
                        print("  权限声明:", ", ".join(perms.keys()))
                except Exception as e:
                    print(f"  manifest.json 解析失败: {e}")
            for jsname in ("app-service.js", "app-view.js"):
                p = os.path.join(www, jsname)
                if not os.path.exists(p):
                    continue
                text = open(p, encoding="utf-8", errors="replace").read()
                mods = split_modules(text)
                print(f"  {jsname}: {len(text)} 字符, {len(mods)} 个 webpack 模块"
                      + ("  <- 业务逻辑所在" if jsname == "app-service.js" else ""))
                if args.list_modules:
                    for mid, s0, e0 in mods:
                        print(f"      {mid:<8} {e0 - s0:>7} 字符")

    # ---- 关键词扫描 ----
    kws = [k.strip() for k in args.keywords.split(",") if k.strip()]
    targets = []
    for dp, _, fs in os.walk(root):
        for f in fs:
            if f.endswith((".js", ".json", ".xml", ".html")):
                p = os.path.join(dp, f)
                rel = os.path.relpath(p, root)
                if UNI_WWW_GLOB.search(rel.replace(os.sep, "/")) and "view.umd" in f:
                    continue  # 跳过框架文件
                targets.append((rel, p))
    print(f"\n== 关键词扫描 ({', '.join(kws)}) ==")
    hits = 0
    for rel, p in sorted(targets):
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        low = text.lower()
        for kw in kws:
            start = 0
            cnt = 0
            while cnt < 3:  # 每词每文件最多展示 3 处
                i = low.find(kw.lower(), start)
                if i < 0:
                    if cnt == 0:
                        break
                    break
                ctx = text[max(0, i - args.context): i + len(kw) + args.context].replace("\n", " ")
                print(f"  [{rel}] {kw} @{i}: …{ctx}…")
                hits += 1
                cnt += 1
                start = i + len(kw)
    if hits == 0:
        print("  (无命中)")


if __name__ == "__main__":
    main()
