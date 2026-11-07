# APK 版本对比工具

独立脚本(仅 Python 标准库),用于分析 uni-app/DCloud 类 APK、对比两个版本的差异:
文件级 MD5 → webpack 模块级(按 ID 对齐 + 多重集匹配,自动甄别边界位移误报)→ 字符级差异定位。

```bash
python apk_inspect.py <APK路径> --keywords bluetooth,gatt,165
python apk_diff.py <旧APK> <新APK> --workdir ./work
```

> 本目录只包含脚本,不含任何 APK 或反编译代码。分析对象请自备;
> 分析产物(`apk_extracted*/`、`js_modules/` 等)已在 `.gitignore` 排除,请勿提交厂商代码。
