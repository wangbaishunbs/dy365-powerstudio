# DY365 Power Studio

ZT-DY365(众仪 ZOYI 电源 + 万用表二合一仪器)的开源上位机与蓝牙/串口协议实现。
协议逆向自官方 e-Bull App(uni-app JS 层),经差分测试与真机验证,兼容 v1.1.2 / v1.1.3。

**English**: Open-source host software and BLE/Serial protocol implementation for the
ZOYI ZT-DY365 (programmable power supply + True-RMS multimeter). Protocol reverse-engineered
from the official e-Bull app and verified against real hardware.

## 功能

- 🖥 **Web 上位机**(`web/index.html`,Edge/Chrome 双击即用,无需安装)
  - 双连接方式:USB 串口(Web Serial)/ 蓝牙 BLE(Web Bluetooth)
  - 实时仪表盘:输出电压/电流/功率、CV/CC、温度、电池、累计电能
  - 万用表读数(AC/DC/R/C/通断/二极管)、曲线图表、数据记录(CSV/Excel 导出)
  - 输出开关、电压/电流设定、保护阈值、10 组预设、电压/电流扫描
  - 内置模拟器(无硬件体验全部功能)、五套主题、中英双语
- 🐍 **PC 命令行客户端**(`pc-client/`,bleak):扫描/连接/实时显示/控制命令/CSV 记录
- 📦 **协议库**(`protocol/dy365-ble-protocol.js`):可嵌入任意网页的独立 JS 库
- 📄 **协议文档**(`docs/protocol.md`):帧格式、CRC16、字段表、命令集、时序、已知设备行为

## 协议速览

```
传输   服务 0000FFF0;每条通知 / 每个 20 字节分包用 20 字节密钥独立 XOR
帧式   A5 5A | LEN | ADDR | FUNC | CTL | DATA… | CRC16_HI | CRC16_LO | 0D 0A
周期   设备约 100ms 推送一帧 208B 状态体(电源 + 万用表字段)
命令   FF·00 握手/心跳 | FC·02 输出 | FC·03 调预设 | FC·04 万用表档位
       FD·01 写全部设置 | FD·05 设定 V/I | FE·06 请求预置
```

完整字段表、CRC16 算法、四种纯万用表子协议(5A A5)见 [docs/protocol.md](docs/protocol.md)。

## 快速开始

### Web 上位机

用 Edge / Chrome 打开 `web/index.html`(或部署到 GitHub Pages 后在线使用):

- 串口:USB 连接设备 → 选择串口 → 连接(默认 9600 8N1)
- 蓝牙:点击「📶 蓝牙BLE」→ 系统弹窗选择 ZT-DY365 开头的设备
- 没有硬件点「🎮 模拟器」

### PC 命令行客户端

```bash
pip install -r pc-client/requirements.txt
python pc-client/dy365_client.py            # 自动扫描并连接
python pc-client/dy365_client.py --csv log.csv
```

连接后可用命令:`out 1/0`(输出)、`v 12.34` / `i 1.5`(设定)、`status`、`presets`、`quit`。

## 目录结构

```
web/index.html            Web 上位机(单文件,含全部主题与逻辑)
pc-client/                Python 命令行客户端(bleak)
protocol/                 独立 JS 协议库(浏览器/Node 通用)
docs/protocol.md          协议完整文档
tools/apk-analyze/        APK 版本对比工具(分析 App 更新是否影响协议)
```

## 兼容性

| 设备 | 状态 |
|---|---|
| ZT-DY365(电源+万用表) | ✅ 真机验证 |
| e-Bull App v1.1.2 / v1.1.3 | ✅ 协议层逐模块比对一致 |

## 声明

- 本项目与众仪/ZOTEK/ZOYI 官方**无任何关联**;ZT-DY365 及相关商标归其所有者所有。
- 协议信息通过**个人使用的互操作性研究**获得;本项目不含任何厂商专有代码。
- 仅供学习与个人使用,请自行承担使用风险;勿用于商业用途。
- 若您是权利人并认为内容不妥,请提 issue 联系,我会及时处理。

## 作者

- 抖音: https://v.douyin.com/C9HPBB3nRQ8/
- 哔哩哔哩: https://b23.tv/LbPhbHL
- 小红书: https://xhslink.cn/o/AYfQzZ3QbDe

## License

[MIT](LICENSE)
