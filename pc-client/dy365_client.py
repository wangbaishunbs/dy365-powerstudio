# -*- coding: utf-8 -*-
"""
ZT-DY365 (众仪 ZOYI 电源+万用表二合一) PC 端 BLE 客户端
====================================================
协议逆向自 e-Bull 电牛V2 v1.1.2 APK (uni-app JS 层)。

用法:
    python dy365_client.py                 # 扫描并连接第一台 ZT-DY*/ZOYI*/POWER* 设备
    python dy365_client.py --scan          # 仅扫描
    python dy365_client.py --name DY365    # 按名称关键字过滤
    python dy365_client.py --address XX:XX:XX:XX:XX:XX
    python dy365_client.py --csv log.csv   # 保存测量数据到 CSV
    python dy365_client.py --mult          # 连接 "Bluetooth DMM" 万用表设备 (5A A5 协议)

连接成功后进入实时显示;可用命令:
    out 1 / out 0     打开/关闭电源输出        (func 0xFC, ctl 2)
    v 12.34           设置输出电压 V           (func 0xFD, ctl 8)
    i 1.234           设置输出电流 A           (func 0xFD, ctl 8)
    unit N            切换万用表显示单位索引    (func 0xFC, ctl 4)
    pre               重新请求 10 组预置参数    (func 0xFE, ctl 6)
    raw FF 00 [hex]   发送任意帧 (func ctl payload)
    status            打印最近一帧完整解码数据
    quit              退出

依赖: pip install bleak
"""

import argparse
import asyncio
import csv
import sys
import time

from bleak import BleakClient, BleakScanner

from dy365_protocol import (
    MULT_GEARS_TABLE, MULT_UNIT_TABLE, MULT_UNIT_TABLE_DMM, OUTPUT_ERROR_TABLE,
    SCHEMA_C, classify_frame, encode_payload, encode_tx, get_send_byte,
    resolve_frames, resolve_mult, xor_code, decode_payload, SCHEMA_S)

DEVICE_NAME_KEYWORDS = ["ZT-DY", "Bluetooth DMM", "ZOYI", "POWER"]  # App get_device 过滤表
SERVICE_PREFIX = "0000fff0"

RESET = "\x1b[0m"
DIM = "\x1b[2m"
BOLD = "\x1b[1m"
GREEN = "\x1b[32m"
CYAN = "\x1b[36m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"


def log(msg: str):
    print(f"{DIM}[{time.strftime('%H:%M:%S')}] {RESET}{msg}", flush=True)


def fmt_version(v: int) -> str:
    """App get_software_version: e => V{e/100}.{e%100/10}.{e%10}"""
    if not v:
        return "-"
    return f"V{v // 100}.{v % 100 // 10}.{v % 10}"


class Dy365Session:
    """一台设备的会话:连接、收发、握手时序、数据缓存。"""

    def __init__(self, address: str, csv_path: str = None, mult_only: bool = False):
        self.address = address
        self.mult_only = mult_only
        self.client = BleakClient(address)
        self.rx_buf = bytearray()
        self.handshake = False          # 收到首帧后为 True (App 的 handshake 标志)
        self.got_pre_data = False
        self.show_data = {}             # 最近一次 show_data/system/ctl 解码结果
        self.pre_data = {}
        self.frames_rx = 0
        self.mult_frames_rx = 0
        self.last_frame_time = 0.0
        self.csv_file = None
        self.csv_writer = None
        self.csv_path = csv_path
        self._csv_header_done = False
        self._last_display = ""
        self._stop = asyncio.Event()

    # ------------------------------------------------------------ BLE ----
    async def open(self):
        log(f"连接 {self.address} ...")
        await self.client.connect()
        svcs = self.client.services
        target = None
        for s in svcs:
            if str(s.uuid).lower().startswith(SERVICE_PREFIX):
                target = s
                break
        if target is None:
            # 兜底:找同时具备 notify+write 特征的服务
            for s in svcs:
                if any("notify" in c.properties for c in s.characteristics) and \
                   any("write" in c.properties or "write-without-response" in c.properties
                       for c in s.characteristics):
                    target = s
                    break
        if target is None:
            raise RuntimeError("未找到 FFF0 服务 (设备可能不是 ZOYI 协议设备)")
        notify_char = next(c for c in target.characteristics if "notify" in c.properties)
        write_char = next(c for c in target.characteristics
                          if "write" in c.properties or "write-without-response" in c.properties)
        log(f"服务 {target.uuid} | notify {notify_char.uuid} | write {write_char.uuid}")
        self.write_char = write_char
        self.write_response = "write" in write_char.properties and \
            "write-without-response" not in write_char.properties
        await self.client.start_notify(notify_char, self._on_notify)
        if self.csv_path:
            self.csv_file = open(self.csv_path, "w", newline="", encoding="utf-8-sig")
            self.csv_writer = csv.writer(self.csv_file)
        log(f"{GREEN}已连接,开始接收...{RESET}")

    async def close(self):
        self._stop.set()
        try:
            await self.client.disconnect()
        except Exception:
            pass
        if self.csv_file:
            self.csv_file.close()
        log("已断开")

    async def send_chunks(self, chunks):
        for chunk in chunks:
            await self.client.write_gatt_char(self.write_char, chunk, response=self.write_response)
            if len(chunks) > 1:
                await asyncio.sleep(0.02)

    async def send_frame(self, payload: bytes, func: int, ctl: int):
        chunks = encode_tx(payload, func, ctl)
        try:
            await self.send_chunks(chunks)
        except Exception as e:
            log(f"{RED}发送失败: {e}{RESET}")

    async def send_mult_cmd(self, frame: bytes):
        """万用表 AB CD 命令 (sendData2 路径): XOR 后 20 字节分包。"""
        await self.send_chunks([xor_code(c) for c in
                                [frame[i:i + 20] for i in range(0, len(frame), 20)]])

    # -------------------------------------------------------- 接收处理 ----
    def _on_notify(self, sender, data: bytearray):
        dec = xor_code(bytes(data))
        # mode 1: 万用表 5A A5 短帧 (逐包直接解析)
        if dec[:2] == b"\x5a\xa5":
            self.mult_frames_rx += 1
            r = resolve_mult(dec)
            if r:
                self._on_mult_data(*r)
            return
        # mode 0: 电源协议,帧尾 \r\n 才拼包解析 (App receiveData 逻辑)
        self.rx_buf += dec
        if len(dec) >= 2 and dec[-2] == 0x0D and dec[-1] == 0x0A:
            frames, _ = resolve_frames(bytes(self.rx_buf))
            self.rx_buf.clear()
            for fr in frames:
                self.frames_rx += 1
                self.last_frame_time = time.time()
                if not self.handshake:
                    self.handshake = True
                    log(f"{GREEN}握手成功,设备已响应{RESET}")
                self._on_frame(fr)

    def _on_frame(self, fr):
        type_name, data = classify_frame(fr)
        if type_name in ("show_data", "system_data", "ctl_data"):
            self.show_data = data
            if type_name == "ctl_data":
                log(f"{CYAN}设置已确认 (ctl={fr.ctl}){RESET}")
            elif type_name == "system_data":
                log(f"{CYAN}system_data 已确认{RESET}")
            self._render()
            self._csv_row(data)
        elif type_name == "pre_data":
            self.pre_data = data
            if not self.got_pre_data:
                self.got_pre_data = True
                log(f"{CYAN}收到预置参数 (10 组){RESET}")
        elif type_name == "cycle_ok":
            log(f"{CYAN}cycle_ok (循环预置运行确认){RESET}")
        else:
            log(f"未知帧: {fr}")

    def _on_mult_data(self, proto, parsed):
        self.mult_parsed = parsed
        val = parsed.get("data_big", "?")
        unit = MULT_UNIT_TABLE_DMM[parsed.get("unit", 0)] if parsed.get("unit", 0) < len(MULT_UNIT_TABLE_DMM) else ""
        print(f"\r{BOLD}[万用表] {val} {unit:<3}{RESET} "
              f"hold={parsed.get('hold')} bat={parsed.get('bat')} beep={parsed.get('beep')} "
              f"gear={parsed.get('gears')}    ", end="", flush=True)

    # ---------------------------------------------------------- 显示 ----
    def _render(self):
        d = self.show_data
        if not d:
            return
        mult_show = d.get("mult_show", "")
        if d.get("mult_show_raw") is not None and abs(d["mult_show_raw"] - 4294967296.0) < 0.5:
            mult_show = "-"  # 0xFFFFFFFF = 万用表无读数
        gears = d.get("mult_gears", 0)
        gear_name = MULT_GEARS_TABLE[gears] if gears < len(MULT_GEARS_TABLE) else str(gears)
        unit = MULT_UNIT_TABLE[d.get("mult_unit", 0)] if d.get("mult_unit", 0) < len(MULT_UNIT_TABLE) else ""
        err = OUTPUT_ERROR_TABLE[d.get("error_status", 0)] if d.get("error_status", 0) < len(OUTPUT_ERROR_TABLE) else str(d.get("error_status"))
        temps = [float(d.get(k, 0) or 0) for k in ("temperature", "temperature2", "temperature3")]
        temp = max(temps)
        out_state = f"{GREEN}ON {RESET}" if d.get("output_status") else f"{RED}OFF{RESET}"
        mode = ("CC" if d.get("cc_cv_flag") == 1 else "CV") if d.get("output_status") else "--"
        line = (f"{BOLD}OUT {d.get('out_vol','--')}V / {d.get('out_ele','---')}A = {d.get('power','--')}W{RESET} "
                f"[{out_state} {mode}] 设定 {d.get('set_vol','--')}V/{d.get('set_ele','---')}A | "
                f"{temp:.1f}℃ | 输入 {d.get('in_vol','--')}V 电池 {d.get('bat_vol','--')}V/{d.get('bat_capacity',0)}% | "
                f"{BOLD}表: {mult_show} {unit} ({gear_name}){RESET} | "
                f"累计 {d.get('power_sum_Wh','--')}Wh {d.get('power_sum_Ah','---')}Ah | "
                f"{('故障:' + err) if err else '正常'}   ")
        print("\r" + line[:int(_term_width()) - 1].ljust(int(_term_width()) - 1), end="", flush=True)
        self._last_display = line

    def _csv_row(self, d):
        if not self.csv_writer:
            return
        if not self._csv_header_done:
            self.csv_writer.writerow(["time", "out_vol", "out_ele", "power", "temperature",
                                      "mult_show", "mult_unit", "mult_gears", "output_status",
                                      "cc_cv_flag", "error_status", "in_vol", "bat_vol",
                                      "set_vol", "set_ele", "power_sum_Wh", "power_sum_Ah"])
            self._csv_header_done = True
        self.csv_writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"),
                                  d.get("out_vol"), d.get("out_ele"), d.get("power"),
                                  d.get("temperature"), d.get("mult_show"),
                                  MULT_UNIT_TABLE[d.get("mult_unit", 0)],
                                  MULT_GEARS_TABLE[d.get("mult_gears", 0)],
                                  d.get("output_status"), d.get("cc_cv_flag"),
                                  d.get("error_status"), d.get("in_vol"), d.get("bat_vol"),
                                  d.get("set_vol"), d.get("set_ele"),
                                  d.get("power_sum_Wh"), d.get("power_sum_Ah")])
        self.csv_file.flush()

    # ------------------------------------------------------ 时序任务 ----
    async def timing_loop(self):
        """复刻 App 100ms 定时器: 握手 500ms→心跳 2s;pre_data 请求 300ms。"""
        tick = 0
        while not self._stop.is_set() and self.client.is_connected:
            await asyncio.sleep(0.1)
            tick += 1
            if not self.mult_only:
                # 握手/心跳: func 0xFF ctl 0
                if not self.handshake:
                    if tick % 5 == 0:
                        await self.send_frame(b"", 0xFF, 0)
                elif tick % 20 == 0:
                    await self.send_frame(b"", 0xFF, 0)
                # pre_data 请求: func 0xFE ctl 6
                if not self.got_pre_data and tick % 3 == 0:
                    await self.send_frame(b"", 0xFE, 6)
            if self.handshake and self.last_frame_time and \
                    time.time() - self.last_frame_time > 8:
                log(f"{YELLOW}超过 8s 未收到数据帧,设备可能已断开{RESET}")
                self.last_frame_time = time.time()

    # ------------------------------------------------------ 命令交互 ----
    async def command_loop(self):
        loop = asyncio.get_running_loop()
        while not self._stop.is_set():
            try:
                cmd = await loop.run_in_executor(None, input)
            except (EOFError, OSError):
                log("输入流结束 (EOF),客户端退出。")
                self._stop.set()
                break
            cmd = cmd.strip()
            if not cmd:
                continue
            try:
                await self._exec(cmd)
            except Exception as e:
                log(f"{RED}命令错误: {e}{RESET}")

    async def _exec(self, cmd: str):
        parts = cmd.split()
        name = parts[0].lower()
        if name == "quit":
            self._stop.set()
            return
        elif name == "out" and len(parts) >= 2:
            await self.send_frame(bytes([1 if parts[1] in ("1", "on", "开") else 0]), 0xFC, 2)
            print()
            log(f"已发送输出{'打开' if parts[1] in ('1','on','开') else '关闭'}命令")
        elif name == "v" and len(parts) >= 2:
            d = dict(self.show_data)
            d["set_vol"] = float(parts[1])
            await self.send_frame(encode_payload(d, SCHEMA_C), 0xFD, 8)
            print()
            log(f"已发送电压设定 {parts[1]}V")
        elif name == "i" and len(parts) >= 2:
            d = dict(self.show_data)
            d["set_ele"] = float(parts[1])
            await self.send_frame(encode_payload(d, SCHEMA_C), 0xFD, 8)
            print()
            log(f"已发送电流设定 {parts[1]}A")
        elif name == "unit" and len(parts) >= 2:
            await self.send_frame(bytes([int(parts[1]) & 0xFF]), 0xFC, 4)
            print()
            log(f"已发送万用表单位切换 ({parts[1]})")
        elif name == "pre":
            self.got_pre_data = False
            await self.send_frame(b"", 0xFE, 6)
            print()
            log("已请求预置参数")
        elif name == "status":
            print()
            log("最近一帧完整数据:")
            for k, v in sorted(self.show_data.items()):
                print(f"    {k:28s} = {v}")
        elif name == "presets":
            print()
            log("预置参数 (10 组):")
            for i in range(1, 11):
                print(f"    组{i}: {self.pre_data.get(f'set_vol{i}','-')}V / "
                      f"{self.pre_data.get(f'set_ele{i}','-')}A / "
                      f"{self.pre_data.get(f'time_output{i}','-')}s")
        elif name == "raw" and len(parts) >= 3:
            func = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
            ctl = int(parts[2], 16) if parts[2].startswith("0x") else int(parts[2])
            payload = bytes.fromhex(parts[3]) if len(parts) >= 4 else b""
            await self.send_frame(payload, func, ctl)
            print()
            log(f"已发送 raw 帧 func=0x{func:02X} ctl={ctl} payload={payload.hex(' ').upper() or '(空)'}")
        elif name == "bt" and len(parts) >= 2:
            # 万用表按键命令: getSendByte(3, code[, extra])
            code = int(parts[1], 0)
            extra = bytes(int(x, 0) & 0xFF for x in parts[2:6])
            frame = get_send_byte(3, code, extra)
            await self.send_mult_cmd(frame)
            print()
            log(f"已发送万用表命令 {frame.hex(' ').upper()}")
        else:
            print()
            log("可用命令: out 1|0 | v <V> | i <A> | unit <N> | pre | presets | status | "
                "raw <func> <ctl> [hex] | bt <code> [d0..d3] | quit")


def _term_width():
    try:
        import shutil
        return shutil.get_terminal_size((100, 24)).columns
    except Exception:
        return 100


# ------------------------------------------------------------------ 扫描 ----
async def scan(name_filter: str = None, timeout: float = 8.0):
    print(f"扫描 BLE 设备 ({timeout}s),过滤关键字: {name_filter or DEVICE_NAME_KEYWORDS} ...")
    found = {}

    def cb(device, adv):
        name = device.name or (adv.local_name or "")
        if not name:
            return
        if name_filter:
            ok = name_filter.lower() in name.lower()
        else:
            ok = any(k in name for k in DEVICE_NAME_KEYWORDS)
        if ok:
            found[device.address] = (name, device.address, adv.rssi)

    async with BleakScanner(detection_callback=cb):
        await asyncio.sleep(timeout)
    if not found:
        print("未发现匹配设备。请确认设备已开机、未被手机 App 占用连接。")
        return []
    devs = sorted(found.values(), key=lambda x: -x[2])
    print(f"\n发现 {len(devs)} 台设备:")
    for i, (name, addr, rssi) in enumerate(devs):
        print(f"  [{i}] {name:24s} {addr}  RSSI {rssi} dBm")
    return devs


async def main():
    ap = argparse.ArgumentParser(description="ZT-DY365 / ZOYI BLE PC 客户端")
    ap.add_argument("--scan", action="store_true", help="仅扫描设备")
    ap.add_argument("--name", help="按名称关键字过滤 (默认 ZT-DY/ZOYI/POWER/Bluetooth DMM)")
    ap.add_argument("--address", help="直接指定设备地址连接")
    ap.add_argument("--index", type=int, default=0, help="扫描结果序号 (默认 0,信号最强)")
    ap.add_argument("--csv", help="将测量数据保存到 CSV 文件")
    ap.add_argument("--mult", action="store_true", help="万用表模式 (Bluetooth DMM 设备, 5A A5 协议)")
    ap.add_argument("--scan-time", type=float, default=8.0)
    args = ap.parse_args()

    if args.scan:
        await scan(args.name, args.scan_time)
        return

    address = args.address
    if not address:
        devs = await scan(args.name, args.scan_time)
        if not devs:
            return
        idx = min(args.index, len(devs) - 1)
        address = devs[idx][1]
        print(f"\n连接设备 [{idx}]: {devs[idx][0]} ({address})\n")

    session = Dy365Session(address, csv_path=args.csv, mult_only=args.mult)
    try:
        await session.open()
    except Exception as e:
        log(f"{RED}连接失败: {e}{RESET}")
        return

    tasks = [asyncio.create_task(session.timing_loop()),
             asyncio.create_task(session.command_loop())]
    print("\n实时数据 (Ctrl+C 退出;输入 help 查看命令):\n")
    try:
        await asyncio.gather(*tasks)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await session.close()


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n[错误] {type(e).__name__}: {e}")
        print("提示: 1) 确认 PC 蓝牙已开启; 2) 关闭手机上的 e-Bull App (设备同时只允许一个连接);")
        print("      3) 确认设备已开机并靠近电脑。")
