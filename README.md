# SimAdmin + luci-app-simadmin（原生 IMS / VoLTE 短信栈）

这个仓库是 SimAdmin 后端与 OpenWrt LuCI 打包目录的合并工作区，重点是**把设备上已跑通的
`ims/` 协议库移植进后端**，让短信收发在 OpenWrt（aarch64 / musl）上可用，不再依赖
python daemon。

## 目录

```
SimAdmin-main/            Rust 后端（workspace：backend + crates）
  backend/src/volte/      原生 IMS 栈（12 个模块）
  backend/src/volte_manager.rs
luci-app-simadmin/        OpenWrt 软件包（LuCI 页面 + 启动脚本 + 预编译二进制）
.github/workflows/        CI：跑单测 → 交叉编译 aarch64-musl → 产出二进制/整包
```

## IMS 栈做了什么

```
IMSI/AID ─→ IMS PDN（qmicli 优先，裸 QMUX 降级）─→ P-CSCF + 主机路由
      └→ REGISTER#1（空 Digest + Security-Client）
            └→ 401 ─→ USIM AKA（qmi-proxy 优先，裸 QMUX 降级）
                  └→ ip xfrm 无缝换装 ─→ REGISTER#2（Authorization + Security-Client + Security-Verify）
                        └→ 200 OK ─→ 常驻收包（port_c + port_s）
```

- 承载、AKA 各两条通道，任一条失败自动降级；IPsec 装不上就退回纯 UDP 注册。
- MO：`SMS-SUBMIT → RP-DATA → SIP MESSAGE`，等 2xx + 同 reference 的 RP-ACK。
- MT：`200 OK`（空体）+ 单独一条带 RP-ACK 体的 MESSAGE，落库时用 `ims:<md5>` 去重。
- 注册后 ModemManager 侧的短信监听只清理不导入，避免同一条 MT 入库两次。

## 编译

CI 会自动构建，产物在 Actions 的 artifact 里：

- `simadmin-aarch64-musl` —— 单个静态二进制
- `luci-app-simadmin-pkg` —— 已替换好二进制的整包目录

本地交叉编译（需要 musl 交叉工具链）：

```sh
cd SimAdmin-main
rustup target add aarch64-unknown-linux-musl
export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
cargo build --release --target aarch64-unknown-linux-musl -p simadmin
```

## 部署

1. 把 `simadmin` 覆盖到 `/opt/simadmin/simadmin`（`chmod 0755`）；
2. 依赖：`qmi-utils`、`ip-full`（只有它带 `ip xfrm`）、`jsonfilter`、`curl`、`modemmanager`；
3. 配置文件 `/opt/simadmin/data/config.json` 的 `volte` 段，默认已开启：

```json
"volte": {
  "feature_enabled": true,
  "sms_enabled": true,
  "apn": "",
  "apn_protocol": "IPV4V6",
  "smsc": "",
  "pcscf": "",
  "interface": "",
  "mux": 2,
  "port_c": 47481,
  "port_s": 47482,
  "prefer_ipsec": true,
  "refresh_secs": 1800
}
```

4. 验证：`curl -s 127.0.0.1:3000/api/volte/control`，看 `runtime.phase` 是否为
   `registered`；`logread | grep simadmin::volte` 看注册到哪一步。

`mux` 与 `apn` 是最可能需要按现场调整的两个参数（默认 `mux=2` 对应 `wwan0.2`，
APN 为空时按 IMSI 推导 `ims.epc.mncXXX.mccXXX.gprs`）。

### P-CSCF 一定要手填的情况

P-CSCF 按下面顺序找，前一步拿到就不再往下走：

1. `volte.pcscf` 手工配置（最可靠）；
2. QMI `--wds-get-current-settings` 的 0x1F TLV；
3. `AT+CGCONTRDP`（会先发 `AT$QCPDPIMSCFGE=<cid>,1,1,1` 打开上报）；
4. IMS 承载所在 /24 的 SIP 探测（发 REGISTER，收到 `SIP/2.0` 即认定）。

中国联通实测四条全空：QMI 无 0x1F、`+CGCONTRDP` 只有 7 个字段（第 8 个 P-CSCF 不存在）、
公网 DNS 对 `pcscf.mnc001.mcc460.3gppnetwork.org` 返回 NXDOMAIN、把 UE 所在
`/16` 全扫一遍无人应答。这种情况下 `runtime.phase` 会停在 `failed`，
错误码 `volte_runtime_all_pcscf_failed`，**必须**在 `volte.pcscf` 里填上运营商给的地址：

```sh
# 直接改配置文件后重启服务
jsonfilter -i /opt/simadmin/data/config.json -e '@.volte' >/dev/null 2>&1
uci set simadmin.volte.pcscf='10.x.x.x'   # 或用 API：
curl -s -X POST 127.0.0.1:3000/api/volte/settings \
     -H 'Content-Type: application/json' \
     -d '{"pcscf":"10.x.x.x"}'
```

填好之后重启 `simadmin`，`logread | grep simadmin::volte` 应出现
`IMS REGISTER 200 OK — 短信通道已接管`。

### 默认数据连接

`/usr/bin/simadmin-data` 用 ModemManager 建默认承载（`mmcli --simple-connect`），
不要改成手拼 `qmicli --wds-start-network`：bam-dmux 上必须先 bind mux 数据口，
不带 bind 的会话能拿到地址但数据面是死的。另外 `volte.feature_enabled=false` 时
它不会等 IMS 注册，否则开机后要空等 `WAIT_IMS`（默认 600s）才有网。
