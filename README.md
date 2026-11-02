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
