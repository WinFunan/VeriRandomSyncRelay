# VeriRandom Sync Relay (ASP.NET Core 10)

[![CI](https://github.com/WinFunan/VeriRandomSyncRelay/actions/workflows/ci.yml/badge.svg)](https://github.com/WinFunan/VeriRandomSyncRelay/actions/workflows/ci.yml)

一个匿名、短时、端到端加密的名单/文件中转服务，作为 VeriRandom 的云端名单传输通道。

- 服务端：ASP.NET Core 10 Minimal API，内存存储，默认单条密文上限 **1 MiB**。
- 载荷加密：**AES-128-CTR + HMAC-SHA256**（Encrypt-then-MAC）。
- 会话码模式：**Argon2id(password, salt) 直接派生载荷密钥**，不再上传 wrapped key。
- 二维码模式：32 字节随机载荷密钥放在 URL fragment 中，服务端永远看不到。
- 会话码：12 位码只作为查找键；密码经 Argon2id 派生密钥，服务端只看到盐和密文。

> 重要：本项目不是“纯 AES-128-CTR”。纯 CTR 没有完整性保护，能被逐位篡改；因此实现中强制加入 HMAC-SHA256。

---

## 1. 先说结论：直接派生之后安全了吗？

直接派生比“wrapped key”更简单，也少了一层密钥封装，但它**不能阻止服务端离线猜测密码**。

服务端虽然没有 wrapped key，但它仍然持有：

- Argon2id 盐和参数；
- 密文；
- 用于校验完整性的 HMAC。

攻击者拿到这些后，可以离线尝试密码：用候选密码 + 盐跑 Argon2id，派生密钥，解密并校验 HMAC。密码正确，HMAC 就通过。  
所以“服务端不持有可解密的密钥”是事实，但“服务端不能离线猜密码”**不成立**。Argon2id 只能提高每次猜测的成本，不能消除猜测。

### 这个改动带来的实际变化

更好的地方：

- 协议更简单，没有“先解封密钥、再解密载荷”的两段式流程。
- 服务端不再存储任何形式的密钥材料，只存盐 + 密文。
- 载荷密钥不会因为“wrapped key 泄露”而单独泄露；攻击者仍然必须猜密码。
- 密码和载荷绑定更直接；改密码意味着重新加密，不会出现“旧 wrapped key 配新密码”的歧义。
- 会话码模式把会话码哈希绑定进 MAC，恶意中转不能把一个会话码的信封换到另一个会话码下（即使密码复用）。

没有解决的问题：

- **离线猜测仍然存在**，因为盐和密文都在服务端。
- **弱密码仍然会被猜出**。Argon2id 不是密码强度保险。
- **会话码 + 密码如果一起发送**，截获者两个都拿到，密码不会增加保护。
- **“点对点”仍然是误称**：数据经过中转服务器，准确说法是“端到端加密 + 不可信中转”。

### 如果你的目标是抵抗服务端离线猜测

只有两条路：

1. 使用高熵密码（例如客户端生成的 32 字符随机密码），并保证传递渠道安全；
2. 不让服务端持有可离线验证的数据，例如真正的点对点传输，或者密码永远不用于派生落地的持久密钥。

在“匿名中转 + 服务端存密文”的模型下，只要密码可被枚举，离线猜测就无法从密码学上消除。

### 关于 AES-128-CTR

CTR 本身没有认证，攻击者翻转密文位会让接收端得到被篡改的明文。  
本实现使用 **Encrypt-then-MAC**：先 AES-128-CTR 加密，再对规范化的格式、算法、内容类型、KDF 参数、IV 和密文计算 HMAC-SHA256。接收端先验 MAC，再解密。

如果重新设计，我会优先选 **AES-256-GCM** 或 **XChaCha20-Poly1305**，少一层自建协议；但本项目保留了 AES-128-CTR + HMAC，以满足你的要求。

---

## 2. 项目结构

```
VeriRandomSyncRelay/
├── src/
│   ├── VeriRandomSyncRelay.Crypto/   # 协议、AES-CTR、HMAC、Argon2id、会话码
│   ├── VeriRandomSyncRelay.Server/   # ASP.NET Core 10 中转服务
│   └── VeriRandomSyncRelay.Cli/      # 发送/接收命令行客户端
├── tests/
│   └── VeriRandomSyncRelay.Tests/    # 37 个单元/集成测试
├── Directory.Build.props
├── NuGet.config
├── Dockerfile
└── VeriRandomSyncRelay.slnx
```

---

## 3. 快速开始

要求：.NET SDK 10.0。

```powershell
cd D:\Source\VeriRandomSyncRelay

dotnet build VeriRandomSyncRelay.slnx -c Release
dotnet test  VeriRandomSyncRelay.slnx -c Release --no-build

# 启动服务（默认 http://localhost:5227）
dotnet run --project src/VeriRandomSyncRelay.Server -c Release
```

另开一个终端，发送一个文件：

```powershell
# 快速二维码模式：输出一个带 #fragment 密钥的配对 URL
dotnet run --project src/VeriRandomSyncRelay.Cli -c Release -- send `
  --server http://localhost:5227 `
  --file .\roster.xlsx `
  --mode quick

# 会话码模式：输出 12 位会话码和密码
dotnet run --project src/VeriRandomSyncRelay.Cli -c Release -- send `
  --server http://localhost:5227 `
  --file .\roster.xlsx `
  --mode session `
  --password "correct horse battery staple"
```

接收：

```powershell
# 快速二维码：把 send 输出的 Pairing URL 原样传入
dotnet run --project src/VeriRandomSyncRelay.Cli -c Release -- receive `
  --url "http://localhost:5227/#t=...&k=..." `
  --output .\received.xlsx

# 会话码：输入会话码，密码会交互式读取
dotnet run --project src/VeriRandomSyncRelay.Cli -c Release -- receive `
  --code "ABCD-EFGH-JKLM" `
  --output .\received.xlsx
```

> 二维码：把 `Pairing URL` 交给任意本地二维码生成器即可。不要使用会把 URL 上传到第三方的在线二维码服务，否则 fragment 中的密钥会泄露。

---

## 4. 协议

### 4.1 创建传输

```http
POST /v1/transfers
Content-Type: application/json

{
  "mode": "quick" | "session",
  "contentType": "roster" | "settings" | "all-data" | "text-library",
  "payloadLength": 12345,
  "payloadSha256": "<64 hex>",
  "sessionCodeHash": "<64 hex, 仅 session>",
  "maxDownloads": 10,
  "expiresInSeconds": 600
}
```

响应：

```json
{
  "id": "24 位 hex",
  "uploadToken": "32 字节随机值的 Base64Url",
  "expiresAt": "2026-11-22T08:21:49Z",
  "maxDownloads": 10
}
```

`payloadLength` / `payloadSha256` 针对的是**密文**，不是明文。

### 4.2 上传密文

```http
PUT /v1/transfers/{id}/payload
X-VeriRandom-Upload-Token: <uploadToken>
Content-Type: application/json

<TransferEnvelope>
```

上传成功后返回 `204 No Content`。同一条传输只能上传一次，防止分享后被替换。

### 4.3 信封格式（v3）

```json
{
  "format": "verirandom-sync-envelope/v3",
  "cipher": "aes-128-ctr-hmac-sha256",
  "content_type": "roster",
  "iv": "<16 字节 Base64Url>",
  "mac": "<32 字节 Base64Url>",
  "ciphertext": "<Base64Url>",
  "password_kdf": {
    "kdf": "argon2id",
    "salt": "<16 字节 Base64Url>",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 4
  }
}
```

- 快速二维码：`password_kdf` 为 `null`，载荷密钥在二维码 URL fragment 中。
- 会话码：`password_kdf` 必填；服务端只存储盐和参数，不持有密码或载荷密钥。
- 没有 `key_wrap` / `wrapped_key` 字段。

### 4.4 获取

```http
GET /v1/transfers/{id}
```

返回信封 JSON。响应带 `Cache-Control: no-store`。

### 4.5 会话码解析

```http
POST /v1/sessions/resolve
Content-Type: application/json

{ "sessionCodeHash": "<64 hex>" }
```

返回信封 JSON。服务端只按 SHA-256 哈希查找，不接触明文会话码。接收端还会把同一个哈希作为 MAC context，因此恶意中转不能把一个会话码的信封换到另一个会话码下。

### 4.6 撤销

```http
DELETE /v1/transfers/{id}
X-VeriRandom-Upload-Token: <uploadToken>
```

返回 `204`。过期或下载次数用尽时，记录会被自动删除。

---

## 5. 加密细节

### 5.1 快速二维码：随机载荷密钥

```
masterKey = 32 字节 CSPRNG
encKey    = HKDF-SHA256(masterKey, info="verirandom-sync/v3/enc", 16)
macKey    = HKDF-SHA256(masterKey, info="verirandom-sync/v3/mac", 32)
```

配对 URL：

```
https://relay.example/#t=<transferId>&k=<Base64Url(masterKey)>
```

fragment 不会随 HTTP 请求发送给服务端。

### 5.2 会话码：密码直接派生

```
salt      = 16 字节 CSPRNG
masterKey = Argon2id(password, salt, memory=64 MiB, iterations=3, parallelism=4, 32 字节)
encKey    = HKDF-SHA256(masterKey, info="verirandom-sync/v3/enc", 16)
macKey    = HKDF-SHA256(masterKey, info="verirandom-sync/v3/mac", 32)
```

- 没有 wrapped key，服务端只存 `salt` 和 Argon2 参数。
- 改密码必须重新加密并重新上传；不能只换密码而不重加密。
- 同一密码在不同传输中使用不同盐，因此派生密钥不同。

### 5.3 载荷加密与认证

```
iv         = 16 字节 CSPRNG
ciphertext = AES-128-CTR(encKey, iv, plaintext)
mac        = HMAC-SHA256(macKey, canonical(
                 format, cipher, contentType,
                 "raw" 或 "argon2id" + salt + memory + iterations + parallelism,
                 iv,
                 context,        // 会话码哈希；快速二维码为空
                 ciphertext))
```

接收端先校验 MAC，再解密。MAC 覆盖 KDF 参数，因此篡改盐或 Argon2 参数会导致认证失败。会话码模式还把 **会话码的 SHA-256 哈希**作为 `context` 绑定进 MAC：即使两个传输复用同一个密码，恶意中转也无法把一个会话码的信封换到另一个会话码下（接收端用不同 context 校验会失败）。

### 5.4 会话码

- 12 位，字符集 `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`（去掉 I/O/0/1）。
- 仅作为服务端查找键：`sessionCodeHash = SHA-256(normalizedCode)`。
- 密码与载荷密钥都不会以明文形式到达服务端。

---

## 6. 服务端限制与防护

| 项目 | 默认值 |
|---|---|
| 密文上限 | 1 MiB |
| JSON 信封上限 | 2 MiB（Base64 膨胀） |
| 默认 TTL | 600 秒 |
| TTL 范围 | 30–3600 秒 |
| 默认下载次数 | 10 |
| 最大下载次数 | 100 |
| 单进程总存储 | 256 MiB |
| 最大传输数 | 10,000 |
| 创建速率 | 30 次/分钟/IP |
| 解析速率 | 60 次/分钟/IP |
| 上传速率 | 120 次/分钟/IP |

其他防护：

- 上传 token 只存 SHA-256，使用常量时间比较。
- 上传后不可覆盖（409），防止分享后替换载荷。
- 过期清理后台服务每 30 秒运行一次；下载次数用尽立即删除。
- 请求体硬限制 + 流式读取限制，避免内存耗尽。
- 服务端不解密、不记录密码、不记录会话码明文、不记录 URL fragment。
- 响应带 `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`。
- 默认不强制 HTTPS，便于本地开发；生产环境必须设置 `Relay:RequireHttps=true` 并放在 TLS 反向代理后。

---

## 7. 配置

`src/VeriRandomSyncRelay.Server/appsettings.json`：

```json
{
  "Relay": {
    "MaxPayloadBytes": 1048576,
    "MaxEnvelopeBytes": 2097152,
    "DefaultTtlSeconds": 600,
    "MinTtlSeconds": 30,
    "MaxTtlSeconds": 3600,
    "DefaultMaxDownloads": 10,
    "MaxDownloads": 100,
    "MaxTotalBytes": 268435456,
    "MaxTransfers": 10000,
    "CleanupIntervalSeconds": 30,
    "RequireHttps": false
  }
}
```

也可以用环境变量覆盖：

```powershell
$env:Relay__MaxPayloadBytes = "1048576"
$env:Relay__RequireHttps = "true"
dotnet run --project src/VeriRandomSyncRelay.Server -c Release
```

---

## 8. 测试

```powershell
dotnet test VeriRandomSyncRelay.slnx -c Release
```

当前 **37 个测试全部通过**，覆盖：

- NIST SP 800-38A F.5.1 AES-128-CTR 测试向量；
- 快速二维码 / 会话码信封往返；
- 密码直接派生、错误密码拒绝；
- 密文、MAC、内容类型、Argon2 盐/参数篡改检测；
- Argon2 参数滥用拒绝；
- 服务端创建/上传/获取/会话解析/撤销；
- token 错误、重复上传、过期、下载次数、容量、1 MiB 上限；
- `WebApplicationFactory` HTTP 端到端集成。

---

## 9. 生产部署注意事项

1. **必须使用 HTTPS**。虽然载荷是端到端加密的，TLS 仍保护元数据、可用性和上传 token。
2. **不要把内存存储当持久队列**。进程重启会丢失所有传输；需要持久化时换成 Redis/数据库，并保留 TTL、单次上传、下载计数语义。
3. **反向代理要正确传递真实 IP**，否则限流会把所有客户端当成同一个 IP。只在可信代理后启用 `ForwardedHeaders`，不要默认信任任意代理。
4. **不要记录 URL fragment**。fragment 不会到达服务端，但如果反向代理/网关记录了完整 URL，要确认没有把客户端侧的 URL 拼进去。
5. **密码策略**。会话码模式的密码至少 12 位，最好使用客户端生成的高熵密码。Argon2id 不能把弱密码变成强密码。命令行 `--password` 可能出现在进程列表或 shell 历史中；发送时省略它会自动生成密码，接收时省略它会交互式读取。
6. **服务端仍可拒绝服务**。匿名中转无法阻止攻击者大量创建传输；生产环境应加配额、验证码、账号或边缘防护。
7. **直接派生 = 改密码要重加密**。没有 wrapped key，就无法只换密码而不重加密载荷；需要换密码时，重新发起一次传输。
8. **升级路径**。`format` / `cipher` 字段已经预留；未来切换 AES-256-GCM 或 XChaCha20-Poly1305 时可以并存一段时间。

---

## 10. 与旧版中转实现的差异

| 维度 | 旧版中转（AES-256-GCM） | 本项目 |
|---|---|---|
| 载荷加密 | AES-256-GCM | AES-128-CTR + HMAC-SHA256 |
| 会话码 KDF | PBKDF2-SHA256（600k） | Argon2id（默认 64 MiB/3/4） |
| 会话码角色 | 查找键 + 密钥材料 | 仅查找键 |
| 密码 | 无独立密码 | 独立密码，直接派生载荷密钥 |
| 服务端可见密钥材料 | 快速二维码：无；会话码：仅哈希 | 快速二维码：无；会话码：盐 + 密文 |
| 服务端离线猜测 | 会话码哈希可验证，但 60-bit | 可用“解密 + MAC 校验”验证密码猜测 |
| 改密码 | 重新生成会话码 | 必须重新加密并重新上传 |
| 1 MiB 上限 | 是 | 是 |
| 上传后不可覆盖 | 现有实现未强制 | 是（409） |
| 下载次数限制 | 否 | 是 |
| 主动撤销 | 是 | 是 |
| 认证 | 匿名 | 匿名 |

---

## 11. 代码入口

- 加密/协议：`src/VeriRandomSyncRelay.Crypto/EnvelopeCrypto.cs`、`AesCtr.cs`、`SessionCode.cs`
- 服务端：`src/VeriRandomSyncRelay.Server/Program.cs`、`RelayStore.cs`、`RelayOptions.cs`
- 客户端：`src/VeriRandomSyncRelay.Cli/Program.cs`
- 测试：`tests/VeriRandomSyncRelay.Tests/`

---

## 12. 云端 CI

GitHub Actions 工作流位于 `.github/workflows/ci.yml`，在 `push`、`pull_request` 和手动触发时运行：

- `ubuntu-latest` + .NET SDK `10.0.x`；
- `dotnet restore` / `dotnet build -c Release`；
- `dotnet test`，并上传 TRX 测试结果；
- 发布服务端产物并上传 artifact；
- 构建 Docker 镜像，验证 `Dockerfile` 可用。

---

## 13. 许可证

Copyright (C) 2026 WinFunan.

本项目采用 **GNU Affero General Public License v3.0 or later（AGPL-3.0-or-later）**。

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

完整许可证文本见 `LICENSE`。

