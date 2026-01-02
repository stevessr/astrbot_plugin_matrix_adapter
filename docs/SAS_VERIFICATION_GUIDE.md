# Matrix SAS 设备验证指南

本指南介绍当其他客户端（如 Element、FluffyChat 等）发起 SAS 验证时，如何操作 AstrBot Matrix 机器人。

## 什么是 SAS 验证？

SAS（Short Authentication String）是 Matrix 端到端加密中用于验证设备身份的安全机制。通过对比双方显示的 emoji 或数字，确保您正在与正确的设备通信，而非中间人攻击者。

## 前提条件

在进行设备验证之前，请确保：

1. **启用了 E2EE**：在配置中设置 `matrix_enable_e2ee: true`
2. **安装了 vodozemac**：运行 `pip install vodozemac`
3. **机器人已正常运行**：机器人已成功登录并在同步消息

## 配置选项

### 自动验证模式 (`matrix_e2ee_auto_verify`)

机器人支持三种自动验证模式：

| 模式 | 说明 | 推荐场景 |
|------|------|---------|
| `auto_accept` | 自动接受所有验证请求 | 个人使用、受信任环境 |
| `auto_reject` | 自动拒绝所有验证请求 | 高安全需求、不需要验证 |
| `manual` | 记录请求但不自动响应 | 需要人工审核 |

### 首次使用信任 (`matrix_e2ee_trust_on_first_use`)

- `true`：自动信任首次见到的设备（TOFU 模式）
- `false`：只信任经过完整验证的设备

## 从客户端发起验证

### 使用 Element 客户端

1. **打开与机器人的聊天**
   - 在 Element 中找到机器人用户
   - 点击进入私聊房间

2. **访问设备信息**
   - 点击右上角的房间信息图标（i）
   - 点击成员列表中的机器人用户名
   - 点击"安全"或"设备"选项

3. **发起验证**
   - 找到机器人的设备（设备名通常为 "AstrBot"）
   - 点击"验证"按钮
   - 选择"从这里开始验证"

4. **完成验证**

   根据机器人的配置模式，验证流程会有所不同：

   **如果配置为 `auto_accept`：**
   - 机器人会自动响应验证请求
   - Element 会显示 7 个 emoji
   - 机器人日志中也会显示相同的 emoji：
     ```
     [E2EE-Verify] ===== SAS 验证码 (使用 vodozemac) =====
     [E2EE-Verify] Emoji: 🐶 🌳 🔥 🎂 ✈️ 🎸 📌
     [E2EE-Verify] Emoji 名称：Dog, Tree, Fire, Cake, Aeroplane, Guitar, Pin
     [E2EE-Verify] 数字：1234 5678 9012
     [E2EE-Verify] ==========================================
     ```
   - 如果 emoji 匹配，在 Element 中点击"匹配"
   - 验证完成

   **如果配置为 `manual`：**
   - 机器人会记录验证请求但不响应
   - 需要管理员手动处理（当前版本暂不支持手动确认）
   - 建议使用 `auto_accept` 模式

   **如果配置为 `auto_reject`：**
   - 机器人会自动拒绝验证请求
   - Element 会显示验证被取消

### 使用 FluffyChat 客户端

1. 打开与机器人的聊天
2. 点击机器人头像
3. 选择"设备"
4. 点击需要验证的设备
5. 选择"验证"
6. 按照屏幕提示完成验证

### 使用 Nheko 客户端

1. 打开与机器人的私聊
2. 点击房间设置
3. 选择"成员"标签
4. 右键点击机器人用户
5. 选择"验证"
6. 按照提示完成 SAS 验证

## 验证日志解读

机器人运行时会输出详细的验证日志，帮助您了解验证状态：

### 收到验证请求
```
[E2EE-Verify] 收到验证请求：sender=@user:server.com device=DEVICEID methods=['m.sas.v1']
```

### 自动接受验证
```
[E2EE-Verify] 自动接受验证请求 (mode=auto_accept)
[E2EE-Verify] 已发送 ready
```

### 密钥交换
```
[E2EE-Verify] 收到对方公钥：ABC123...
[E2EE-Verify] 已发送 key: XYZ789...
```

### SAS 验证码显示
```
[E2EE-Verify] ===== SAS 验证码 (使用 vodozemac) =====
[E2EE-Verify] Emoji: 🐶 🐱 🦁 🐴 🦄 🐷 🐘
[E2EE-Verify] Emoji 名称：Dog, Cat, Lion, Horse, Unicorn, Pig, Elephant
[E2EE-Verify] 数字：1234 5678 9012
[E2EE-Verify] ==========================================
```

### 验证完成
```
[E2EE-Verify] 已发送 mac
[E2EE-Verify] 已发送 done
[E2EE-Verify] ✅ 验证完成！sender=@user:server.com txn=abc123...
[E2EE-Verify] Device verified and saved: @user:server.com|DEVICEID
```

### 验证取消
```
[E2EE-Verify] ❌ 验证被取消：code=m.user reason=用户取消
```

## 房间内验证 vs 设备间验证

Matrix 支持两种验证方式：

### 设备间验证（To-Device）
- 通过私密的设备间消息进行
- 不会在房间中留下痕迹
- 适合大多数场景

### 房间内验证（In-Room）
- 验证消息发送在房间内
- 其他房间成员可以看到验证正在进行
- 某些客户端默认使用此方式

机器人同时支持这两种验证方式，会自动识别并正确响应。

## 常见问题

### Q: 验证请求没有响应？

**可能原因：**
1. 机器人配置为 `manual` 模式
2. E2EE 未正确初始化
3. vodozemac 未安装

**解决方法：**
1. 检查日志确认 E2EE 是否初始化成功：
   ```
   E2EE 初始化成功 (device_id: XXXXX)
   ```
2. 确认 vodozemac 已安装：
   ```bash
   pip install vodozemac
   ```
3. 将 `matrix_e2ee_auto_verify` 设置为 `auto_accept`

### Q: Emoji 不匹配怎么办？

如果您看到的 emoji 与机器人日志中显示的不同，**请勿确认验证**。这可能表示：
1. 存在中间人攻击
2. 网络问题导致消息损坏
3. 客户端 bug

建议取消验证并重新尝试。

### Q: 如何重新验证设备？

1. 在客户端中取消对机器人设备的信任
2. 重新发起验证请求
3. 机器人会再次响应新的验证请求

### Q: 验证后仍然无法解密消息？

验证设备后，可能还需要：
1. 等待密钥同步（几秒钟）
2. 重新发送无法解密的消息
3. 如果启用了密钥备份，从备份恢复密钥

### Q: 收到 "unknown one-time key" 错误？

这个错误表示客户端使用了一个旧的一次性密钥来加密消息，但这个密钥不在机器人账户中。

**常见原因：**
1. 机器人的 Olm 账户被重新创建（例如更换了 device_id 或删除了 E2EE 存储）
2. 客户端缓存了旧的设备密钥信息
3. 一次性密钥已被其他会话使用

**机器人会自动处理：**
当检测到此错误时，机器人会：
1. 自动查找对应的设备
2. Claim 对方的新一次性密钥
3. 创建新的 Olm 会话
4. 发送加密的 m.dummy 消息通知对方

日志中会显示：
```
[E2EE] 尝试与 @user:server/DEVICE 建立新的 Olm 会话
[E2EE] 成功创建与 @user:server/DEVICE 的新 Olm 会话
[E2EE] 已向 @user:server/DEVICE 发送加密的 m.dummy，新会话已建立
```

**如果问题持续：**
1. 在客户端（如 FluffyChat/Element）中，进入设置 → 安全 → 会话
2. 找到与机器人的加密会话并删除它
3. 重新发送消息，客户端会自动建立新会话

### Q: 如何查看已验证的设备？

已验证的设备信息存储在 E2EE 存储目录下的 `devices.json` 文件中：
```
{store_path}/{homeserver_hash}/{user_hash}/devices.json
```

## 安全建议

1. **生产环境**：建议使用 `auto_accept` + `trust_on_first_use: false`
2. **个人使用**：可以使用 `auto_accept` + `trust_on_first_use: true`
3. **高安全需求**：等待未来版本支持 `manual` 模式的手动确认功能

## 配置示例

```yaml
# 推荐的安全配置
matrix_enable_e2ee: true
matrix_e2ee_auto_verify: auto_accept
matrix_e2ee_trust_on_first_use: false
matrix_e2ee_key_backup: true
matrix_e2ee_recovery_key: "您的恢复密钥（Base58 格式）"

# 个人使用的便捷配置
matrix_enable_e2ee: true
matrix_e2ee_auto_verify: auto_accept
matrix_e2ee_trust_on_first_use: true
matrix_e2ee_key_backup: true
```

## 技术细节

SAS 验证使用以下加密算法：
- **密钥协商**：X25519（Curve25519-based ECDH）
- **哈希算法**：SHA-256
- **MAC 算法**：HKDF-HMAC-SHA256.v2
- **SAS 显示**：7 个 emoji 或 3 组 4 位数字

验证流程：
1. 请求方发送 `m.key.verification.request`
2. 响应方发送 `m.key.verification.ready`
3. 请求方发送 `m.key.verification.start`
4. 响应方发送 `m.key.verification.accept`（包含 commitment）
5. 双方交换 `m.key.verification.key`（公钥）
6. 双方计算并显示 SAS
7. 用户确认 SAS 匹配
8. 双方交换 `m.key.verification.mac`（验证密钥签名）
9. 双方发送 `m.key.verification.done`

---

如有问题，请查看机器人日志或在 GitHub 仓库提交 Issue。
