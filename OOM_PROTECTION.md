# ⚠️ OOM 防护说明

## 问题描述

在使用 `-C` 功能时，如果配置文件中定义了过多的 methods、URIs 和 header 值，会导致生成的 payload 数量呈**指数级增长**，最终导致系统内存耗尽（OOM - Out of Memory）。

## 实际案例

一个看似合理的配置文件：
```ini
[methods]
GET, POST, PUT, DELETE (4个)

[uris]
5个不同的URI

[headers]
Host: 3个值
User-Agent: 3个值
Accept: 3个值
Accept-Language: 2个值
Accept-Encoding: 1个值
Content-Type: 2个值
Authorization: 2个值
Connection: 1个值
```

**计算结果**：
- 4 × 5 × 3 × 3 × 3 × 2 × 1 × 2 × 2 × 1 = **12,960 个 payload**
- 每个 payload 约 6KB
- 总内存占用：**约 78 MB**

如果再增加一些值，很容易就会超过 **10 万个 payload**，占用 **600 MB** 内存。

更极端的情况下，可能生成数百万个 payload，导致系统 OOM。

## 已实施的保护措施

### 1. 最大 Payload 数量限制

程序现在会检查将要生成的 payload 总数，如果超过 **100,000 个**，会拒绝启动并显示错误信息：

```
ERROR: Too many payloads (1234567) would be generated from config
ERROR: Maximum allowed is 100000 payloads (approx 600.0 MB memory)
ERROR: Please reduce the number of methods/URIs/header values in your config
```

### 2. 内存占用提示

程序启动时会显示预计的内存占用：

```
Generating 12960 payloads from config file (approx 78.0 MB memory)
```

## 如何避免 OOM

### 计算公式

**总 payload 数 = methods数 × URIs数 × (每个header的值数量的乘积)**

### 推荐配置规模

| 场景 | Payload 数量 | 内存占用 | 配置建议 |
|------|-------------|---------|---------|
| 测试环境 | 50 - 500 | < 3 MB | 2-3 methods, 5-10 URIs, 每个header 2-3个值 |
| 生产环境 | 500 - 5,000 | 3-30 MB | 3-5 methods, 10-20 URIs, 每个header 2-4个值 |
| 高级场景 | 5,000 - 50,000 | 30-300 MB | 5-10 methods, 20-50 URIs, 每个header 3-5个值 |
| **危险区域** | > 100,000 | > 600 MB | ⚠️ 会被拒绝 |

### 优化建议

1. **减少 header 的值数量**
   - 每个 header 的值数量对总数影响最大
   - 例如：5个header各有5个值 = 5^5 = 3,125 倍增长

2. **合理选择 methods**
   - 只包含真正需要的 HTTP 方法
   - 通常 GET + POST 就足够了

3. **精简 URIs**
   - 选择代表性的 URI 路径
   - 避免列举所有可能的路径

4. **分批配置**
   - 如果需要大量变化，考虑创建多个配置文件
   - 分别运行多个实例

## 安全配置示例

### 小规模配置（推荐）
```ini
[methods]
GET
POST

[uris]
/api/v1/data
/api/v2/info

[headers]
Host: api.example.com
Host: api2.example.com
User-Agent: Mozilla/5.0
User-Agent: curl/7.68.0
Accept: application/json

[body]
{"test":"data"}
```

**结果**：2 × 2 × 2 × 2 × 1 = **16 个 payload** (约 96 KB)

### 中等规模配置
```ini
[methods]
GET
POST
PUT

[uris]
/api/v1/users
/api/v1/products
/api/v1/orders
/api/v2/analytics

[headers]
Host: api1.example.com
Host: api2.example.com
Host: api3.example.com
User-Agent: Mozilla/5.0 (Windows)
User-Agent: Mozilla/5.0 (Mac)
Accept: application/json
Accept: application/xml
Content-Type: application/json

[body]
{"data":"test"}
```

**结果**：3 × 4 × 3 × 2 × 2 × 1 = **144 个 payload** (约 864 KB)

## 检查你的配置

在运行前，先计算一下：

```bash
# 假设你的配置是：
# 3 methods × 5 URIs × 2 hosts × 2 user-agents × 2 accepts = ?

# 计算：3 × 5 × 2 × 2 × 2 = 120 个 payload
# 内存：120 × 6KB ≈ 720 KB ✅ 安全

# 如果是：
# 5 methods × 20 URIs × 5 hosts × 5 UAs × 5 accepts × 3 langs = ?
# 计算：5 × 20 × 5 × 5 × 5 × 3 = 37,500 个 payload
# 内存：37,500 × 6KB ≈ 225 MB ⚠️ 可用但较大

# 如果是：
# 10 methods × 50 URIs × 10 hosts × 10 UAs × 10 accepts = ?
# 计算：10 × 50 × 10 × 10 × 10 = 500,000 个 payload
# 内存：500,000 × 6KB ≈ 3 GB ❌ 会被拒绝！
```

## 修改限制

如果你确实需要更多的 payload，可以修改源代码中的限制：

在 `src/payload.c` 中找到：
```c
const size_t MAX_PAYLOAD_COUNT = 100000; /* 最多 10 万个，防止 OOM */
```

修改为更大的值（风险自负）：
```c
const size_t MAX_PAYLOAD_COUNT = 500000; /* 50 万个，约 3GB 内存 */
```

然后重新编译：
```bash
make clean && make
```

## 监控内存使用

运行时可以使用以下命令监控内存：

```bash
# 查看进程内存占用
ps aux | grep fakehttp

# 实时监控
top -p $(pgrep fakehttp)

# 或使用 htop
htop -p $(pgrep fakehttp)
```

## 总结

- ✅ 使用小到中等规模的配置（< 10,000 个 payload）
- ✅ 在运行前计算预期的 payload 数量
- ✅ 注意程序启动时的内存占用提示
- ⚠️ 避免每个 header 都有大量的值
- ❌ 不要创建会生成超过 10 万个 payload 的配置
- 💡 如果需要大量变化，考虑使用多个配置文件分批运行

