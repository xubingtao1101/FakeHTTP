# 限制参数扩大说明

## 修改概述

所有与 `-C` 功能相关的限制和 buffer 大小已经扩大为原来的 **3倍**，以支持更大规模的配置文件和更多的 payload 生成。

## 详细修改对比

### 1. 配置文件解析限制

| 参数 | 原值 | 新值 | 倍数 |
|------|------|------|------|
| MAX_METHODS | 10 | 30 | 3x |
| MAX_URIS | 100 | 300 | 3x |
| MAX_HEADERS | 50 | 150 | 3x |
| MAX_HEADER_VALUES | 20 | 60 | 3x |
| MAX_LINE_LENGTH | 4096 字节 | 12288 字节 (12KB) | 3x |
| MAX_BODY_SIZE | 8192 字节 | 24576 字节 (24KB) | 3x |

### 2. Payload 存储 Buffer

| 参数 | 原值 | 新值 | 倍数 |
|------|------|------|------|
| BUFFLEN (payload.c) | 2000 字节 | 6000 字节 | 3x |

## 实际影响

### 最大 Payload 数量计算

假设使用最大限制：
- 30 个 methods
- 300 个 uris
- 每个 header 有 60 个值
- 假设有 10 个不同的 headers

理论最大 payload 数量 = 30 × 300 × 60^10 = **约 5.4 × 10^20 个**

**注意**：实际使用中不建议生成如此大量的 payload，建议控制在合理范围内（如几千到几万个）。

### 实用配置示例

#### 小规模配置（推荐用于测试）
- 3 methods × 5 uris × 2 hosts × 2 user-agents = **60 个 payload**

#### 中等规模配置（推荐用于生产）
- 5 methods × 20 uris × 3 hosts × 3 user-agents × 2 accepts = **1,800 个 payload**

#### 大规模配置（高级用户）
- 10 methods × 50 uris × 5 hosts × 4 user-agents × 3 accepts = **30,000 个 payload**

## 内存占用估算

每个 payload 节点占用内存：
- payload buffer: 6000 字节
- payload_len: 8 字节
- next 指针: 8 字节
- **总计约 6KB per payload**

不同规模的内存占用：
- 60 个 payload: ~360 KB
- 1,800 个 payload: ~10.8 MB
- 30,000 个 payload: ~180 MB

## 性能建议

1. **启动时间**：payload 数量越多，初始化时间越长
2. **内存使用**：建议在内存充足的系统上使用大规模配置
3. **轮询效率**：所有 payload 会被打乱成随机顺序，轮流使用

## 配置文件示例

### 接近限制的大型配置示例

```ini
[methods]
GET
POST
PUT
DELETE
PATCH
HEAD
OPTIONS
CONNECT
TRACE

[uris]
/api/v1/users
/api/v1/products
/api/v1/orders
# ... 可以添加最多 300 个 URI

[headers]
Host: api1.example.com
Host: api2.example.com
Host: api3.example.com
# ... 每个 header 可以有最多 60 个不同的值
# ... 可以有最多 150 个不同的 header 名称

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
# ... 最多 60 个不同的 User-Agent

Accept: application/json
Accept: application/xml
Accept: text/html
# ... 最多 60 个不同的 Accept

[body]
# 可以包含最多 24KB 的内容
{"very":"large","json":"payload","with":"many","fields":"..."}
```

## 错误处理

如果超出限制，程序会输出清晰的错误信息：

```
ERROR: Line 35: Too many methods (max 30)
ERROR: Line 120: Too many URIs (max 300)
ERROR: Line 200: Too many headers (max 150)
ERROR: Line 85: Too many values for header Host (max 60)
ERROR: Line 250: Body too large (max 24576 bytes)
```

## 修改的文件

1. **include/config_parser.h** - 更新宏定义
2. **src/config_parser.c** - 更新宏定义
3. **src/payload.c** - 扩大 BUFFLEN
4. **CONFIG_C_USAGE.md** - 更新文档说明
5. **REFACTOR_SUMMARY.md** - 更新文档说明

## 验证方法

编译并运行：
```bash
make clean && make
./build/fakehttp -i lo -C your_large_config.conf
```

查看日志输出，确认生成的 payload 数量：
```
Config loaded: X methods, Y URIs, Z headers
Generating N payloads from config file
```

## 注意事项

1. **内存限制**：确保系统有足够的内存来存储所有 payload
2. **启动时间**：大量 payload 的生成和打乱需要时间
3. **实际需求**：根据实际使用场景选择合适的配置规模
4. **测试建议**：先用小规模配置测试，确认无误后再扩大规模

## 后续优化建议

如果需要更大的限制，可以考虑：
1. 使用动态内存分配而不是固定数组
2. 实现 payload 的延迟生成（按需生成）
3. 使用文件缓存机制存储 payload
4. 实现 payload 的压缩存储

