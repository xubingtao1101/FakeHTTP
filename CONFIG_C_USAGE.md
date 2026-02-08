# -C 选项使用说明

## 功能概述

新的 `-C` 选项允许你通过配置文件来定义 HTTP 请求的各个部分，程序会根据配置文件自动生成多种不同的 payload 组合。

## 配置文件格式

配置文件采用 INI 风格的格式，包含以下几个部分：

### 1. [methods] - HTTP 方法

定义要使用的 HTTP 方法，每行一个。支持的方法包括：
- GET
- POST
- PUT
- DELETE
- HEAD
- OPTIONS
- PATCH

示例：
```ini
[methods]
GET
POST
PUT
```

### 2. [uris] - URI 路径

定义要请求的 URI 路径，每行一个。URI 必须以 `/` 开头。

示例：
```ini
[uris]
/api/v1/data
/api/v2/users
/resource/info
```

### 3. [headers] - HTTP Headers

定义 HTTP 请求头，格式为 `Header-Name: value`。

**重要特性：**
- 相同的 header 名可以出现多次，程序会在不同的 payload 中轮流使用这些值
- **至少需要一个 Host header**（必需）
- 其他 header 如 User-Agent、Accept 等都是可选的

示例：
```ini
[headers]
Host: example.com
Host: api.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
User-Agent: curl/7.68.0
Accept: application/json
Accept: */*
Content-Type: application/json
```

### 4. [body] - 请求体

定义请求体内容（可选）。

**注意：**
- 只有 POST、PUT、PATCH 等需要 body 的方法才会使用这部分内容
- GET、HEAD、OPTIONS 等方法会自动忽略 body
- 可以是多行内容
- 程序会自动计算并添加 Content-Length header

示例：
```ini
[body]
{"key":"value","data":"test"}
```

## Payload 生成规则

程序会根据配置文件生成所有可能的组合：

**总 payload 数量 = methods 数量 × uris 数量 × 每个 header 的值数量的乘积**

例如，如果配置文件中有：
- 3 个 methods (GET, POST, PUT)
- 3 个 uris
- Host 有 2 个值
- User-Agent 有 2 个值
- Accept 有 2 个值

则总共会生成：3 × 3 × 2 × 2 × 2 = 72 个不同的 payload

## 使用示例

1. 创建配置文件 `http_config.conf`：

```ini
[methods]
GET
POST

[uris]
/api/data
/api/users

[headers]
Host: example.com
Host: api.example.com
User-Agent: Mozilla/5.0
Accept: application/json

[body]
{"test":"data"}
```

2. 运行 FakeHTTP：

```bash
sudo ./fakehttp -i eth0 -C http_config.conf
```

## 注意事项

1. **-C 选项只能使用一次**：如果多次指定 -C，程序会报错
2. **必须包含 Host header**：配置文件中至少要有一个 Host header
3. **自动处理 Content-Length**：对于需要 body 的方法，程序会自动计算并添加 Content-Length
4. **方法与 body 的匹配**：
   - GET、HEAD、OPTIONS 等方法不会包含 body
   - POST、PUT、PATCH 等方法会包含 body（如果配置文件中定义了）
5. **配置文件大小限制**：
   - 最多 10 个 methods
   - 最多 100 个 uris
   - 最多 50 个不同的 headers
   - 每个 header 最多 20 个不同的值
   - body 最大 8192 字节

## 错误处理

程序会进行以下验证：
- 配置文件是否存在且可读
- 配置文件格式是否正确
- 是否包含必需的 Host header
- HTTP 方法是否有效
- URI 是否以 `/` 开头
- 是否超出各项限制

如果发现任何错误，程序会输出详细的错误信息并退出。

## 完整示例

参见项目根目录下的 `config_example.conf` 文件。

