# -C 功能重构说明

## 概述

已成功将 `-C` 选项从原来的 "TLS client hello payload" 功能重构为 "基于配置文件生成 HTTP payload" 功能。

## 新增文件

### 核心代码文件
1. **src/config_parser.c** - 配置文件解析器实现
2. **include/config_parser.h** - 配置文件解析器头文件

### 文档和示例文件
3. **CONFIG_C_USAGE.md** - 详细的使用说明文档
4. **config_example.conf** - 基础配置文件示例
5. **test_config.conf** - 简单测试配置（生成 16 个 payload）
6. **advanced_config.conf** - 高级配置示例（模拟真实 API 请求）

## 修改的文件

1. **include/payload.h**
   - 将 `FH_PAYLOAD_TLS_CLIENT_HELLO` 改为 `FH_PAYLOAD_HTTP_CONFIG`

2. **src/payload.c**
   - 添加 `#include "config_parser.h"`
   - 在 `fh_payload_setup()` 中添加 `FH_PAYLOAD_HTTP_CONFIG` 的处理逻辑
   - 移除了原来的 `FH_PAYLOAD_TLS_CLIENT_HELLO` 处理

3. **src/mainfun.c**
   - 更新帮助信息，将 `-C <hostname>` 改为 `-C <config_file>`
   - 添加 `-C` 只能使用一次的检查逻辑
   - 更新选项处理，将 `-C` 映射到 `FH_PAYLOAD_HTTP_CONFIG`

## 功能特性

### 1. 配置文件格式
采用 INI 风格的配置文件，包含四个部分：
- `[methods]` - HTTP 方法列表
- `[uris]` - URI 路径列表
- `[headers]` - HTTP 头部（支持同名 header 多个值）
- `[body]` - 请求体（可选）

### 2. 智能 Payload 生成
- 自动组合所有可能的 methods、uris 和 headers 值
- 根据 HTTP 方法自动决定是否添加 body（GET 不加，POST/PUT 加）
- 自动计算并添加 Content-Length header
- 支持同一个 header 的多个值轮流使用

### 3. 安全性和稳定性
- 完整的错误处理和输入验证
- 配置文件格式验证
- 必需字段检查（至少一个 Host header）
- 资源限制保护：
  - 最多 30 个 methods
  - 最多 300 个 uris
  - 最多 150 个不同的 headers
  - 每个 header 最多 60 个值
  - body 最大 24576 字节（24KB）
  - 每行最大 12288 字符（12KB）
  - 单个 payload 最大 6000 字节

### 4. 使用限制
- `-C` 选项只能使用一次（多次使用会报错）
- 确保不会与其他 payload 选项冲突

## 使用示例

### 基础用法
```bash
sudo ./fakehttp -i eth0 -C config_example.conf
```

### 与其他选项组合
```bash
# 指定网卡和队列号
sudo ./fakehttp -i eth0 -C test_config.conf -n 100

# 仅处理出站连接
sudo ./fakehttp -i eth0 -C test_config.conf -1

# 仅处理 IPv4
sudo ./fakehttp -i eth0 -C test_config.conf -4
```

## Payload 生成逻辑

假设配置文件包含：
- 3 个 methods (GET, POST, PUT)
- 2 个 uris
- Host 有 2 个值
- User-Agent 有 2 个值

则会生成：3 × 2 × 2 × 2 = 24 个不同的 payload

每个 payload 会根据 index 选择不同的组合：
- `index % method_count` 选择 method
- `(index / method_count) % uri_count` 选择 uri
- `(index / (method_count * uri_count)) % value_count` 选择每个 header 的值

## 编译说明

无需修改 Makefile，新添加的 `config_parser.c` 会自动被包含在编译过程中。

```bash
# 正常编译
make clean && make

# 调试编译
make clean && make debug

# 静态编译
make clean && make STATIC=1
```

## 测试建议

1. **基础功能测试**
   ```bash
   sudo ./fakehttp -i lo -C test_config.conf
   ```

2. **验证 payload 生成**
   - 检查日志输出，确认生成了正确数量的 payload
   - 使用 tcpdump 抓包验证生成的 HTTP 请求格式

3. **错误处理测试**
   - 测试不存在的配置文件
   - 测试格式错误的配置文件
   - 测试缺少 Host header 的配置
   - 测试多次使用 `-C` 选项

4. **边界条件测试**
   - 测试最大数量的 methods/uris/headers
   - 测试最大长度的 body
   - 测试空配置文件

## 兼容性说明

- 原有的 `-c` 选项（custom/random HTTP payload）功能保持不变
- 其他所有选项（-b, -e, -h, -v, -F）功能不受影响
- 如果需要 TLS client hello 功能，可以使用 `-e` 选项

## 注意事项

1. 配置文件路径可以是相对路径或绝对路径
2. 配置文件必须可读
3. 注释行以 `#` 或 `;` 开头
4. Header 名称不区分大小写（Host = host = HOST）
5. URI 必须以 `/` 开头
6. Body 部分可以是多行内容

## 后续优化建议

1. 支持从环境变量或命令行参数中替换配置文件中的占位符
2. 支持更多的 HTTP 方法（如 CONNECT, TRACE）
3. 支持正则表达式生成动态 URI
4. 支持从文件读取 body 内容
5. 添加配置文件语法检查工具
6. 支持 JSON 或 YAML 格式的配置文件

## 问题排查

如果遇到问题，请检查：
1. 配置文件格式是否正确
2. 是否包含必需的 Host header
3. URI 是否以 `/` 开头
4. HTTP 方法名是否正确（大写）
5. 是否超出了各项限制
6. 查看程序输出的错误信息和行号

