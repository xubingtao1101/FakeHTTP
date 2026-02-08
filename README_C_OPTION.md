# FakeHTTP -C 功能使用指南

## 📖 快速开始

### 1. 创建配置文件

创建一个名为 `my_config.conf` 的文件：

```ini
[methods]
GET
POST

[uris]
/api/test
/api/data

[headers]
Host: example.com
Host: api.example.com
User-Agent: Mozilla/5.0
Accept: application/json

[body]
{"test":"data"}
```

### 2. 检查配置（可选但推荐）

```bash
./check_config.sh my_config.conf
```

这会显示将要生成多少个 payload 和预计内存占用。

### 3. 运行 FakeHTTP

```bash
sudo ./build/fakehttp -i eth0 -C my_config.conf
```

## 📚 完整文档

| 文档 | 说明 |
|------|------|
| [CONFIG_C_USAGE.md](CONFIG_C_USAGE.md) | 详细的使用说明和配置格式 |
| [OOM_PROTECTION.md](OOM_PROTECTION.md) | OOM 防护机制和安全建议 |
| [LIMITS_UPDATE.md](LIMITS_UPDATE.md) | 所有限制参数的详细说明 |
| [REFACTOR_SUMMARY.md](REFACTOR_SUMMARY.md) | 重构总结和技术细节 |
| [COMPLETION_SUMMARY.md](COMPLETION_SUMMARY.md) | 完成情况总结 |
| [QUICK_REFERENCE.txt](QUICK_REFERENCE.txt) | 快速参考卡片 |

## 📝 配置文件示例

| 文件 | 说明 | Payload 数量 |
|------|------|-------------|
| [config_example.conf](config_example.conf) | 基础示例 | ~16 个 |
| [test_config.conf](test_config.conf) | 测试配置 | ~16 个 |
| [advanced_config.conf](advanced_config.conf) | 高级配置 | ~360 个 |

## ⚠️ 重要提示

### Payload 数量计算

**总数 = methods × URIs × (每个header的值数量的乘积)**

### 安全限制

- ✅ 最多 100,000 个 payload（约 600 MB 内存）
- ✅ 超过限制会被拒绝启动
- ✅ 启动时显示预计内存占用

### 推荐规模

- **测试环境**：50-500 个 payload
- **生产环境**：500-5,000 个 payload
- **高级场景**：5,000-50,000 个 payload

## 🛠️ 工具

### check_config.sh

在运行前检查配置文件：

```bash
./check_config.sh my_config.conf
```

输出示例：
```
正在分析配置文件: test_config.conf
========================================
Methods 数量: 2
URIs 数量: 2

Headers 统计:
  Host                : 2 个值
  User-Agent          : 2 个值
  Accept              : 2 个值

Header 组合倍数: 8
========================================
总 Payload 数量: 32
预计内存占用: 0.19 MB

✅ 状态: 安全（测试环境推荐）
```

## 🔍 故障排查

### 问题：程序被 OOM killed

**原因**：配置生成了过多的 payload

**解决方案**：
1. 使用 `check_config.sh` 检查配置
2. 减少 header 的值数量（影响最大）
3. 减少 methods 和 URIs 数量
4. 参考 [OOM_PROTECTION.md](OOM_PROTECTION.md)

### 问题：配置文件格式错误

**解决方案**：
1. 确保每个部分都有 `[section]` 标题
2. 确保至少有一个 Host header
3. 确保 URI 以 `/` 开头
4. 参考示例配置文件

### 问题：启动很慢

**原因**：生成大量 payload 需要时间

**解决方案**：
- 耐心等待（100,000 个约需 10-20 秒）
- 或减少 payload 数量

## 💡 最佳实践

1. **先小后大**：从小配置开始测试，逐步增加
2. **使用检查工具**：运行前先用 `check_config.sh` 检查
3. **注意 header 值**：每个 header 的值数量影响最大
4. **监控内存**：使用 `top` 或 `htop` 监控内存使用
5. **分批运行**：如需大量变化，考虑多个配置文件

## 📊 性能参考

| Payload 数量 | 内存占用 | 启动时间 | 适用场景 |
|-------------|---------|---------|---------|
| 100 | 0.6 MB | < 1秒 | 测试 |
| 1,000 | 6 MB | < 1秒 | 小规模生产 |
| 10,000 | 60 MB | 1-2秒 | 中等规模生产 |
| 50,000 | 300 MB | 5-10秒 | 大规模生产 |
| 100,000 | 600 MB | 10-20秒 | 极限场景 |

## 🎯 配置示例

### 小规模（推荐新手）

```ini
[methods]
GET
POST

[uris]
/api/test

[headers]
Host: example.com
User-Agent: Mozilla/5.0

[body]
{"test":"data"}
```

**结果**：2 × 1 × 1 × 1 = 2 个 payload

### 中等规模（推荐生产）

```ini
[methods]
GET
POST
PUT

[uris]
/api/users
/api/products
/api/orders

[headers]
Host: api1.example.com
Host: api2.example.com
User-Agent: Mozilla/5.0 (Windows)
User-Agent: Mozilla/5.0 (Mac)
Accept: application/json

[body]
{"data":"test"}
```

**结果**：3 × 3 × 2 × 2 × 1 = 36 个 payload

## 🔗 相关链接

- 项目主页：https://github.com/MikeWang000000/FakeHTTP
- 问题反馈：请查看项目 Issues

## 📄 许可证

本项目采用 GPLv3 许可证。

---

**最后更新**：2026年2月8日  
**版本**：v1.0

