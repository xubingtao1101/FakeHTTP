#!/bin/bash
# 配置文件 Payload 数量计算器

if [ $# -eq 0 ]; then
    echo "用法: $0 <config_file>"
    echo "示例: $0 test_config.conf"
    exit 1
fi

CONFIG_FILE="$1"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 配置文件 '$CONFIG_FILE' 不存在"
    exit 1
fi

echo "正在分析配置文件: $CONFIG_FILE"
echo "========================================"

# 统计 methods
method_count=$(awk '/^\[methods\]/,/^\[/ {if ($0 !~ /^\[/ && $0 !~ /^#/ && $0 !~ /^$/) print}' "$CONFIG_FILE" | wc -l)
echo "Methods 数量: $method_count"

# 统计 URIs
uri_count=$(awk '/^\[uris\]/,/^\[/ {if ($0 !~ /^\[/ && $0 !~ /^#/ && $0 !~ /^$/) print}' "$CONFIG_FILE" | wc -l)
echo "URIs 数量: $uri_count"

# 统计 headers（按名称分组并计算每个的值数量）
echo ""
echo "Headers 统计:"
awk '/^\[headers\]/,/^\[/ {
    if ($0 !~ /^\[/ && $0 !~ /^#/ && $0 !~ /^$/) {
        split($0, arr, ":")
        gsub(/^[ \t]+|[ \t]+$/, "", arr[1])
        headers[arr[1]]++
    }
}
END {
    total = 1
    for (h in headers) {
        printf "  %-20s: %d 个值\n", h, headers[h]
        total *= headers[h]
    }
    print ""
    print "Header 组合倍数: " total
}' "$CONFIG_FILE"

# 计算总 payload 数量
total_payloads=$(awk -v methods="$method_count" -v uris="$uri_count" '
BEGIN {
    in_headers = 0
}
/^\[headers\]/ {
    in_headers = 1
    next
}
/^\[/ {
    if (in_headers) in_headers = 0
}
in_headers && $0 !~ /^#/ && $0 !~ /^$/ {
    split($0, arr, ":")
    gsub(/^[ \t]+|[ \t]+$/, "", arr[1])
    headers[arr[1]]++
}
END {
    header_mult = 1
    for (h in headers) {
        header_mult *= headers[h]
    }
    total = methods * uris * header_mult
    print total
}' "$CONFIG_FILE")

echo "========================================"
echo "总 Payload 数量: $total_payloads"

# 计算内存占用
memory_kb=$((total_payloads * 6))
memory_mb=$(echo "scale=2; $memory_kb / 1024" | bc)

echo "预计内存占用: ${memory_mb} MB"
echo ""

# 判断是否安全
if [ "$total_payloads" -le 500 ]; then
    echo "✅ 状态: 安全（测试环境推荐）"
elif [ "$total_payloads" -le 5000 ]; then
    echo "✅ 状态: 良好（生产环境推荐）"
elif [ "$total_payloads" -le 50000 ]; then
    echo "⚠️  状态: 可用（高级场景，内存占用较大）"
elif [ "$total_payloads" -le 100000 ]; then
    echo "⚠️  状态: 警告（接近限制，内存占用很大）"
else
    echo "❌ 状态: 危险（超过限制，程序会拒绝启动）"
    echo ""
    echo "建议："
    echo "  1. 减少每个 header 的值数量"
    echo "  2. 减少 methods 或 URIs 的数量"
    echo "  3. 分批创建多个配置文件"
fi

echo ""
echo "参考："
echo "  测试环境: 50-500 个 payload"
echo "  生产环境: 500-5,000 个 payload"
echo "  高级场景: 5,000-50,000 个 payload"
echo "  最大限制: 100,000 个 payload"

