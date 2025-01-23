#!/bin/bash

# 确保Python环境变量正确设置
export PATH="$PATH:/usr/local/bin"

# 切换到脚本所在目录
cd "$(dirname "$0")"

# 检查日志目录是否存在，不存在则创建
LOG_DIR="logs"
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
fi

# 获取当前时间戳
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# 使用nohup在后台运行Python脚本
nohup python3 LeichiWafReport.py > "$LOG_DIR/monitor_$TIMESTAMP.log" 2>&1 &

# 保存进程ID到文件
echo $! > monitor.pid

echo "WAF监控程序已在后台启动，进程ID: $(cat monitor.pid)"
echo "查看运行日志：tail -f $LOG_DIR/monitor_$TIMESTAMP.log"