# WAF攻击监控告警系统

import requests
import json
import urllib3
import time
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

# 禁用SSL证书验证警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置信息
API_TOKEN = "xxx"
BASE_URL = "xxx"
FEISHU_WEBHOOK = "xxx"

# 配置日志记录
log_file = 'waf_monitor.log'
logger = logging.getLogger('WAFMonitor')
logger.setLevel(logging.INFO)

# 创建RotatingFileHandler，限制单个日志文件大小为10MB，最多保留5个备份
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
file_handler.setLevel(logging.INFO)

# 创建控制台处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# 设置日志格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 添加处理器到logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# HTTP请求头
header = {
    "X-SLCE-API-TOKEN": API_TOKEN
}

def format_response(data):
    """格式化响应数据的辅助函数"""
    if isinstance(data, (dict, list)):
        return json.dumps(data, indent=4, ensure_ascii=False)
    return str(data)

def print_error(message, details=None):
    """打印错误信息的辅助函数"""
    error_msg = f"错误类型: {message}"
    if details:
        error_msg += f"\n详细信息: {details}"
    logger.error(error_msg)

def send_to_feishu(data):
    """发送告警信息到飞书"""
    message = {
        "msg_type": "interactive",
        "card": {
            "config": {
                "wide_screen_mode": True
            },
            "header": {
                "title": {
                    "tag": "plain_text",
                    "content": "🚨 WAF安全告警通知"
                },
                "template": "red"
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {
                        "tag": "lark_md",
                        "content": f"**告警时间**: {data.get('告警通知时间', 'N/A')}\n" +
                                  f"**攻击源IP**: {data.get('攻击源地址', 'N/A')}\n" +
                                  f"**受影响目标**: {data.get('受影响源目地址', 'N/A')}\n" +
                                  f"**攻击来源**: {data.get('攻击来源', 'N/A')}\n" +
                                  f"**触发规则**: {data.get('触发规则', 'N/A')}\n" +
                                  f"**攻击路径**: {data.get('被攻击路径', 'N/A')}\n" +
                                  f"**风险等级**: {data.get('风险等级', 'N/A')}\n" +
                                  f"**攻击类型**: {data.get('攻击类型', 'N/A')}"
                    }
                },
                {
                    "tag": "hr"
                },
                {
                    "tag": "note",
                    "elements": [
                        {
                            "tag": "plain_text",
                            "content": "请及时处理相关安全威胁"
                        }
                    ]
                }
            ]
        }
    }
    
    try:
        response = requests.post(FEISHU_WEBHOOK, json=message)
        if response.status_code == 200:
            logger.info("告警信息已发送到飞书")
        else:
            logger.error(f"发送到飞书失败: {response.text}")
    except Exception as e:
        logger.error(f"发送到飞书时发生异常: {str(e)}")

def get_latest_attack_id(target_time=None):
    """获取最新的攻击日志ID（按时间戳排序）
    Args:
        target_time: 目标时间戳，如果提供，将只返回该时间之后的攻击记录
    """
    url = f"{BASE_URL}/api/commercial/record/export"
    try:
        result = requests.get(url=url, headers=header, verify=False, timeout=10)
        if result.status_code != 200:
            print_error(f"获取攻击日志失败 (状态码: {result.status_code})", result.text)
            return None

        # 解析CSV数据
        import csv
        from io import StringIO
        
        # 清理CSV数据，移除BOM和特殊字符
        cleaned_text = result.text.strip().lstrip('\ufeff')
        
        # 使用UTF-8编码解析CSV数据
        csv_data = list(csv.reader(StringIO(cleaned_text)))
        if not csv_data or len(csv_data) < 2:
            print_error("未找到攻击日志记录")
            return None
            
        # 清理表头字段名称
        headers = [field.strip() for field in csv_data[0]]

        # 获取表头
        headers = csv_data[0]
        
        # 查找必要字段
        try:
            # 直接尝试匹配'Id'字段
            try:
                id_index = headers.index('Id')
                logger.info("成功匹配ID字段")
            except ValueError:
                print_error("在攻击日志中未找到'Id'字段", f"可用字段: {', '.join(headers)}")
                return None
            
            # 匹配时间字段
            try:
                timestamp_index = headers.index('时间')
                logger.info("成功匹配时间字段")
            except ValueError:
                print_error("未找到时间字段", "缺少字段: 时间")
                logger.debug(f"可用的字段名: {', '.join(headers)}")
                return None

            timestamp_index = headers.index('时间')
            logger.info("成功匹配时间字段")

        except ValueError as e:
            print_error("未找到时间字段", "缺少字段: 时间")
            logger.debug(f"可用的字段名: {', '.join(headers)}")
            return None

        # 获取所有记录（跳过表头）
        records = csv_data[1:]
        
        # 按时间戳过滤和排序记录
        try:
            # 过滤记录
            if target_time:
                records = [r for r in records if int(datetime.strptime(r[timestamp_index], "%Y-%m-%d %H:%M:%S").timestamp()) >= target_time]
                if not records:
                    logger.info(f"未找到时间戳 {target_time} 之后的攻击记录")
                    return None
            
            # 按时间戳排序
            records.sort(key=lambda x: int(datetime.strptime(x[timestamp_index], "%Y-%m-%d %H:%M:%S").timestamp()), reverse=True)
            logger.info("已按时间戳降序排序攻击记录")
            
            # 获取最新记录的ID和时间
            latest_record = records[0]
            attack_id = latest_record[id_index]
            attack_time = latest_record[timestamp_index]
            
            logger.info(f"获取到最新攻击记录 - ID: {attack_id}, 时间: {attack_time}")
            
            return attack_id

        except (ValueError, TypeError) as e:
            print_error("处理时间戳时发生错误", str(e))
            return None

    except Exception as e:
        print_error("获取攻击日志时发生异常", str(e))
        return None

def get_attack_details(attack_id):
    """获取攻击详情"""
    url = f"{BASE_URL}/api/open/record/{attack_id}"
    try:
        result = requests.get(url=url, headers=header, verify=False, timeout=10)
        if result.status_code != 200:
            print_error(f"获取攻击详情失败 (状态码: {result.status_code})", result.text)
            return None

        response_data = result.json()
        if response_data.get('err') is None and 'data' in response_data:
            data = response_data['data']
            return {
                'IP拦截处理': data.get('action', 'N/A'),
                '告警通知时间': datetime.fromtimestamp(data.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                '攻击源地址': data.get('src_ip', 'N/A'),
                '受影响源目地址': data.get('dst_ip', 'N/A'),
                '攻击来源': f"{data.get('country', 'N/A')} {data.get('province', '')} {data.get('city', '')}",
                '触发规则': data.get('rule_id', 'N/A'),
                '被攻击路径': data.get('url_path', 'N/A'),
                '原始攻击日志': data.get('req_header', 'N/A'),
                '风险等级': data.get('risk_level', 'N/A'),
                '攻击类型': data.get('attack_type', 'N/A'),
                '攻击载荷': {
                    '请求方法': data.get('method', 'N/A'),
                    '请求头': data.get('req_header', {}),
                    '请求体': data.get('req_body', 'N/A'),
                    '请求参数': data.get('query_string', {}),
                    '攻击Payload': data.get('payload', 'N/A')
                }
            }
        else:
            print_error("API响应错误", response_data.get('msg', '未知错误'))
            return None

    except Exception as e:
        print_error("获取攻击详情时发生异常", str(e))
        return None

def main():
    """主函数：持续监控攻击日志并发送告警"""
    logger.info("WAF攻击监控告警系统已启动...")
    last_processed_id = None
    
    # 设置目标时间戳（2024-12-24 05:50:41）
    target_timestamp = int(datetime.strptime("2024-12-24 05:50:41", "%Y-%m-%d %H:%M:%S").timestamp())
    logger.info(f"设置监控时间点: 2024-12-24 05:50:41")

    while True:
        try:
            # 获取最新攻击ID（仅获取目标时间之后的记录）
            current_id = get_latest_attack_id(target_timestamp)
            if current_id and current_id != last_processed_id:
                logger.info(f"发现新的攻击记录 (ID: {current_id})")
                
                # 获取攻击详情
                attack_details = get_attack_details(current_id)
                if attack_details:
                    # 发送告警
                    send_to_feishu(attack_details)
                    last_processed_id = current_id

            # 等待一段时间再次检查
            time.sleep(60)  # 每分钟检查一次

        except KeyboardInterrupt:
            logger.info("监控系统已停止")
            break
        except Exception as e:
            print_error("监控过程中发生异常", str(e))
            time.sleep(60)  # 发生错误时等待一分钟后继续

if __name__ == "__main__":
    main()