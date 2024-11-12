from scapy.all import *
import telegram
import asyncio
from asyncio import Queue
import threading
import time
import os
import sys

# Telegram Bot 配置
TOKEN = "7638064089:AAF7VsOdEzRpXLeRm8eSeT5btqoT9jO2rls"  # 你的 Telegram 机器人 Token
CHAT_ID = "5868316049"  # 你的 chat_id

bot = telegram.Bot(token=TOKEN)
queue = Queue()

# 发送 Telegram 通知函数 (异步)
async def send_notification(title, message):
    try:
        await bot.send_message(chat_id=CHAT_ID, text=f"{title}\n{message}")
        print(f"通知发送成功: {title} - {message}")
    except telegram.error.NetworkError as e:
        print(f"网络错误：{e}，将在5秒后重启脚本...")
        time.sleep(5)
        restart_program()
    except telegram.error.TelegramError as e:
        print(f"消息发送失败，错误信息: {e}")

# 异步处理队列中的通知
async def notification_worker():
    while True:
        title, message = await queue.get()
        await send_notification(title, message)
        queue.task_done()
        await asyncio.sleep(1)  # 每隔1秒发送一次消息，防止请求过于频繁

# 设置要监控的 IP 地址
TARGET_IP = "192.168.1.100"  # 替换为你要监控的 IP

# 网络流量检测
def packet_callback(packet):
    if packet.haslayer(IP):
        # 检查目标 IP 是否是流量的源或目的地
        if packet[IP].src == TARGET_IP or packet[IP].dst == TARGET_IP:
            direction = "发送到外网" if packet[IP].src == TARGET_IP else "从外网接收"
            print(f"捕获到流量：{packet.summary()} - {direction}")
            # 将捕获到的信息添加到队列中以便异步通知
            asyncio.run_coroutine_threadsafe(queue.put(("网络流量活动", f"检测到 {TARGET_IP} 有流量：{packet.summary()} - {direction}")), loop)

# 启动嗅探器
def start_sniffing():
    print(f"开始监听 {TARGET_IP} 的网络流量...")
    sniff(filter=f"host {TARGET_IP}", prn=packet_callback, store=0, iface="WLAN 2")  # 修改 iface 为你使用的接口名，例如 "以太网" 或 "Wi-Fi"

# 脚本重启函数
def restart_program():
    """重启当前的 Python 脚本"""
    print("正在重启程序...")
    python = sys.executable
    os.execl(python, python, *sys.argv)

# 主函数，启动事件循环
if __name__ == "__main__":
    # 创建新的事件循环并将其设为当前事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # 启动通知处理 worker
    loop.create_task(notification_worker())

    # 发送开机通知
    asyncio.run(send_notification("系统通知", "电脑开机"))

    # 在独立的线程中启动嗅探器
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()

    # 启动事件循环
    loop.run_forever()
