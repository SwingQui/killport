#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键关闭端口程序 - 简化版
"""
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os
import ctypes


def is_admin():
    """检查是否具有管理员权限"""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def find_process_using_port(port):
    """查找使用指定端口的进程"""
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        lines = result.stdout.split('\n')

        for line in lines:
            if f':{port}' in line and 'LISTENING' in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    return parts[-1]
        return None
    except:
        return None


def kill_process_by_pid(pid):
    """根据PID终止进程"""
    try:
        result = subprocess.run(['taskkill', '/PID', pid, '/F'],
                              capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False


def get_all_used_ports():
    """获取所有正在使用的端口"""
    used_ports = []
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        lines = result.stdout.split('\n')

        for line in lines:
            if 'LISTENING' in line and 'TCP' in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    local_address = parts[1]
                    if ':' in local_address:
                        port_str = local_address.split(':')[-1]
                        if ']' in port_str:
                            port_str = port_str.split(']')[-1]
                        if port_str.isdigit():
                            port = int(port_str)
                            pid = parts[-1]
                            used_ports.append((port, pid))

        # 去重并按端口号排序
        unique_ports = {}
        for port, pid in used_ports:
            if port not in unique_ports:
                unique_ports[port] = pid

        sorted_ports = sorted(unique_ports.items())
        return sorted_ports

    except:
        return []


def get_port_description(port):
    """根据端口号获取常见服务描述"""
    common_ports = {
    # 基础网络协议
    20: "FTP数据",
    21: "FTP控制",
    22: "SSH（安全外壳协议）",
    23: "Telnet（远程终端协议）",
    25: "SMTP（简单邮件传输协议）",
    53: "DNS（域名系统）",
    67: "DHCP服务器（引导程序协议服务端）",
    68: "DHCP客户端（引导程序协议客户端）",
    69: "TFTP（简单文件传输协议）",
    80: "HTTP（超文本传输协议）",
    110: "POP3（邮局协议版本3）",
    119: "NNTP（网络新闻传输协议）",
    123: "NTP（网络时间协议）",
    143: "IMAP（互联网消息访问协议）",
    161: "SNMP（简单网络管理协议）",
    162: "SNMP陷阱（SNMP Trap）",
    443: "HTTPS（安全超文本传输协议）",
    465: "SMTPS（加密SMTP）",
    587: "SMTP提交（邮件提交代理）",
    993: "IMAPS（加密IMAP）",
    995: "POP3S（加密POP3）",
    
    # 数据库服务
    1433: "SQL Server（微软数据库）",
    1434: "SQL Server Browser（SQL Server浏览器服务）",
    1521: "Oracle（甲骨文数据库）",
    1526: "Oracle XE（精简版Oracle）",
    3306: "MySQL（关系型数据库）",
    3307: "MySQL备用端口",
    3389: "远程桌面（RDP，Windows远程桌面协议）",
    5432: "PostgreSQL（开源关系型数据库）",
    5433: "PostgreSQL备用端口",
    6379: "Redis（键值对数据库）",
    6380: "Redis集群/加密端口",
    27017: "MongoDB（文档型数据库）",
    27018: "MongoDB副本集端口",
    27019: "MongoDB配置服务器端口",
    9042: "Cassandra（分布式数据库）",
    28017: "MongoDB HTTP管理端口",
    11211: "Memcached（分布式缓存）",
    11212: "Memcached备用端口",
    8086: "InfluxDB（时序数据库）",
    50000: "DB2（IBM数据库）",
    
    # Web/开发常用
    8080: "HTTP代理/备用HTTP端口",
    8000: "开发服务器（Python/Flask等）",
    8443: "HTTPS-alt（备用HTTPS端口）",
    9000: "开发服务器（PHP-FPM/Node.js等）",
    3000: "Node.js开发服务器/React开发服务",
    5000: "Flask开发服务器/HTTP备用端口",
    7000: "前端开发代理端口",
    9200: "Elasticsearch（搜索引擎HTTP端口）",
    9300: "Elasticsearch（集群通信端口）",
    5601: "Kibana（Elasticsearch可视化）",
    8888: "Jupyter Notebook/开发调试端口",
    4200: "Angular开发服务器",
    8181: "REST API服务端口",
    
    # 网络服务/远程访问
    5900: "VNC（远程桌面协议）",
    5901: "VNC备用端口",
    2049: "NFS（网络文件系统）",
    137: "NetBIOS（网络基本输入输出系统）",
    138: "NetBIOS数据报",
    139: "NetBIOS会话（SMB）",
    445: "SMB（服务器消息块）/Windows文件共享",
    636: "LDAPS（加密轻量级目录访问协议）",
    389: "LDAP（轻量级目录访问协议）",
    514: "Syslog（系统日志）",
    515: "LPD（行式打印机后台程序）",
    6000: "X11（Unix图形界面）",
    
    # 云/容器/运维
    2375: "Docker HTTP（未加密）",
    2376: "Docker HTTPS（加密）",
    2379: "ETCD（分布式键值存储）",
    2380: "ETCD集群通信",
    6443: "Kubernetes API Server",
    10250: "Kubernetes Kubelet",
    10251: "Kubernetes Controller Manager",
    10252: "Kubernetes Scheduler",
    8472: "Flannel（K8s网络）",
    3128: "Squid代理服务器",
    1080: "SOCKS代理",
    
    # 其他常用服务
    3801: "Radmin（远程管理工具）",
    5060: "SIP（会话初始协议，VoIP）",
    5061: "SIPS（加密SIP）",
    873: "Rsync（文件同步工具）",
    9987: "TS3 Server（Teamspeak语音服务器）",
    25565: "Minecraft（我的世界游戏服务器）",
    1900: "UPnP（通用即插即用）",
    49152: "动态端口起始（临时端口范围）",
    65535: "动态端口结束（临时端口范围）"
}
    return common_ports.get(port, f"自定义服务 (端口 {port})")


class PortKillerApp:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        self.refresh_port_list()

    def setup_ui(self):
        """设置界面"""
        self.root.title("端口关闭工具 v1.0")
        self.root.geometry("550x650")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")

        # 主框架
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 标题
        title_label = tk.Label(main_frame, text="🔧 一键关闭端口工具",
                              font=("微软雅黑", 18, "bold"),
                              fg="#2c3e50", bg="#f0f0f0")
        title_label.pack(pady=(0, 20))

        # 端口输入框架
        input_frame = ttk.LabelFrame(main_frame, text="📌 输入端口号", padding="15")
        input_frame.pack(fill=tk.X, pady=(0, 15))

        # 端口输入
        port_input_frame = ttk.Frame(input_frame)
        port_input_frame.pack(fill=tk.X)

        ttk.Label(port_input_frame, text="端口号:", font=("微软雅黑", 11)).pack(side=tk.LEFT, padx=(0, 10))

        self.port_entry = ttk.Entry(port_input_frame, width=10, font=("Arial", 12))
        self.port_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.port_entry.focus()

        self.close_button = tk.Button(port_input_frame,
                                     text="关闭端口",
                                     command=self.close_port,
                                     font=("微软雅黑", 11, "bold"),
                                     bg="#3498db", fg="white",
                                     activebackground="#2980b9",
                                     relief="raised", padx=15, pady=5)
        self.close_button.pack(side=tk.LEFT)

        # 快捷端口
        quick_frame = ttk.Frame(input_frame)
        quick_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(quick_frame, text="快捷端口:", font=("微软雅黑", 10)).pack(side=tk.LEFT, padx=(0, 10))

        quick_ports = [80, 443, 8080, 3000, 3306, 5000]
        for port in quick_ports:
            btn = tk.Button(quick_frame, text=str(port),
                           command=lambda p=port: self.set_port(p),
                           font=("Arial", 9), bg="#95a5a6", fg="white",
                           width=5, relief="flat")
            btn.pack(side=tk.LEFT, padx=2)

        # 端口列表
        list_frame = ttk.LabelFrame(main_frame, text="📋 本机端口使用情况", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.port_listbox = tk.Listbox(list_frame,
                                     yscrollcommand=scrollbar.set,
                                     font=("Consolas", 9),
                                     bg="#ffffff", fg="#2c3e50")
        self.port_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.port_listbox.yview)

        self.port_listbox.bind('<<ListboxSelect>>', self.on_port_select)

        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        refresh_button = tk.Button(button_frame,
                                 text="🔄 刷新列表",
                                 command=self.refresh_port_list,
                                 font=("微软雅黑", 11, "bold"),
                                 bg="#27ae60", fg="white",
                                 activebackground="#229954",
                                 relief="raised", padx=15, pady=5)
        refresh_button.pack(side=tk.LEFT)

        clear_button = tk.Button(button_frame,
                               text="清空输入",
                               command=lambda: self.port_entry.delete(0, tk.END),
                               font=("微软雅黑", 11, "bold"),
                               bg="#e74c3c", fg="white",
                               activebackground="#c0392b",
                               relief="raised", padx=15, pady=5)
        clear_button.pack(side=tk.LEFT, padx=(10, 0))

        # 状态
        self.status_label = ttk.Label(main_frame, text="✅ 就绪",
                                    font=("微软雅黑", 10, "bold"),
                                    foreground="#27ae60")
        self.status_label.pack(pady=(0, 10))

        # 提示
        tip_label = tk.Label(main_frame,
                           text="⚠️ 提示: 关闭端口会强制终止占用该端口的进程，请谨慎操作",
                           foreground="#e67e22",
                           font=("微软雅黑", 9, "italic"),
                           bg="#f0f0f0")
        tip_label.pack()

        # 绑定键盘
        self.root.bind('<Return>', lambda e: self.close_port())
        self.root.bind('<Escape>', lambda e: self.port_entry.delete(0, tk.END))

    def set_port(self, port):
        """设置端口号"""
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(port))

    def on_port_select(self, event):
        """选择端口时"""
        selection = self.port_listbox.curselection()
        if selection:
            item = self.port_listbox.get(selection[0])
            # 提取端口号
            try:
                import re
                match = re.search(r'端口\s+(\d+)', item)
                if match:
                    self.set_port(match.group(1))
            except:
                pass

    def close_port(self):
        """关闭端口"""
        port = self.port_entry.get().strip()
        if not port:
            messagebox.showerror("错误", "请输入端口号！")
            return

        if not port.isdigit():
            messagebox.showerror("错误", "端口号必须是数字！")
            return

        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            messagebox.showerror("错误", "端口号必须在1-65535之间！")
            return

        # 查找进程
        self.status_label.config(text="正在查找占用端口的进程...")
        self.root.update()

        pid = find_process_using_port(port_num)
        if not pid:
            messagebox.showinfo("提示", f"端口 {port} 没有被任何进程占用！")
            self.status_label.config(text="操作完成")
            return

        # 询问确认
        result = messagebox.askyesno("确认",
                                    f"端口 {port} 被进程 {pid} 占用。\n是否要终止该进程？")
        if result:
            self.status_label.config(text=f"正在终止进程 {pid}...")
            self.root.update()
            if kill_process_by_pid(pid):
                messagebox.showinfo("成功", f"已成功关闭端口 {port}")
                self.status_label.config(text="操作成功")
                self.refresh_port_list()  # 刷新列表
            else:
                messagebox.showerror("错误", "终止进程失败！")
                self.status_label.config(text="操作失败")
        else:
            self.status_label.config(text="操作已取消")

    def refresh_port_list(self):
        """刷新端口列表"""
        try:
            self.port_listbox.delete(0, tk.END)
            used_ports = get_all_used_ports()

            if not used_ports:
                self.port_listbox.insert(tk.END, "没有找到正在使用的端口")
                return

            # 显示标题
            title = f"正在使用的端口 (共 {len(used_ports)} 个):"
            self.port_listbox.insert(tk.END, title)
            self.port_listbox.insert(tk.END, "-" * 60)

            # 显示端口
            for port, pid in used_ports:
                port_desc = get_port_description(port)
                display = f"🔴 端口 {port:5d} - PID:{pid:6s} - {port_desc}"
                self.port_listbox.insert(tk.END, display)
                self.port_listbox.itemconfig(tk.END, {'fg': '#e74c3c'})

        except Exception as e:
            self.port_listbox.insert(tk.END, f"刷新失败: {str(e)}")


def main():
    """主函数"""
    if not is_admin():
        # 以管理员权限重新运行
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                          " ".join(sys.argv), None, 1)
        return

    root = tk.Tk()
    app = PortKillerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()