#-----scapy needed via sudo pip install scapy
#-----input tex.py [num_thread] [level] [MAX_SENT_NUM] [is_whole_network(default not|0 for no|1 for yes)]
#-----example : sudo python3 tex.py 40 2 2 0
#-----(you can change the scope of IP space via modify codes between line30 and line33, its a 4 levels of 'for' loop to traverse ip of num1.num2.num3.num4)
import socket
import sys
import threading
import time
import os
from scapy.all import *
available = { 'any' : 0 }
lock = threading.Lock()
base = 64
level = 3 #0:* for 64(2^0*64)/128(2^1*64)/256(2^2*64)/2*256/4*256/8*256/16*256
num_thread = 10
task_pool = []
state = []
process = []

is_whole_net = False

flag_rcv = False

MAX_SENT_NUM = 1

NUM_OF_BLOCK = 100#default 60

sip = '1.1.1.1'

num1 = [10]
num2 = [0,80,193,194,201,208]
num3 = [(0,255)]
num4 = [(1,254)]

def get_host_ip():#查询本机ip地址
    global num2
    global is_whole_net
    if is_whole_net:
        num2.clear()
        for i in range(256):
            num2.append(i)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
        _time = time.localtime(time.time())
        tmp = 'localtime : '+str(_time[0])+'/'+str(_time[1])+'/'+str(_time[2])+' '+str(_time[3])+':'+str(_time[4])+':'+str(_time[5])
        print(tmp)
    return ip

def control(num1,num2,num3,num4):
    global sip
    global flag_rcv
    global num_thread
    global base
    global level
    global available
    global task_pool
    global state
    global process
    global NUM_OF_BLOCK
    flag3 = False
    flag4 = False
    div = 1
    if level > 10:
        level = 10
    elif level < 0:
        level = 0
    else:
        level = int(level)
    base = pow(2,level)*64
    for i in range(num_thread):
        state.append(True)
        process.append([0,base])
    if level >= 2 and level <= 10:
        flag3 = True
        div = pow(2,level - 2)
    else:#level = 0 | 1
        flag4 = True
        div = pow(2,level)*64
    for i1 in range(len(num1)):
        tex1 = [num1[i1]]
        for i2 in range(len(num2)):
            tex2 = [num2[i2]]
            for i3 in range(len(num3)):
                start3 = num3[i3][0]
                end3 = num3[i3][1]
                if flag3:
                    while True:
                        if start3 > end3:
                            break
                        if start3 + div - 1 <= end3:
                            tex3 = [(start3,start3 + div - 1)]
                            tex4 = num4
                            start3 += div
                            task_pool.append((tex1,tex2,tex3,tex4))
                        else:
                            tex3 = [(start3,end3)]
                            tex4 = num4
                            task_pool.append((tex1,tex2,tex3,tex4))
                            break
                elif flag4:
                    for i in range(start3,end3+1):
                        tex3 = [(i,i)]
                        for i4 in range(len(num4)):
                            start4 = num4[i4][0]
                            end4 = num4[i4][1]
                            while True:
                                if start4 > end4:
                                    break
                                if start4 + div - 1 <= end4:
                                    tex4 = [(start4,start4 + div - 1)]
                                    start4 += div
                                    task_pool.append((tex1,tex2,tex3,tex4))
                                else:
                                    tex4 = [(start4,end4)]
                                    task_pool.append((tex1,tex2,tex3,tex4))
                else:
                    print('WARNING flag3 | flag4 : ',flag3,flag4)
    print('every task has '+str(base)+' times of request, total '+str(len(task_pool))+' tasks')#print(task_pool)
    #tasks division finished
    while flag_rcv == False:
        time.sleep(0.2)
    #task distribution starting
    len_pool = len(task_pool)
    counter = 0
    loop = 0
    pid = 0
    MAX_LOOP = 10
    num_block = NUM_OF_BLOCK
    thread_info = ''
    while True:
        alive = 0
        for id in range(num_thread):
            if state[id] == True:
                if len(task_pool)>0:
                    task_t = task_pool.pop()
                    counter += 1
                    try:
                        t = threading.Thread( target = request,args = (sip,id,task_t[0],task_t[1],task_t[2],task_t[3],) )
                        t.start()
                    except:
                        counter -= 1
                        task_pool.append(task_t)
                        print ("Error: unable to start thread")
            else:
                alive += 1
        if loop == 0:
            curpid = pid
            while state[pid] == True:
                pid += 1
                pid = pid % num_thread
                if pid == curpid:
                    break
            thread_info = str(pid) + ':' + str(process[pid]) + '|'
            pid +=1
            pid = pid % num_thread
        loop += 1
        loop = loop%MAX_LOOP

        num = int(counter/len_pool*num_block)
        num_working = int(alive/len_pool*num_block)
        num -= num_working
        if num >= num_block:
            num = num_block
        perc = int(counter/len_pool*100)
        sys.stdout.write('#' * num + '>' * num_working + '_' * (num_block - num) + '|' + str(perc) + '%|'+str(counter)+'/'+str(len_pool)+'|'+str(alive)+'alive|'+thread_info+str(int(time.clock())%100000)+' ' * 10+'\r')
        sys.stdout.flush()
        time.sleep(0.2)
        if counter == len_pool and alive == 0:
            print('#')
            break
    print('--------- finish requesting ---------')
    _time = time.localtime(time.time())
    filepath = 'result'+'_'+str(_time[1])+'_'+str(_time[2])+'_'+str(_time[3])+'_'+str(_time[4])+'.txt'
    with open(filepath,'w') as f_w:
        tmp = 'total number (any): ' + str(available['any']) + '\n'
        f_w.write(tmp)
        for key in available.keys():
            if key == 'any':
                pass
            else:
                tmp = key + ' : ' + str(available[key]) + '\n'
                f_w.write(tmp)
    print('--------- finish writing ---------\n           into '+filepath)
    print('___| exit by ctrl-Z|___')
               
def request(src_ip,id,num1,num2,num3,num4):
    global state
    global process
    global lock
    global MAX_SENT_NUM
    lock.acquire()
    state[id] = False
    process[id][0] = 0
    lock.release()
    ipp = IP(src=src_ip,ttl=128)
    icmpp = ICMP(type=8,code=0)
    icmpp.id = int(os.getgid())
    counter = 0
    dst_ip_1 = str(num1)+'.'
    for i1 in range(len(num1)):
        dst_ip_1 = str(num1[i1])+'.'
        for i2 in range(len(num2)):
            dst_ip_2 = dst_ip_1 + str(num2[i2]) + '.'
            for i3 in range(len(num3)):
                start3 = num3[i3][0]
                end3 = num3[i3][1]
                while start3 <= end3:
                    dst_ip_3 = dst_ip_2 + str(start3) + '.'
                    start3 += 1
                    for i4 in range(len(num4)):
                        start4 = num4[i4][0]
                        end4 = num4[i4][1]
                        while start4 <= end4:
                            dst_ip = dst_ip_3 + str(start4)
                            start4 += 1
                            ipp.dst = dst_ip
                            icmpp.seq = counter
                            for _ in range(MAX_SENT_NUM):
                                send((ipp/icmpp),verbose = 0)
                            counter += 1
                            process[id][0] = counter
    lock.acquire()
    state[id] = True
    lock.release()

def invoke(pkt):
    global available
    global sip
    if pkt[0][2].type == 0 and pkt[0][2].code == 0 and pkt[0][1].dst == sip:
        ip_rcv = pkt[0][1].src
        if ip_rcv in available:
            available[ip_rcv]+=1
        else:
            available[ip_rcv]=1
            available['any']+=1

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        num = int(sys.argv[1])
        if num > 0 and num <= 100:
            num_thread = num
    if len(sys.argv) >= 3:
        num = int(sys.argv[2])
        if num >= 0 and num <= 10:
            level = num
    if len(sys.argv) >= 4:
        num = int(sys.argv[3])
        if num > 0 and num < 10:
            MAX_SENT_NUM = num
    if len(sys.argv) >= 5:
        num = int(sys.argv[4])
        if num == 0:
            is_whole_net = False
        else:
            is_whole_net = True
    sip = get_host_ip()
    try:
        t = threading.Thread( target = control,args = (num1,num2,num3,num4,) )
        t.start()
        print ("success to start thread : control")
    except:
        print ("Error: unable to start thread")
    print('---------- initilized ----------\n')
    lock.acquire()
    flag_rcv = True
    lock.release()
    pkt = sniff(filter = 'icmp',prn = invoke)
