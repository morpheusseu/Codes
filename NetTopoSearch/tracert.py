#-----scapy needed via sudo pip install scapy
#-----input tracert.py [filepath] [div_A] [num_thread] [MAX_REPEAT_NUM] [MAX_HOP_NUM]
#-----example : sudo python3 tracert.py filepath[result_11_11_21_56.txt] 50 20 2 10
#-----div_A means at most how number positive ip is divided into a task | num_thread means how many threads the process assign tasks to | MAX_REPEAT_NUM means how many times to send same package to avoid bag lost | MAX_HOP_NUM means how many hops you want to try to traceroute its route path
import socket
import sys
import threading
import time
from scapy.all import *

num_thread = 10
div_A = 25
filepath = 'result2020_11_4_18_42.txt'
originpath = 'result2020_11_4_18_42.txt'
sip = '1.1.1.1'

task_poll = []
state = []
process = []

positive_ip = []# index : ip
ip_link = {}# ip : [ip1,ip2] (from source record the steps src_ip -> ip1 -> ip2 -> ip3 -> dst) => dst : [ip1,ip2,ip3]
ip_ip = {}#[(index1,index2):1] -- src : -1

count = []
lock = threading.Lock()

flag_rcv = False

NUM_OF_BLOCK = 60
MAX_REPEAT_NUM = 1
MAX_HOP_NUM = 30
#id = index, seq = ttl

def get_host_ip():#inqury localhost ip
    ip = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
        _time = time.localtime(time.time())
        tmp = 'localtime : '+str(_time[0])+'/'+str(_time[1])+'/'+str(_time[2])+' '+str(_time[3])+':'+str(_time[4])+':'+str(_time[5])+'\nfrom '+ip+' | '+filepath
        print(tmp)
    return ip

def read_result(filepath,sip):#read positive_ip from file
    global state
    global process
    global positive_ip
    global task_poll
    global num_thread
    global div_A
    with open(filepath,'r') as f_r:
        while True:
            str1 = f_r.readline()
            if str1 == '':
                print('--------- finish processing ---------')
                break
            else:
                if str1[0] == 't':
                    pass
                else:
                    index_end = str1.index(':')
                    str1 = str1[0:index_end].replace(' ','')
                    if sip != str1:
                        positive_ip.append(str1)

    counter = 0
    for i in range(len(positive_ip)):
        tmp = positive_ip.count(positive_ip[i])
        if tmp > 1:
            print(positive_ip[i],' occurs ',tmp,' times')
            counter += 1
        if counter > 0:
            print('total : ',counter)
    
    start = 0
    end = len(positive_ip) - 1
    while start < end:
        left = start
        right = start+div_A-1
        if right >= end:
            right = end
        elif end - right < div_A/5:
            right = end
        start = right + 1
        tmp = (left,right)
        task_poll.append(tmp)

    for i in range(num_thread):
        state.append(True)
        process.append((0,0,0))

    pass

def control(sip):
    global task_poll
    global state
    global process
    global num_thread
    global NUM_OF_BLOCK
    global flag_rcv
    global ip_link
    poll_cap = len(task_poll)
    num_block = NUM_OF_BLOCK

    while flag_rcv == False:
        time.sleep(0.1)
    counter = 0
    loop = 0
    MAX_LOOP = 5
    pid = 0
    thread_info = ''
    while counter < poll_cap:
        alive = 0
        for i in range(num_thread):
            if state[i] == True:
                start = task_poll[counter][0]
                end = task_poll[counter][1]
                counter +=1
                try:
                    t = threading.Thread( target = request,args = (sip,i,start,end) )
                    t.start()
                except:
                    counter -=1
                    print ("Error: unable to start thread")
                if counter == poll_cap:
                    break
            else:
                alive += 1
                pass

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

        num = int(counter/poll_cap*num_block)
        if num >= num_block:
            num = num_block
        perc = int(counter/poll_cap*100)
        sys.stdout.write('#' * num + '_' * (num_block - num) + '|' + str(perc) + '%|'+str(counter)+'/'+str(poll_cap)+'|'+str(alive)+'alive|'+thread_info+str(int(time.clock())%1000)+' ' * 10+'\r')
        sys.stdout.flush()

        time.sleep(1)
        if counter == poll_cap:#int(poll_cap/2):#
            break

    sys.stdout.write(' ' * (num_block + 50) +'\r')
    sys.stdout.flush()
    
    while True:
        tmp = '#alive|'
        nofalse = True
        for i in range(num_thread):
            if state[i] == True:
                tmp += 'X|'
                pass
            else:
                tmp += str(i) + '|'
                nofalse = False
        if nofalse:
            break
        num_white = num_block + 50 - len(tmp)
        if num_white < 0:
            num_white = 0
        sys.stdout.write(tmp + str(int(time.clock())%1000) + ' ' * num_white +'|' + '\r')
        sys.stdout.flush()
    
    print('#')
    time.sleep(3)

    print('--------- finishing requesting ---------')
    print('--------- start post-process ---------')
    print('|--( ip => index )&( link => tuple)--|')

    ip_link_t = []
    for key in ip_link.keys():
        tmp = [sip]
        for i in range(len(ip_link[key])):
            tmp.append(ip_link[key][i])
        tmp.append(positive_ip[key])
        ip_link_t.append(tmp)
    ip_link.clear()
    ip_link_t = sorted(ip_link_t,key = lambda line : len(line),reverse = False)
    print('|-- sort finished --|')
    print('--------- start writing ---------')
    for i in range(len(ip_link_t)):
        line = ip_link_t[i]
        len_line = len(line)
        #print(ip_link_t[i],'\n',ip_link_t[i+1],'\n',ip_link_t[i+2],' : index',len_line)
        end_point = line[len_line-1]
        for j in range(i,len(ip_link_t)):
            line_j = ip_link_t[j]
            if len(line_j) <= len_line:
                pass
            else:
                if end_point == line_j[len_line-1]:
                    line.clear()
                    break
    del_count = ip_link_t.count([])
    print('|-- clear finished --|')
    while True:
        ip_link_t.remove([])
        del_count -= 1
        if del_count == 0:
            break

    _time = time.localtime(time.time())
    filepath = 'ip_link_'+str(_time[1])+'_'+str(_time[2])+'_'+str(_time[3])+'_'+str(_time[4])+'.txt'
    with open(filepath,'w') as f_w:
        f_w.write('total number of ip_link : '+str(len(ip_link))+' from file : '+originpath+'\n')
        for line in ip_link_t:
            tmp = ''
            for ip_t in line:
                tmp += ' => ' + ip_t
            tmp += '\n'
            f_w.write(tmp[tmp.index('>')+2:])
    print('--------- finish writing ---------\n           into '+filepath)
    print('___| exit by ctrl-Z|___')

def tracert(sip,index):
    global positive_ip
    global MAX_HOP_NUM
    ipp = IP(src=sip,dst=positive_ip[index])#empty dst | ttl to fill
    icmpp = ICMP(type=8,code=0)#empty id | seq to fill ( dst_ip index | ttl )
    for i in range(1,MAX_HOP_NUM+1):
        ipp.ttl = i
        icmpp.id = index
        icmpp.seq = i
        tmp = ipp/icmpp
        try:
            send(tmp,verbose = 0)
        except:
            print('ERROR occurs : index-',index,sip,'=>',positive_ip[index],'ttl :',i)
    pass

def request(sip,id,start,end):#[start,end]
    global positive_ip
    global MAX_REPEAT_NUM
    global state
    global process
    global lock

    lock.acquire()
    state[id] = False
    lock.release()

    for index in range(start,end+1):
        for i in range(MAX_REPEAT_NUM):
            tracert(sip,index)
        process[id] = (start,index,end)

    lock.acquire()
    state[id] = True
    lock.release()
    return 0

def invoke_react(pkt):
    global ip_link
    global sip
    if pkt[0][2].type == 11 and pkt[0][2].code == 0 and pkt[0][1].dst == sip:#returned ttl equal 0 in transition packet
        #pkt[3].show()
        ip_rcv = pkt[0][1].src
        #ip_src = pkt[0][1].dst
        seq_rcv = pkt[0][4].seq
        id_rcv = pkt[0][4].id#index of dst_ip in icmp request
        if id_rcv in ip_link:
            pass
        else:
            ip_link[id_rcv]=[]
        if len(ip_link[id_rcv]) >= seq_rcv: #no less than this ttl
            ip_link[id_rcv][seq_rcv-1]=ip_rcv
        else:
            while len(ip_link[id_rcv])<seq_rcv:
                ip_link[id_rcv].append('***.***.***.***')
            ip_link[id_rcv][seq_rcv-1]=ip_rcv

if __name__ == '__main__':
    #-----input tracert.py [filepath] [div_A] [MAX_REPEAT_NUM] [MAX_HOP_NUM]
    if len(sys.argv) >= 2:
        filepath = sys.argv[1]
        originpath = filepath
    if len(sys.argv) >= 3:
        div_A = int(sys.argv[2])
    if len(sys.argv) >= 4:
        num_thread = int(sys.argv[3])
    if len(sys.argv) >= 5:
        MAX_REPEAT_NUM = int(sys.argv[4])
    if len(sys.argv) >= 6:
        MAX_HOP_NUM = int(sys.argv[5])
    sip = get_host_ip()

    print('--------- start reading ---------')
    read_result(filepath,sip)
    print('--------- finish reading ---------')
    
    try:
        t = threading.Thread( target = control,args = (sip,) )
        t.start()
    except:
        print ("Error: unable to start thread")
    
    filter_str = 'icmp and host '+sip
    lock.acquire()
    flag_rcv = True
    print('--------- start sniffing ---------')
    lock.release()
    pkt = sniff(filter = filter_str,prn = invoke_react)
    pass