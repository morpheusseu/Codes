#-----scapy | networkx | matplotlib needed via sudo pip install scapy | networkx | matplotlib
#-----input ploth.py [filepath]
#-----example : python3 ploth.py filepath[ip_link_12_4_19_1.txt]
#-----
import networkx as nx
import matplotlib
import matplotlib.pyplot as plt
import sys
import threading
import time
positive_ip = {}#{ index1:ip1 , index2:ip2 , ... }
ip_degree = {}#{ (index1,ip1) : degree1 , (index2,ip2) : degree2 , ... }
degree_ip = {}#{ degree1 : [number1,[ip1,ip2,ip3,...]] , degree2 : [number2,[...]] , ...}
ip_ip = []#[ (index1,index2) , (index1,index3) , ...]
ip_net = []#[ (ip1,ip2) , (ip1,ip3) , (ip1,net1) , ... ] net : 192.168:[number of ip beneath the subnet]
iplinkpath = 'ip_link_11_11_22_47.txt'

G = nx.Graph()

def read_ip_link(ip_link_path):
    global ip_ip
    NET_ALLOWANCE = 3
    ip_link = []
    with open(ip_link_path,'r') as f_r:
        while True:
            str1 = f_r.readline()
            if str1 == '':
                break
            elif str1[:5] == 'total':
                print(str1.replace('\n',''))
                continue
            str1 = str1.replace('=>',',').replace(' ','').replace('\n','') 
            line = str1.split(',')
            ip_link.append(line)
    #throw out ***.***.***.*** start
    for i in range(len(ip_link)):
        while True:
            if '***.***.***.***' in ip_link[i]:
                flag_finish = False
                line = ip_link[i]
                len_line = len(line)
                index = line.index('***.***.***.***')
                if index == 0:
                    print('***.***.***.*** at head of routine\n')
                    break
                cur = line[index]
                pre = line[index-1]
                num_unknown = 1
                post = line[index+num_unknown]
                #print('pre : ',line,' | line : '+str(i))
                isBreak = False
                while index + num_unknown < len_line:
                    if post == cur:
                        if index + num_unknown == len_line -1:
                            isBreak = True
                            break
                        else:
                            num_unknown += 1
                            post = line[index + num_unknown]
                    else:
                        break
                if isBreak:
                    print('***.***.***.*** at end of routine\n')
                    break

                for j in range(i+1,len(ip_link)):
                    line_j = ip_link[j]
                    if post in line_j and pre in line_j and line_j.index(post) - line_j.index(pre) == num_unknown + 1:
                        index_j = line_j.index(pre) + 1
                        flag_finish = False
                        for k in range(num_unknown):
                            if line_j[index_j+k] != '***.***.***.***':
                                ip_link[i][index+k]=line_j[index_j+k]
                                flag_finish = True
                        if flag_finish == True:
                            print('post :',line_j,'| line : '+str(j))
                            print('repair :',ip_link[i],'| line : '+str(i))
                            break
                
                if flag_finish == False:
                    print('unsolved : ',line,' | line : '+str(i))
                    break
            else:
                break
    #print(ip_link)
    #throw out ***.***.***.*** done
    #ip_link list => ip_ip list
    #ip_ip = []
    for line in ip_link:
        pre = 0
        for i in range(1,len(line)):
            tup = (line[pre],line[i])
            tup_r = (line[i],line[pre])
            if tup in ip_ip or tup_r in ip_ip:
                pass
            else:
                ip_ip.append(tup)
            pre = i
    #finish ip_ip
    #ip_ip list => ip_degree dict
    ip_degree = {}#{ ip1 : degree1 , ip2 : degree2 , ... }
    for tup_t in ip_ip:
        A = tup_t[0]
        B = tup_t[1]
        if A in ip_degree:
            ip_degree[A] += 1
        else:
            ip_degree[A] = 1
        if B in ip_degree:
            ip_degree[B] += 1
        else:
            ip_degree[B] = 1
    #finish ip_degree
    #ip_degree dict => degree_1 list
    degree_1 = []
    for key in ip_degree.keys():
        if ip_degree[key] == 1:
            degree_1.append(key)
    ip_degree.clear()
    #finish degree_1
    #ip_ip list&degree_1 list => ip_end dict
    ip_end = {}#{ ip1 : [end1,end2,...], ip2 : [end1,end2,...]}
    ip_ip_del = []
    for tup_t in ip_ip:
        A = tup_t[0]
        B = tup_t[1]
        flag = 0# 0 unknown/A&B!degree_1-> | 1 A->degree_1 | 2 B->degree_1 | 3 A&B->degree_1
        if A in degree_1:
            flag = 1
        if B in degree_1:
            if flag == 1:
                flag = 3
            else:
                flag = 2
        if flag == 0:
            pass
        elif flag == 1:
            if B in ip_end:
                ip_end[B].append(A)
            else:
                ip_end[B] = [A]
            ip_ip_del.append(tup_t)
        elif flag == 2:
            if A in ip_end:
                ip_end[A].append(B)
            else:
                ip_end[A] = [B]
            ip_ip_del.append(tup_t)
        else:
            print(tup_t,' each has 1 degree')
    degree_1.clear()
    for del_o in ip_ip_del:
        ip_ip.remove(del_o)
    #finish ip_end
    #ip_ip list & ip_end dict => ip_ip list
    for key in ip_end.keys():
        net = {}#{'a.b':[subnet8bit,len,num],...}
        #11111111.11111111.11111111.00000000 00000000:0 10000000:128 11000000:192 11100000:224 11110000:240 11111000:248 11111100:252 11111110:254 11111111:255
        ip_list = ip_end[key]
        if len(ip_list) <= NET_ALLOWANCE:
            for ip_ in ip_list:
                ip_ip.append((key,ip_))
            continue
        for ip_ in  ip_list:
            index1 = ip_.index('.')
            index2 = ip_[index1+1:].index('.') + index1 + 1
            index3 = ip_[index2+1:].index('.') + index2 + 1
            subnet_num = int(ip_[index2+1:index3])
            subnet = bin(256+subnet_num)[3:]
            tup = [ip_[:index2],subnet,8]#[subnet01,subnet2,len0~8]
            if tup[0] in net:#{'a.b':[subnet8bit,len,num],...}
                if net[tup[0]][1] == 0:
                    net[tup[0]][2] += 1
                    continue
                length = 0
                for i in range(8):
                    if tup[1][i] == net[tup[0]][0][i]:
                        length += 1
                    else:
                        net[tup[0]][0]=net[tup[0]][0][:i] + '0' * (8-i)
                net[tup[0]][1] = length    
                net[tup[0]][2] += 1
            else:
                net[tup[0]] = [tup[1],tup[2],1]
        for key_ in net.keys():
            value = net[key_]
            num = int(value[0],2)
            subnet = key_+'.'+str(num)+'.0/'+str(value[1]+16)+':'+str(value[2])
            print(value[0],'=>',num,':',subnet)
            ip_ip.append((key,subnet))
    filepath = 'ip_net'+ip_link_path[ip_link_path.index('_'):]
    with open(filepath,'w') as f_w:
        for key in ip_end.keys():
            f_w.write('node : '+key+'\n')
            f_w.write('end : ')
            loop = 0
            MAX_LOOP = 10
            for ip_ in ip_end[key]:
                tmp = ''
                if loop == 0:
                    tmp += '\n   | '
                loop += 1
                loop = loop % MAX_LOOP
                tmp += ip_ + ' => '
                f_w.write(tmp)
            f_w.write('\n')

def import_graph():
    global iplinkpath
    global ip_ip
    global G
    
    pngpath = iplinkpath
    G.add_edges_from(ip_ip)

    colors_node = []
    colors_edge = []
    for node in G.nodes():
        colors_node.append('#0000FF')
    for edge in G.edges():
        colors_edge.append('#FFC0CC')

    nx.draw(G,node_size=10,node_color = colors_node,edge_color = colors_edge,alpha = 1,pos = nx.spring_layout(G),with_labels = True,font_size = 12)
    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(18.5, 10.5)
    index = pngpath.index('.')
    pngpath = pngpath[:index+1]
    pngpath += 'png'
    print('save image to '+pngpath)
    fig.savefig(pngpath,dpi=300)
    plt.savefig('last.png',dpi=300)
    plt.show()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        iplinkpath = sys.argv[1]
    read_ip_link(iplinkpath)
    import_graph()