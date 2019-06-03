import socket
import re
import codecs
import dbQuery as dbq
import fetchPack as fet
import makePack as mkp
import threading as thr
import queue
import time
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('-s', "--dnsserver", default='None',
                    help="Manually assign a local dns server")
parser.add_argument('-f', "--configfile", default='config.txt',
                    help="Manually assign a config file")
group = parser.add_mutually_exclusive_group()
# 定义互斥参数dd和d
group.add_argument('-d', "--debugs", help="Output simple debug information", action="store_true")
group.add_argument('-dd', "--debugc", help="Output complex debug information", action="store_true")
args = parser.parse_args()
debug_simple = args.debugs
debug_complex = args.debugc
debug_none = False
if debug_simple:
    debug_level = 'Simple Output'
elif debug_complex:
    debug_level = 'Complex Output'
else:
    debug_level = 'None'
    debug_none = True
config_file = args.configfile

# dns_auth_server_a = '202.106.0.20'
dns_auth_server_b = '202.106.196.115'
f = codecs.open(config_file, "r", encoding='utf-8')
lines = f.readlines()
f.close()
dns_auth_server_a = re.sub('default_dns=', '', lines[0].strip())
is_learning = re.sub('learning=', '', lines[1].strip())

if not args.dnsserver == 'None':
    dns_auth_server_a = args.dnsserver

print("Local DNS Server:" + dns_auth_server_a)
print("Debug:" + debug_level)
print("Config File:" + config_file)
print("Learning:" + str(is_learning))

conn, cur = dbq.init_db()
mutex_1 = thr.Lock()
mutex_2 = thr.Lock()
mutex_3 = thr.Lock()
mutex_4 = thr.Lock()
mutex_5 = thr.Lock()  # 数据库互斥访问
pack_id = 0
data_buffer_1 = queue.Queue()
# 从浏览器收到的包，准备进入数据库查询
data_buffer_2 = queue.Queue()
# 要发回浏览器的包
data_buffer_3 = queue.Queue()
# 要发往DNS服务器的包
data_buffer_4 = {}
# 维护一个还在查询中的包的（地址，编号）映射表（字典）

'''
b = mkp.convert_dotstr_to_bytes('www.baidu.com.cni')
print(b)
c = mkp.convert_bytes_to_dotstr(b)
print(c)
d = mkp.convert_ip_str_to_bytes('192.168.1.1')
print(d)
e = mkp.convert_bytes_to_ip_str(d)
print(e)
f = mkp.convert_pos_to_ptr_bytes(12)
print(f)
'''


def trans(s):
    return "b'%s'" % ''.join('\\x%.2x' % x for x in s)


def get_data_from_apps():
    """收到应用发来的请求包并存在包队列中"""
    global mutex_1, data_buffer_1
    while 1:
        # print(1)
        time.sleep(0.005)
        data, addr, data_pack = fet.get_data_from_socket(q)
        if not debug_none:
            print(data_pack)
        mutex_1.acquire()
        while data_buffer_1.qsize() >= 100:
            data_buffer_1.get()
            # 丢弃超过缓冲区大小的包

        data_buffer_1.put((data, addr, data_pack))
        # print(data_buffer_1.qsize())
        mutex_1.release()
    return


def query_ip():
    """向数据库查询ip，如果查到了则返回，查不到则进入本地DNS查询队列"""
    global mutex_1, mutex_2, mutex_3, mutex_4, pack_id, data_buffer_4, data_buffer_1, data_buffer_3
    global conn, cur
    while 1:
        # print(2)
        time.sleep(0.005)
        need_query = 1
        # 默认是不需要询问本地DNS服务器。不需要=1，需要=0
        mutex_1.acquire()
        if not data_buffer_1.empty():
            (data, addr, data_pack) = data_buffer_1.get()
            mutex_1.release()
        else:
            mutex_1.release()
            continue

        mutex_4.acquire()
        while len(data_buffer_4) >= 200:
            data_buffer_4.popitem()
            # 超过映射表大小随机丢弃一个包，这个区比缓冲区大一些更好，以防止没必要的丢包

        # 内部编号，是在查询过程中使用的编号，由地址和原编号共同决定，映射关系存储在data_buffer_4中
        pack_id = pack_id + 1
        pack_id = pack_id % 65536
        data = mkp.change_id(data, pack_id)
        # 修改id
        data_buffer_4[pack_id] = (addr, data_pack[0])
        mutex_4.release()

        record_list = []
        # 多个问题的回答
        for url in data_pack[3]:
            mutex_5.acquire()
            is_found, record = dbq.get_data_from_db(url, cur)
            # record是一个查询对应的全部记录，包里有多个查询
            mutex_5.release()
            if is_found == 0:
                need_query = 0
                break
            record_list.append(record)
            # 从数据库获得URL对应ip地址，并判断是否需要问本地DNS服务器，如果包中一条记录查询不到则需要

        if need_query == 1:
            # 数据库中有查询结果
            has_mx = 0
            cname_ip_list_vec = []
            # 存放组装包尾需要的信息
            data_mid = data[12:]
            # 取包的中部，不用考虑后面不是question的部分，问题包后面没有尾巴
            for i in range(0, len(record_list)):
                # 对每个问题
                if data_pack[4][i] == 1:
                    # 如果是A类型(1)查询
                    rec_a, rec_cname, rec_mx, rec_ns = dbq.sort_by_type(record_list[i])
                    rec_a_with_tag = []
                    for rec in rec_a:
                        rec_a_with_tag.append((rec, 'A'))
                    if (len(rec_cname) == 0) and (len(rec_a) != 0):
                        # 只有A的记录
                        cname_ip_list_vec.append(rec_a_with_tag)
                    elif (len(rec_cname) != 0) and (len(rec_a) != 0):
                        # 有A也有CNAME，查cname，合并入(extend)A的列表rec_a
                        for rec in rec_cname:
                            mutex_5.acquire()
                            ip_found, cname_ip_list = dbq.recursive_query_cname(rec, cur)
                            mutex_5.release()
                            if ip_found == 1:
                                # 如果找到有A的记录，将查询过程全部记录下来，之后要加入包中
                                cname_ip_list.insert(0, (rec, 'C'))
                                rec_a_with_tag.extend(cname_ip_list)
                        cname_ip_list_vec.append(rec_a_with_tag)
                    elif (len(rec_cname) != 0) and (len(rec_a) == 0):
                        # 无A有CNAME，查cname，合并入(extend)A的列表rec_a，
                        # 如果递归查询后也无A则向本地dns查
                        need_query = 0
                        for rec in rec_cname:
                            mutex_5.acquire()
                            ip_found, cname_ip_list = dbq.recursive_query_cname(rec, cur)
                            mutex_5.release()

                            if ip_found == 1:
                                # 如果找到有A的记录，将查询过程全部记录下来，之后要加入包中
                                cname_ip_list.insert(0, (rec, 'C'))
                                rec_a_with_tag.extend(cname_ip_list)
                                need_query = 1
                        cname_ip_list_vec.append(rec_a_with_tag)

                elif data_pack[4][i] == 5:
                    # 如果是CNAME类型(5)查询，也要递归查询所有的CName
                    rec_a, rec_cname, rec_mx, rec_ns = dbq.sort_by_type(record_list[i])
                    # 无A有CNAME，查cname，合并入(extend)A的列表rec_a，
                    # 如果递归查询后也无A则向本地dns查
                    if len(rec_cname) > 0:
                        # 有CNAME记录
                        need_query = 1
                        for rec in rec_cname:
                            mutex_5.acquire()
                            cname_ip_list = dbq.recursive_query_cname_without_a(rec, cur)
                            mutex_5.release()
                            cname_ip_list.insert(0, (rec, 'C'))
                            cname_ip_list_vec.append(cname_ip_list)
                    else:
                        need_query = 0

                elif data_pack[4][i] == 15:
                    # 如果是MX类型(15)查询，先找mx的记录，再查NS，再根据NS查A
                    has_mx = 1
                    if i > 0 or len(record_list) > 1:  # 不处理多个的
                        need_query = 0
                        break
                    rec_a, rec_cname, rec_mx, rec_ns = dbq.sort_by_type(record_list[i])
                    ad_count = 0
                    for rec in rec_mx:
                        mutex_5.acquire()
                        is_found_pref, ttl = dbq.get_mx_pref_from_db(data_pack[3][i], rec, cur)
                        mutex_5.release()
                        if is_found_pref:
                            cname_ip_list_vec.append((rec, 'MX', ttl[0][0]))
                    for rec in rec_ns:
                        cname_ip_list_vec.append((rec, 'NS'))
                    for rec in rec_ns:
                        # 这里不需要递归查询，最后ns对应的value只有A
                        mutex_5.acquire()
                        is_found, record = dbq.get_data_from_db(rec, cur)  # (data, type)的列表
                        mutex_5.release()
                        for record_dt in record:
                            if record_dt[1] == 'A':
                                cname_ip_list_vec.append((record_dt[0], 'A', rec))
                                ad_count += 1

                    if not len(cname_ip_list_vec) == 0:
                        new_data = mkp.make_mx_pack_cname_ip(data, data_mid,
                                                             cname_ip_list_vec,
                                                             len(rec_mx),
                                                             len(rec_ns),
                                                             ad_count)
                        q_auth.sendto(new_data, (dns_auth_server_b, 53))
                        # 再往外发一次，要让wireshark能抓到并分析，以测试结果

                        # 将组好的包放进data_buffer_2中传回
                        mutex_2.acquire()
                        while data_buffer_2.qsize() >= 100:
                            data_buffer_2.get()
                            # 丢弃超过缓冲区大小的包
                        data_buffer_2.put(new_data)
                        mutex_2.release()

                    else:
                        need_query = 0

                    break

                else:
                    need_query = 0

            if not debug_none:
                if not len(cname_ip_list_vec) == 0:
                    print('Database query answer:')
                    print(cname_ip_list_vec)

            if not has_mx:
                if not len(cname_ip_list_vec) == 0:
                    # 可能出现AAAA等类型，数据库里虽有A数据但没有AAAA的数据
                    new_data = mkp.make_pack_cname_ip(data, data_mid, cname_ip_list_vec)
                    q_auth.sendto(new_data, (dns_auth_server_b, 53))
                    # 再往外发一次，注意是发到另一个地方以标识是往外发的包
                    # 要让wireshark能抓到并分析，以测试结果

                    # 将组好的包放进data_buffer_2中传回
                    mutex_2.acquire()
                    while data_buffer_2.qsize() >= 100:
                        data_buffer_2.get()
                        # 丢弃超过缓冲区大小的包
                    data_buffer_2.put(new_data)
                    mutex_2.release()

            else:
                need_query = 0

        if need_query == 0:
            # 发往DNS本地服务器
            mutex_3.acquire()
            while data_buffer_3.qsize() >= 100:
                data_buffer_3.get()
                # 丢弃超过缓冲区大小的包
            data_buffer_3.put(data)
            mutex_3.release()

    return


def send_to_dns():
    """将data_buffer3的包发往本地DNS服务器"""
    global mutex_3, q_auth, data_buffer_3
    while 1:
        # print(3)
        time.sleep(0.005)
        mutex_3.acquire()
        if not data_buffer_3.empty():
            data = data_buffer_3.get()
            mutex_3.release()
        else:
            mutex_3.release()
            continue

        q_auth.sendto(data, (dns_auth_server_a, 53))
    return


def get_from_dns():
    """从本地DNS服务器接收包到data_buffer_2"""
    global mutex_2, q_auth, data_buffer_2, mutex_5
    while 1:
        # print(4)
        time.sleep(0.005)
        mutex_2.acquire()
        while data_buffer_2.qsize() >= 100:
            data_buffer_2.get()
            # 丢弃超过缓冲区大小的包
        mutex_2.release()

        data_auth, addr_auth = q_auth.recvfrom(1024)
        data_pack = fet.analyze_response_data(data_auth)
        if not debug_none:
            print('Received from local DNS:')
            if not debug_simple:
                print(data_pack)
            else:
                print(data_pack[:8])
            print()  # \n

        if is_learning:
            mutex_5.acquire()
            dbq.learning(data_pack, cur, conn)
            mutex_5.release()

        mutex_2.acquire()
        data_buffer_2.put(data_auth)
        mutex_2.release()
    return


def return_to_apps():
    """从data_buffer_2返回包给对应的应用"""
    global mutex_2, mutex_4, q_auth_2, data_buffer_2, data_buffer_4
    while 1:
        # print(5)
        time.sleep(0.005)
        mutex_2.acquire()
        if not data_buffer_2.empty():
            data = data_buffer_2.get()
            mutex_2.release()
        else:
            mutex_2.release()
            continue

        p_id = fet.analyze_data_pack(data)[0]

        mutex_4.acquire()
        if p_id not in data_buffer_4:
            mutex_4.release()
            continue
        addr_and_id = data_buffer_4.get(p_id)
        del data_buffer_4[p_id]
        mutex_4.release()

        addr = addr_and_id[0]
        old_id = addr_and_id[1]
        data = mkp.change_id(data, old_id)
        q_auth_2.sendto(data, addr)
    return


q = fet.connect_and_listen('127.0.0.1', 53)
q_auth = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
q_auth.sendto(b'', (dns_auth_server_a, 53))
q_auth_2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


t1 = thr.Thread(target=get_data_from_apps, args=())
t1.start()
t2 = thr.Thread(target=query_ip, args=())
t2.start()
t3 = thr.Thread(target=send_to_dns, args=())
t3.start()
t4 = thr.Thread(target=get_from_dns, args=())
t4.start()
t5 = thr.Thread(target=return_to_apps, args=())
t5.start()
