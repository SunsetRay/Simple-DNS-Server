import socket
import dbQuery as dbq
import fetchPack as fet
import makePack as mkp
import threading as thr

dns_auth_server_a = '202.106.0.20'
dns_auth_server_b = '202.106.196.115'

is_found, record = dbq.get_data_from_db('www.bupt.edu.cn')
q = fet.connect_and_listen('127.0.0.1', 53)
while 1:
    data, addr, data_pack = fet.get_data_from_socket(q)
    if data_pack[1] == 0:
        # question包
        q_auth = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        q_auth.sendto(data, (dns_auth_server_a, 53))
        q_auth.settimeout(0.5)
        while 1:
            try:
                data_auth, addr_auth = q_auth.recvfrom(1024)
            except:
                print("query failed, abandoned")
                break
            else:
                break

        # print(data_auth)
        # print(addr_auth)
        q_auth.sendto(data_auth, addr)

