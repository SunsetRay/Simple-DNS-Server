import socket
import makePack as mkp


def connect_and_listen(ip_addr, port_num):
    """连接并监听端口"""
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    # 地址簇ipv4, 数据报式socket(for UDP)
    sk.bind((ip_addr, port_num))
    return sk


def get_data_from_socket(sk):
    """从socket得到数据并解query包"""
    data, addr = sk.recvfrom(1024)
    data_pack = analyze_data_pack(data)
    return data, addr, data_pack


def analyze_data_pack(data):
    """解query包"""
    # 获取id
    id_str = data[0:2]
    id_int = int.from_bytes(id_str, byteorder='big', signed=False)
    # 网络数据big-endian

    # 获取qr
    qr_str = data[2:3]
    qr_int = int.from_bytes(qr_str, byteorder='big', signed=False)
    if qr_int >= 128:
        qr = 1
        # 获取ancount，应答个数
        anc_str = data[6:8]
        anc_int = int.from_bytes(anc_str, byteorder='big', signed=False)
        anc_current = 0
    else:
        qr = 0
        # 获取qdcount，查询问题个数
        qdc_str = data[4:6]
        qdc_int = int.from_bytes(qdc_str, byteorder='big', signed=False)
        qdc_current = 0

    # 对于question包，逐个获取url，并转化格式，获取类型
    if qr == 0:
        start_byte_pos = []
        count = 12
        url_list = []
        type_list = []
        while qdc_int > qdc_current:
            qdc_current += 1
            # 目前是第几个问题的url
            prev_count = count + 1 - 1
            tail = data[prev_count:]
            start_byte_pos.append(prev_count)
            for byte in tail:
                if byte == 0:
                    break
                count = count + 1
                # count为这段尾部为0的位置
            url_bytes = data[prev_count:count]
            url_str = url_bytes.decode('utf-8')

            pointer = 0
            while pointer < count - prev_count:
                seg_len = ord(url_str[pointer])
                url_str = url_str[:pointer] + '.' + url_str[pointer + 1:]
                pointer += seg_len + 1

            url_str = url_str[1:]
            url_list.append(url_str)

            # 获取类型
            type_bytes = data[count + 1:count + 3]
            type_int = int.from_bytes(type_bytes, byteorder='big', signed=False)
            type_list.append(type_int)

            count += 5

        data_pack = [id_int, qr, qdc_int, url_list, type_list, start_byte_pos]
    else:
        # 对于answer包
        data_pack = [id_int, qr, anc_int]

    return data_pack


def analyze_response_data(data):
    """解answer包"""
    # 获取id
    id_str = data[0:2]
    id_int = int.from_bytes(id_str, byteorder='big', signed=False)
    # 网络数据big-endian

    # 获取qr
    qr_str = data[2:3]
    qr_int = int.from_bytes(qr_str, byteorder='big', signed=False)
    if qr_int >= 128:
        qr = 1
        # 获取qdcount，查询问题个数
        qdc_str = data[4:6]
        qdc_int = int.from_bytes(qdc_str, byteorder='big', signed=False)
        qdc_current = 0
        # 获取ancount，应答个数
        anc_str = data[6:8]
        anc_int = int.from_bytes(anc_str, byteorder='big', signed=False)
        anc_current = 0
        # 获取nscount，权威应答个数
        nsc_str = data[8:10]
        nsc_int = int.from_bytes(nsc_str, byteorder='big', signed=False)
        # 获取arcount，应答个数
        arc_str = data[10:12]
        arc_int = int.from_bytes(arc_str, byteorder='big', signed=False)
    else:
        qr = 0

    # 对于question包，逐个获取url，并转化格式，获取类型
    if qr == 1:
        count = 12  # 是整个解包过程中的位置指针
        q_url_list = []
        q_type_list = []
        # Query部分
        while qdc_int > qdc_current:
            qdc_current += 1
            # 目前是第几个问题的url
            prev_count = count + 1 - 1
            tail = data[prev_count:]
            for byte in tail:
                if byte == 0:
                    break
                count = count + 1
                # count为这段尾部为0的位置
            url_bytes = data[prev_count:count]
            url_str = url_bytes.decode('utf-8')

            pointer = 0
            while pointer < count - prev_count:
                seg_len = ord(url_str[pointer])
                url_str = url_str[:pointer] + '.' + url_str[pointer + 1:]
                pointer += seg_len + 1

            url_str = url_str[1:]
            q_url_list.append(url_str)

            # 获取类型
            type_bytes = data[count + 1:count + 3]
            type_int = int.from_bytes(type_bytes, byteorder='big', signed=False)
            q_type_list.append(type_int)

            count += 5
        data_pack = [id_int, qr, qdc_int, anc_int, nsc_int, arc_int, q_url_list, q_type_list]

        # Answer部分
        a_url_list = []
        a_type_list = []
        a_val_list = []
        a_mx_preference = []
        while anc_int + nsc_int + arc_int > anc_current:
            anc_current += 1
            a_url, count = mkp.convert_bytes_with_pointer_to_dotstr(data, count)
            a_url = mkp.tailor_dotstr(a_url)  # 外部裁剪最后一个00和第一个.
            a_url_list.append(a_url)
            type_int = int.from_bytes(data[count:count+2], byteorder='big', signed=False)
            a_type_list.append(type_int)
            count += 10  # 跳过无用信息
            if not type_int == 1:  # 不为A
                if type_int == 15:  # MX的优先级要考虑
                    pref = int.from_bytes(data[count:count + 2], byteorder='big', signed=False)
                    count += 2
                    a_mx_preference.append(pref)

                a_val, count = mkp.convert_bytes_with_pointer_to_dotstr(data, count)
                a_val = mkp.tailor_dotstr(a_val)  # 外部裁剪最后一个00和第一个.

            else:  # A,4个数
                a_val = mkp.convert_bytes_to_ip_str(data[count:count+4])
                count += 4
            a_val_list.append(a_val)
        data_pack.append(a_url_list)
        data_pack.append(a_type_list)
        data_pack.append(a_mx_preference)
        data_pack.append(a_val_list)

    else:
        # 对于question包
        data_pack = [id_int, qr]

    return data_pack
