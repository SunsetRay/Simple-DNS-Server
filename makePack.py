import fetchPack as fet


def make_header(previous_pack, ans_count):
    """制作包头"""
    header = previous_pack[:12]
    # 获取qr
    qr_byte = header[2:3]
    qr_int = int.from_bytes(qr_byte, byteorder='big', signed=False)
    if qr_int < 128:
        qr_int += 128
        # qr位0变成1

    qr_byte = int.to_bytes(qr_int, 1, byteorder='big', signed=False)
    header = header[:2] + qr_byte + header[3:]

    # 修改ancount
    ancount_bytes = int.to_bytes(ans_count, 2, byteorder='big', signed=False)
    header = header[:6] + ancount_bytes + header[8:]

    return header


def change_id(data, id_int):
    """修改包id"""
    id_bytes = int.to_bytes(id_int, 2, byteorder='big', signed=False)
    data = id_bytes + data[2:]
    return data


def make_pack_cname_ip(data_prev, data_mid, cname_ip_list_vector):
    """制作含有cname和ip的应答包"""
    ans_count = 0
    for cname_ip_list in cname_ip_list_vector:
        ans_count += len(cname_ip_list)
    header = make_header(data_prev, ans_count)
    # 包头部分完成
    data = header + data_mid
    ptr = len(data)

    data_pack = fet.analyze_data_pack(data_prev)
    start_byte_pos = data_pack[5]
    ptr_vec = []
    # 存储所有名字的指针位置
    for i in range(0, len(start_byte_pos)):
        ptr_vec.append((data_pack[3][i], data_pack[5][i]))

    i = 0
    data_tail = b''
    class_bytes = b'\x00\x01'
    ttl_bytes = b'\x00\x01\x51\x80'
    for cname_ip_list in cname_ip_list_vector:
        # 对每一个问题，一开始的回答名字肯定是个指针
        name_bytes = convert_pos_to_ptr_bytes(start_byte_pos[i])
        i += 1
        for cname_ip in cname_ip_list:
            # 对每一条资源记录
            if cname_ip[1] == 'A':
                # A
                type_bytes = b'\x00\x01'
                datalen_bytes = b'\x00\x04'
                if cname_ip[0] == '0.0.0.0':  # 拦截功能
                    rcode_byte = data[3:4]
                    rcode_int = int.from_bytes(rcode_byte, byteorder='big', signed=False)
                    if rcode_int % 16 == 0:  # 后4位为0
                        rcode_int += 3  # rcode改为3
                        rcode_byte = int.to_bytes(rcode_int, 1, byteorder='big', signed=False)
                        data = data[:3] + rcode_byte + header[4:]

                addr_bytes = convert_ip_str_to_bytes(cname_ip[0])
                data_tail += name_bytes + type_bytes + class_bytes + ttl_bytes + datalen_bytes + addr_bytes
                ptr += 16
            else:
                # cname,也要负责定位下面一条的name的指针，下一条的name肯定是上一条的结果
                type_bytes = b'\x00\x05'
                is_found, pos = find_name_in_ptr_vec(cname_ip[0], ptr_vec)
                if is_found == 1:
                    datalen_bytes = b'\x00\x02'
                    cname_bytes = convert_pos_to_ptr_bytes(pos)
                    data_tail += name_bytes + type_bytes + class_bytes + ttl_bytes + datalen_bytes + cname_bytes
                    name_bytes = cname_bytes
                    # 下一条的名字，是指针
                    ptr += 14
                else:
                    cname_bytes = convert_dotstr_to_bytes(cname_ip[0])
                    datalen_bytes = int.to_bytes(len(cname_bytes), 2, byteorder='big', signed=False)
                    data_tail += name_bytes + type_bytes + class_bytes + ttl_bytes + datalen_bytes + cname_bytes
                    name_bytes = convert_pos_to_ptr_bytes(ptr + 12)
                    # 下一条的名字，是指针，位置是当前指针加上这个answer的头部分长度
                    ptr_vec.append((cname_ip[0], ptr + 12))
                    ptr += 12 + len(cname_bytes)

    data += data_tail
    # print(ptr_vec)
    return data


def make_mx_pack_cname_ip(data_prev, data_mid, cname_ip_list_vector, mx_count, ns_count, ad_count):
    """制作mx的应答包"""
    ans_count = mx_count
    header = make_header(data_prev, ans_count)
    nscount_bytes = int.to_bytes(ns_count, 2, byteorder='big', signed=False)
    header = header[:8] + nscount_bytes + header[10:]
    adcount_bytes = int.to_bytes(ad_count, 2, byteorder='big', signed=False)
    header = header[:10] + adcount_bytes + header[12:]
    # 包头部分完成
    data = header + data_mid
    ptr = len(data)

    data_pack = fet.analyze_data_pack(data_prev)
    start_byte_pos = data_pack[5]
    ptr_vec = []
    # 存储所有名字的指针位置
    for i in range(0, len(start_byte_pos)):
        ptr_vec.append((data_pack[3][i], data_pack[5][i]))

    data_tail = b''
    class_bytes = b'\x00\x01'
    ttl_bytes = b'\x00\x01\x51\x80'

    # 对mx问题（本程序规定只能有一个），一开始的回答名字肯定是个指针
    name_bytes = convert_pos_to_ptr_bytes(start_byte_pos[0])

    for cname_ip in cname_ip_list_vector:
        # 对每一条资源记录
        if cname_ip[1] == 'MX':
            # MX
            type_bytes = b'\x00\x0f'
            pref_bytes = int.to_bytes(cname_ip[2], 2, byteorder='big', signed=False)
            mx_bytes = convert_dotstr_to_bytes(cname_ip[0])
            datalen_bytes = int.to_bytes(len(mx_bytes)+2, 2, byteorder='big', signed=False)
            # preference也要算在datalen中
            data_tail += name_bytes + type_bytes + class_bytes + ttl_bytes + datalen_bytes + \
                         pref_bytes + mx_bytes

            ptr += 14 + len(mx_bytes)

        elif cname_ip[1] == 'NS':
            # NS
            type_bytes = b'\x00\x02'
            ns_bytes = convert_dotstr_to_bytes(cname_ip[0])
            datalen_bytes = int.to_bytes(len(ns_bytes), 2, byteorder='big', signed=False)
            data_tail += name_bytes + type_bytes + class_bytes + ttl_bytes + datalen_bytes + ns_bytes
            ptr_vec.append((cname_ip[0], ptr + 12))
            ptr += 12 + len(ns_bytes)

        elif cname_ip[1] == 'A':
            type_bytes = b'\x00\x01'
            addr_bytes = convert_ip_str_to_bytes(cname_ip[0])
            datalen_bytes = b'\x00\x04'
            is_find, pos = find_name_in_ptr_vec(cname_ip[2], ptr_vec)
            name_bytes = convert_pos_to_ptr_bytes(pos)
            data_tail += name_bytes + type_bytes + class_bytes + ttl_bytes + datalen_bytes + addr_bytes
            ptr += 16

    data += data_tail
    # print(ptr_vec)
    return data


def convert_dotstr_to_bytes(dotstr):
    """将url字串转换成DNS数据包中的形式，格式为bytes"""
    dotstr_new = '.' + dotstr
    data = dotstr_new.encode('utf-8')
    char_count = -1
    new_str_index = 0
    for char in dotstr:
        char_count += 1
        if char == '.':
            data = data[:new_str_index] + int.to_bytes(char_count, 1, byteorder='big', signed=False) + \
                   data[new_str_index + 1:]
            # 替换成数字
            new_str_index += char_count + 1
            char_count = -1
    data = data[:new_str_index] + int.to_bytes(char_count + 1, 1, byteorder='big', signed=False) + \
           data[new_str_index + 1:]
    # 最后一段
    data += int.to_bytes(0, 1, byteorder='big', signed=False)
    return data


def convert_bytes_to_dotstr(data):
    """将DNS数据包中的形式转换成url"""
    url_bytes = data[:-1]
    url_str = url_bytes.decode('utf-8')

    pointer = 0
    count = 0
    for byte in data:
        if byte == 0:
            break
        count = count + 1
    while pointer < count:
        seg_len = ord(url_str[pointer])
        url_str = url_str[:pointer] + '.' + url_str[pointer + 1:]
        pointer += seg_len + 1

    url_str = url_str[1:]
    return url_str


def convert_bytes_with_pointer_to_dotstr(data, start_pos):
    """将DNS数据包中的形式（含指针）转换成url，从data中的start_pos开始"""
    pointer = 0
    url_bytes = data[start_pos:]
    has_pointer = False

    end_pos = start_pos + 1 - 1
    for byte in url_bytes:
        end_pos = end_pos + 1
        if byte == 0:
            break
        if byte >= 0xc0:
            # 是指针，前两位为1；指针是后向最大匹配的
            end_pos -= 1
            # 跳到指针前面的一个byte
            has_pointer = True
            break

    url_bytes = data[start_pos:end_pos]

    try:
        url_str = url_bytes.decode('utf-8')
    except:
        url_str = ''
        return url_str, end_pos

    if has_pointer:
        end_pos += 2  # 再跳到指针后面的一个byte
        url_bytes = data[start_pos:end_pos]

    while pointer < end_pos - start_pos - 1:
        seg_len = int.from_bytes(url_bytes[pointer:pointer+1], byteorder='big', signed=False)
        # 这段的长度
        if seg_len < 0xc0:
            url_str = url_str[:pointer] + '.' + url_str[pointer + 1:]
            pointer += seg_len + 1
        else:  # 是指针
            url_str = url_str[:pointer]
            new_start_pos = int.from_bytes(url_bytes[pointer:pointer+2], byteorder='big', signed=False)
            new_start_pos -= 0xc000
            # 递归查询，找到指针对应的文本
            new_url_str, new_end_pos = convert_bytes_with_pointer_to_dotstr(data, new_start_pos)
            url_str += new_url_str
            break

    url_str = url_str[:]
    # end_pos是url后第一个字节，指导后面的解包工作
    # 因为是递归，所以这个函数不好裁剪掉第一个和最后一个，应该在外部裁剪
    return url_str, end_pos


def convert_ip_str_to_bytes(ip_str):
    """ip字串转换为bytes"""
    numbers = ip_str.split('.')
    data = b''
    for num in numbers:
        data += int.to_bytes(int(num), 1, byteorder='big', signed=False)
    return data


def convert_bytes_to_ip_str(data):
    """bytes转换为ip字串"""
    ip_str = ''
    for i in range(4):
        ip_str += str(int.from_bytes(data[i: i+1], byteorder='big', signed=False))
        ip_str += '.'
    ip_str = ip_str[:-1]
    return ip_str


def convert_pos_to_ptr_bytes(pos):
    """将位置转化为指针"""
    ptr_bytes = int.to_bytes(pos + 2 ** 15 + 2 ** 14, 2, byteorder='big', signed=False)
    # 指针前两位是11
    return ptr_bytes


def find_name_in_ptr_vec(name, ptr_vec):
    """在名字列表中查找有无匹配的，返回是否找到和对应位置"""
    for name_ptr in ptr_vec:
        if name == name_ptr[0]:
            return 1, name_ptr[1]
    return 0, -1


def tailor_dotstr(url_str):
    """裁剪url_str"""
    if len(url_str) == 0:
        return url_str
    if url_str[0] == '.':
        url_str = url_str[1:]
    if url_str[-1] == '\x00':
        url_str = url_str[:-1]
    return url_str
