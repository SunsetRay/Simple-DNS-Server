import mysql.connector


def init_db():
    """数据库初始化"""
    conn = mysql.connector.connect(host='localhost', port='3306', user='root', password='qq123456',
                                   database='dns_server_db')
    cur = conn.cursor()
    return conn, cur


def get_data_from_db(url, cur):
    query_str = "select value,type from dns where domain_name=\'" + url + "\'"
    cur.execute(query_str)
    record = cur.fetchall()
    record_num = len(record)
    if record_num == 0:
        is_found = 0
    else:
        is_found = 1

    # print(record)

    return is_found, record


def get_mx_pref_from_db(url, value, cur):
    """查找对应的mx记录的preference，在数据库中为方便期间放在ttl下"""
    query_str = "select ttl, domain_name from dns where domain_name=\'" + url + "\' and " \
                "type='MX' and value='"+value+"'"
    cur.execute(query_str)
    record = cur.fetchall()
    record_num = len(record)
    if record_num == 0:
        is_found = 0
    else:
        is_found = 1

    return is_found, record


def sort_by_type(record):
    """将record中的记录分类成4个记录不同类型的record"""
    rec_a = []
    rec_cname = []
    rec_mx = []
    rec_ns = []
    for rec in record:
        if rec[1] == 'A':
            rec_a.append(rec[0])
        if rec[1] == 'CNAME':
            rec_cname.append(rec[0])
        if rec[1] == 'NS':
            rec_ns.append(rec[0])
        if rec[1] == 'MX':
            rec_mx.append(rec[0])
    return rec_a, rec_cname, rec_mx, rec_ns


def recursive_query_cname(cname, cur):
    """递归查询cname，查询到IP返回1，一路上的cname列表（深度优先）和ip，否则返回0"""
    query_str = "select value,type from dns where domain_name=\'" + cname + "\'"
    cur.execute(query_str)
    record = cur.fetchall()
    rec_a, rec_cname, rec_mx, rec_ns = sort_by_type(record)
    cname_ip_list = []
    rec_a_with_tag = []
    ip_found = 0
    for rec in rec_a:
        rec_a_with_tag.append((rec, 'A'))

    if len(rec_a) > 0:
        cname_ip_list.extend(rec_a_with_tag)
        ip_found = 1

    if len(rec_cname) > 0:
        # 如果有cname，逐个进入深搜
        for rec in rec_cname:
            ip_found_in_rec, cname_ip_list_internal = recursive_query_cname(rec, cur)
            if ip_found_in_rec == 1:
                ip_found = 1
                cname_ip_list.append((rec, 'C'))
                cname_ip_list.extend(cname_ip_list_internal)

    # cname_ip_list返回深度优先搜索的结果，不包括函数参数cname本身
    return ip_found, cname_ip_list


def recursive_query_cname_without_a(cname, cur):
    """递归查询cname，查询一路上的cname列表（深度优先）"""
    query_str = "select value,type from dns where domain_name=\'" + cname + "\'"
    cur.execute(query_str)
    record = cur.fetchall()
    rec_a, rec_cname, rec_mx, rec_ns = sort_by_type(record)
    cname_list = []

    if len(rec_cname) > 0:
        # 如果有cname，逐个进入深搜
        for rec in rec_cname:
            cname_list_internal = recursive_query_cname_without_a(rec, cur)
            cname_list.append((rec, 'C'))
            cname_list.extend(cname_list_internal)

    # cname_list返回深度优先搜索的结果，不包括函数参数cname本身
    return cname_list


def insert_record(record, cur, conn):
    """向数据库中插入一条数据，record按顺序为域名、值、类型"""
    query_str = "insert into dns values('"+record[0]+"','"+record[1]+"',86400,'"+\
                record[2]+"','IN')"
    success = True
    try:
        # 执行sql语句
        cur.execute(query_str)
        # 提交到数据库执行
        conn.commit()
    except:
        # Rollback in case there is any error
        conn.rollback()
        success = False

    return success


def learning(data_pack, cur, conn):
    """把从本地dns得到的学习进数据库"""
    pref_count = 0
    is_success = False
    for i in range(0, data_pack[3] + data_pack[4] + data_pack[5]):
        record = [data_pack[8][i], data_pack[11][i], 'A']
        if data_pack[9][i] == 1:  # A
            is_success = insert_record(record, cur, conn)
        if data_pack[9][i] == 5:  # CNAME
            record[2] = 'CNAME'
            is_success = insert_record(record, cur, conn)
        if data_pack[9][i] == 15:  # MX
            record[2] = 'MX'
            record.append(data_pack[10][pref_count])
            is_success = insert_mx_record(record, cur, conn)
            pref_count += 1
        if data_pack[9][i] == 2:  # NS
            record[2] = 'NS'
            is_success = insert_record(record, cur, conn)
    return is_success


def insert_mx_record(record, cur, conn):
    """向数据库中插入一条数据，record按顺序为域名、值、类型、mx优先级"""
    query_str = "insert into dns values('"+record[0]+"','"+record[1]+"',"+str(record[3])+",'"+\
                record[2]+"','IN')"
    success = True
    try:
        # 执行sql语句
        cur.execute(query_str)
        # 提交到数据库执行
        conn.commit()
    except:
        # Rollback in case there is any error
        conn.rollback()
        success = False

    return success
