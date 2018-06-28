# -*- coding: utf-8 -*-
import hashlib
import hmac
import uuid
import base64
import json
import logging
import datetime
from http.client import HTTPSConnection
import urllib.parse as urllib


API_SITE = "alidns.aliyuncs.com"
API_METHOD = "POST"


def _signature(access_id, access_token, params):
    params.update({
        "Format": "json",
        "Version": "2015-01-09",
        "AccessKeyId": access_id,
        "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureMethod": "HMAC-SHA1",
        "SignatureNonce": uuid.uuid4(),
        "SignatureVersion": "1.0",
    })
    query = urllib.urlencode(sorted(params.items()))
    sign_query = API_METHOD + "&" + urllib.quote_plus("/") + "&" + urllib.quote(query, safe="")

    sign = hmac.new((access_token + "&").encode("utf-8"), sign_query.encode("utf-8"), hashlib.sha1).digest()
    sign = base64.b64encode(sign).strip()
    params["Signature"] = sign

    logging.debug("sign_query: %s sign: %s" % (sign_query, sign))
    return params


def _request(access_id, access_token, **params):
    params = _signature(access_id, access_token, params)
    logging.debug(params)

    conn = HTTPSConnection(API_SITE)
    conn.request(API_METHOD, '/', urllib.urlencode(params), {"Content-type": "application/x-www-form-urlencoded"})
    response = conn.getresponse()
    data = response.read()
    conn.close()

    if response.status < 200 or response.status >= 300:
        logging.error("Response error, status: %d", response.status)
        msg = "Unknown"
        try:
            data = json.loads(data.decode("utf-8"))
            msg = data["Message"]
        except Exception as ex:
            pass
        raise RuntimeError(msg)
    else:
        data = json.loads(data.decode("utf-8"))
        logging.debug(data)
        return data


def get_domain_info(access_id, access_token, domain):
    """
    切割域名获取主域名和对应ID
    e.g: http://alidns.aliyuncs.com/?Action=GetMainDomainName&InputString=www.example.com

    :see: https://help.aliyun.com/document_detail/29755.html
    :param access_id: AccessId
    :param access_token: AccessToken
    :param domain: 要查询的域名
    :return: RR记录, 主记录
    """
    data = _request(access_id, access_token, Action="GetMainDomainName", InputString=domain)
    sub, main = data.get("RR", ""), data.get("DomainName", "")
    return sub, main


def get_records(access_id, access_token, domain):
    """
    获取域名记录
    :note: 只取前100条记录
    :param access_id: AccessId
    :param access_token: AccessToken
    :param domain: 待查询域名
    :return: 域名列表
    """
    data = _request(access_id, access_token, Action="DescribeDomainRecords", DomainName=domain, PageSize=100)
    return data["DomainRecords"]["Record"]


def delete_record(access_id, access_token, record_id):
    """
    删除域名解析记录
    :see: https://help.aliyun.com/document_detail/29773.html
    :param access_id: AccessId
    :param access_token: AccessToken
    :param record_id: 域名解析记录ID
    """
    _request(access_id, access_token, Action="DeleteDomainRecord", RecordId=record_id)


def add_record_A(access_id, access_token, domain, RR, ip, ttl=600, line="default"):
    """
    添加A类域名解析记录
    :see: https://help.aliyun.com/document_detail/29772.html
    :param access_id: AccessId
    :param access_token: AccessToken
    :param domain: 域名
    :param RR: RR记录，如要解析"example.com"，则填'@'
    :param ip: 对应解析的IPV4地址
    :param ttl: 生存时间
    :param line: 解析线路
    """
    data = _request(access_id, access_token, Action="AddDomainRecord", DomainName=domain, RR=RR, Type='A', Value=ip,
                    TTL=ttl, Line=line)
    return data["RecordId"]


def update_record_A(access_id, access_token, record_id, RR, ip, ttl=600, line="default"):
    """
    修改A类域名记录
    :see: https://help.aliyun.com/document_detail/29774.html
    :param access_id: AccessId
    :param access_token: AccessToken
    :param record_id: 记录ID
    :param RR: RR记录，如要解析"example.com"，则填'@'
    :param ip: 对应解析的IPV4地址
    :param ttl: 生存时间
    :param line: 解析线路
    """
    _request(access_id, access_token, Action="UpdateDomainRecord", RecordId=record_id, RR=RR, Type='A', Value=ip,
             TTL=ttl, Line=line)


def util_replace_records_A(access_id, access_token, sub_domain, records):
    """
    辅助函数，将A类域名解析用一组新的IP替换
    :param access_id: AccessId
    :param access_token: AccessToken
    :param sub_domain: 子域名，如"my.example.com"
    :param records: 记录值
    """
    # 分离RR和domain
    RR, domain = get_domain_info(access_id, access_token, sub_domain)
    assert RR != "" and domain != ""

    # 获取所有域名记录
    replacable = []
    for i in filter(lambda k: k["RR"] == RR, get_records(access_id, access_token, domain)):
        if i["Type"] == 'A':
            if i["Value"] not in records:
                logging.debug("Record %s expected to be replaced or removed, value is %s" % (i["RecordId"], i["Value"]))
                replacable.append(i["RecordId"])
            else:
                logging.info("Record %s already resolved to %s" % (i["RecordId"], i["Value"]))
                records.remove(i["Value"])

    # 如果replacable的数量超过records的数量，则删掉后面几个
    if len(replacable) > len(records):
        for i in range(len(records), len(replacable)):
            logging.info("Record %s expected to be removed" % replacable[i])
            delete_record(access_id, access_token, replacable[i])
        replacable = replacable[0:len(records)]

    # 更新域名
    for i in records:
        # 如果replacable里面还有东西，就先原地更新
        if len(replacable) > 0:
            id = replacable.pop()
            logging.info("Update record %s to %s" % (id, i))
            update_record_A(access_id, access_token, id, RR, i)
        else:
            # 添加新域名
            logging.info("Add new record %s" % i)
            add_record_A(access_id, access_token, domain, RR, i)

