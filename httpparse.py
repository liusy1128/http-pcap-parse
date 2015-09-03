#encoding=utf-8
# -*- coding:gb2312 -*-
import time
import dpkt
import socket
import string
import httpdb
import commonlib
import httpmutithread


#对url进行整形，暂时只对部分网址进行解析
#存在bug，对于多种url组合时，存在问题，解决思路是取出每种url的位置，取最小的一个
def urlformat(url):
    err = 0
    test = url.find('.net') #http://blog.chinaunix.net
    if test != -1:
        num = test+4
        format_url = url[0:num]
        return format_url,err

    test = url.find('.org') #http://www.ietf.org/
    if test != -1:
        num = test+4
        format_url = url[0:num]
        return format_url,err
    
    test = url.find('.com')#www.baidu.com
    if test != -1 :
        cnnum = url.find('.com.cn') #www.sina.com.cn
        if cnnum == -1: #.com网址
            num = test+4
        elif test == cnnum: #.com.cn网址
            num = test+7
        else:#在.com网址中访问了.com.cn网址，取第一个
            num = test+4
        format_url = url[0:num]
        return format_url,err
    
    test = url.find('.cn')
    if test != -1:
        num = test+3
        format_url = url[0:num]
        return format_url,err
    
    err = 1
    return url,err


#对http头部协议字段进行解析
def formatheader(http,keyvalue):
    find = 0
    for k,v in http.headers.iteritems():
        if k == keyvalue:
             return v
    return None

#对报文中，get 后的字符进行整理
def httpGetItemformat(tcpdata):
    end = tcpdata.find('Host')
    if end == -1:
        return None
    #去掉换行回车
    end = end-2
    start = tcpdata.find('GET')
    if start == -1:
        return None
    if start > end:
        return None
    start = start + 3
    format_Get = tcpdata[start:end]
    return format_Get

def httpPacketParse(buf,dbTableName,ts):
    
    tabel_line = {}  #数据库行存储结构
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type!=2048:
        return
             
    ip = eth.data
    if ip.p != 6:
        return
    
    tcp = ip.data
    #重点关注客户报文，网页内容暂不关注
    if len(tcp.data) > 0:
        if tcp.dport == 80 :
            try:
                http = dpkt.http.Request(tcp.data)
            except:       
                #i = i+1
                return
        
            find = 0
            #print '===================================='
            for k,v in http.headers.iteritems():
                if k == 'referer':
                    find = 1
                    break
                if find != 1:
                    for k,v in http.headers.iteritems():
                        if k == 'origin':
                            break
               
            tabel_line['timestamp'] = ts
            tabel_line['sip'] = socket.inet_ntoa(ip.src)
            tabel_line['dip'] = socket.inet_ntoa(ip.dst)
            tabel_line['sport'] = tcp.sport
            tabel_line['dport'] = tcp.dport
            tabel_line['method'] = http.method
            url= urlformat(v)
            tabel_line['url'] = url[0]
            tabel_line['get'] = httpGetItemformat(tcp.data)
            tabel_line['accept-language'] = formatheader(http,'accept-language')
            tabel_line['accept-encoding'] = formatheader(http,'accept-encoding')
            tabel_line['connection'] = formatheader(http,'connection')
            tabel_line['accept'] = formatheader(http,'accept')
            tabel_line['host'] = formatheader(http,'host')
            tabel_line['referer'] = formatheader(http,'referer')
            tabel_line['origin'] = formatheader(http,'origin')
            tabel_line['Cache-Control'] = formatheader(http,'cache-control')
            tabel_line['Cookie'] = formatheader(http,'cookie')
            tabel_line['tcp_packet'] = None #不存储报文

            if url[1] == 0:
                if commonlib.IsSupportMutiThread() != 0:
                    httpmutithread.PutDatatoQueue(tabel_line)
                else :
                    httpdb.insert(dbTableName,tabel_line)
                        
            tabel_line.clear()
