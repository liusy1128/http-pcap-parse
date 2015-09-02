#encoding=utf-8
# -*- coding:gb2312 -*-
import dpkt
import socket
import time
import httpdb
import statistics
import os.path
import string



# 秒转化为日期
def timeformat_sec_to_date(timestamp):
    timeArray = time.localtime(timestamp)
    otherStyleTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
    return otherStyleTime

#日期转化为妙
def timeformat_date_to_sec(timestamp):
    tup_birth = time.strptime(timestamp, "%Y-%m-%d %H:%M:%S");
    birth_secds = time.mktime(tup_birth)
    return birth_secds

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

def httpGetformat(tcpdata):
    end = tcpdata.find('host')
    if end == -1:
        return None
    start = tcpdata.find('get')
    if start == -1:
        return None
    if start > test:
        return None
    start = start + 3
    format_Get = tcpdata[start:end]
    return format_Get
    

firsttime = 0
lasttime = 0
tabel_line = {}  #数据库行存储结构


def formatheader(http,keyvalue):
    find = 0
    for k,v in http.headers.iteritems():
        if k == keyvalue:
             return v
    return None

def httpGetformat(tcpdata):
    end = tcpdata.find('Host')
    if end == -1:
        return None
    
    start = tcpdata.find('GET')
    if start == -1:
        return None
    if start > end:
        return None
    start = start + 3
    format_Get = tcpdata[start:end]
    return format_Get

     
def packet_import_to_db(filename,dbTableName):
    not_ip_packet = 0  #记录抓取的报文中非ip包的个数
    not_tcp_packet = 0 #记录抓取的报文中非tcp包的个数
    f = open(filename,'rb')
    #f = open('2015083003.pcap','rb')
    
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        f.close()
        return
    
    cur = httpdb.opendata(dbTableName)  #数据库的conn
    conn = cur[1]
    i = 1#报文编号，记录wireshark中的序号，便于调试
    for ts,buf in pcap:
        #记录第一个报文时间
        if i == 1:
            firsttime = ts

        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type!=2048:
            #print 'not ip packet %d'%i
            not_ip_packet =  not_ip_packet+1
            i= i+1
            continue
             
        ip = eth.data
        if ip.p != 6:
            #print 'not tcp packet %d'%i
            not_tcp_packet = not_tcp_packet + 1
            i= i+1
            continue
        tcp = ip.data
        
        #if tcp.dport == 80 and len(tcp.data) > 0:
        if len(tcp.data) > 0:
            #print 'packet num %d'%i
            if tcp.dport == 80 :
                try:
                    http = dpkt.http.Request(tcp.data)
                except:
                   
                    i = i+1
                    continue
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
                
                tabel_line['get'] = httpGetformat(tcp.data)
                tabel_line['accept-language'] = formatheader(http,'accept-language')
                tabel_line['accept-encoding'] = formatheader(http,'accept-encoding')
                tabel_line['connection'] = formatheader(http,'connection')
                tabel_line['accept'] = formatheader(http,'accept')
                tabel_line['host'] = formatheader(http,'host')
                tabel_line['referer'] = formatheader(http,'referer')
                tabel_line['origin'] = formatheader(http,'origin')
                tabel_line['Cache-Control'] = formatheader(http,'cache-control')
                tabel_line['Cookie'] = formatheader(http,'cookie')
                
                tabel_line['tcp_packet'] = tcp.data


                if url[1] == 0: 
                    httpdb.insert(dbTableName,tabel_line,conn)
                    
                tabel_line.clear()
            #重点关注客户报文，网页内容暂不关注
            if tcp.sport == 80 :
                try:
                    http = dpkt.http.Response(tcp.data)
                except:
                    #print 'response err'
                    i = i+1
                    continue      

        i = i+1
        if i%3000 == 0:
            print '正在读取pcap文件到数据库中，请稍等'
    #记录最后一个报文时间
    lasttime = ts
    httpdb.closedata(conn)
    f.close()

    #print 'this pcap file pcap packet from %s to %s'%(timeformat_sec_to_date(firsttime),timeformat_sec_to_date(lasttime))
    

def url_make_cmdStr(dbTableName):
    
    firsttime =  httpdb.GetMin_timestamp(dbTableName)
    lasttime = httpdb.GetMax_timestamp(dbTableName)
    print 'pcap文件中http报文的时间段是从 %s 到 %s'%(timeformat_sec_to_date(firsttime),timeformat_sec_to_date(lasttime))
    whileflag = True

    while flag :
        print '请输入开始时间，按照后面的格式: 2015-08-23 17:11:57'
        tempStr = '开始时间应该晚于 %s\r\n'%timeformat_sec_to_date(firsttime)
        startime_date = str(raw_input(tempStr))
        startime_input_sec = timeformat_date_to_sec(startime_date)

        print '请输入结束时间，按照后面的格式: 2015-08-23 17:11:57 '
        tempStr = '结束时间应该早于： %s\r\n'%timeformat_sec_to_date(lasttime)
        endtime_date = str(raw_input(tempStr))
        endtime_input_sec = timeformat_date_to_sec(endtime_date)

        #时间有效性校验
        if (endtime_input_sec >  startime_input_sec) and (startime_input_sec > firsttime) and (endtime_input_sec < lasttime) :
            break
        else :
            print '输入时间错误，请重新输入\r\n'
    #SQL语句
    cmsStr = "select * from %s where timestamp > %d and timestamp < %d"%(dbTableName,startime_input_sec,endtime_input_sec)
    return cmsStr


def GetPcapFileName():
    flag = True
    #while flag:
    #    print '请输入需要读取的pcap文件'
    #    filename = str(raw_input())
    #    if False == os.path.exists(filename):
    #        print '文件不存在，请重新输入'
    #    else :
    #        break
    pcapfilename = "http-pcap2.pcap"
    length = pcapfilename.find('.')
    dbTableName = pcapfilename[0:length]
    #此处filename作为表名，需要细化处理，暂时简单处理
    dbTableName = dbTableName.replace('-','_')
    return pcapfilename,dbTableName
        



if __name__ == '__main__':
    #可以做成让用户输入文件名，此处简单处理
    filename = GetPcapFileName()

    #如果报文已经读取，直接读数据库，没有则解析pcap报文
    
    dbTableName = filename[1]
    httpdb.creatdata(dbTableName)
    
    num = httpdb.IsTableExist(dbTableName)
  
    #if True == os.path.exists(filename):
    if num != 0:
       print 'here'
       firsttime =  httpdb.GetMin_timestamp(dbTableName)
       lasttime = httpdb.GetMax_timestamp(dbTableName)
       #print 'this pcap file have been saved in DB'
       print 'pcap文件已经记录在数据库中，直接读取数据库数据'
       #print 'this pcap file pcap packet from %s to %s'%(timeformat_sec_to_date(firsttime),timeformat_sec_to_date(lasttime))
    else : 
       print '读取pcap文件到数据库中，请稍等'
       
       packet_import_to_db(filename[0],filename[1])


    flag = True
    while flag:
        print "数据准备完成"
        print '请选择你需要的功能点，输入数字进行选择'
        print '1、输出一段时间内url的访问记录'
        print '2、在报文中查找关键字'
        print '3、退出'
        choice = str(raw_input())
        if choice == '1':
            cmdStr = url_make_cmdStr(dbTableName)
            statistics.url_Statistics(dbTableName,cmdStr)
        elif choice == '2':
            keyword = str(raw_input('请输入关键字 : '))
            n = str(raw_input('请输入需要打印的记录的条数 :'))
            #这里需要对参数n的有效性做校验
            statistics.keyword_statistcis(dbTableName,keyword,string.atoi(n))
        else :
            break
            

    
        
    
