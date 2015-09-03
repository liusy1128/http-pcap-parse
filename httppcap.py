#encoding=utf-8
# -*- coding:gb2312 -*-
import dpkt
import socket
import time
import httpdb
import statistics
import os.path
import string
import thread
import httpparse

import httpmutithread
import commonlib


# 秒转化为日期


def packet_import_to_db(filename,dbTableName):
   
    
    f = open(filename,'rb')
    
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        f.close()
        return

    i = 1#报文编号，记录wireshark中的序号，便于调试

    if commonlib.IsSupportMutiThread() != 0:
        thread.start_new_thread(httpmutithread.httpThreadDataProcess,(dbTableName,1) )
        
    for ts,buf in pcap:
        if commonlib.IsSupportMutiThread() != 0:
            while True:
                if httpmutithread.GetThreadNum() < 16:
                    thread.start_new_thread(httpmutithread.httpThreadProcess, (buf,dbTableName,ts))
                    break
                else:
                    time.sleep(0.01)
        else:
            httpparse.httpPacketParse(buf,dbTableName,ts)
        i = i+1
        #多线程时，有后台任务写，执行到这里，数据还没有准备好，这里打印不准确
        if commonlib.IsSupportMutiThread() == 0:
            if i%3000 == 0:
                print '正在读取pcap文件到数据库中，请稍等'
    f.close()
    return 
    

def url_make_cmdStr(dbTableName):
    
    firsttime =  httpdb.GetMin_timestamp(dbTableName)
    lasttime = httpdb.GetMax_timestamp(dbTableName)
    print 'pcap文件中http报文的时间段是从 %s 到 %s'%(commonlib.timeformat_sec_to_date(firsttime),commonlib.timeformat_sec_to_date(lasttime))
    whileflag = True

    while flag :
        print '请输入开始时间，按照后面的格式: 2015-08-23 17:11:57'
        tempStr = '开始时间应该晚于 %s\r\n'%commonlib.timeformat_sec_to_date(firsttime)
        startime_date = str(raw_input(tempStr))
        startime_input_sec = commonlib.timeformat_date_to_sec(startime_date)

        print '请输入结束时间，按照后面的格式: 2015-08-23 17:11:57 '
        tempStr = '结束时间应该早于： %s\r\n'%commonlib.timeformat_sec_to_date(lasttime)
        endtime_date = str(raw_input(tempStr))
        endtime_input_sec = commonlib.timeformat_date_to_sec(endtime_date)

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
    while flag:
        print '请输入需要读取的pcap文件'
        pcapfilename = str(raw_input())
        if False == os.path.exists(pcapfilename):
            print '文件不存在，请重新输入'
        else :
            break
    #pcapfilename = "http-pcap2.pcap"
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
    commonlib.SupportMutiThreadSet(0)
    #if True == os.path.exists(filename):
    if num != 0:
       firsttime =  httpdb.GetMin_timestamp(dbTableName)
       lasttime = httpdb.GetMax_timestamp(dbTableName)
       #print 'this pcap file have been saved in DB'
       print 'pcap文件已经记录在数据库中，直接读取数据库数据'
       #print 'this pcap file pcap packet from %s to %s'%(timeformat_sec_to_date(firsttime),timeformat_sec_to_date(lasttime))
    else : 
       print '读取pcap文件到数据库中，请稍等'
       
       packet_import_to_db(filename[0],filename[1])

    #支持多进程，此处等待数据库写入完成  
    if commonlib.IsSupportMutiThread() != 0:
        httpmutithread.httpThreadReadEndSet(1)
        httpmutithread.threadwait()
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
            

    
        
    
