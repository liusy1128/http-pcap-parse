#encoding=utf-8
# -*- coding:gb2312 -*-
import time
import httpdb
import httppcap
import string
import commonlib

dicturl = {}
def url_Count(url):
    val = dicturl.has_key(url)
    if val == True:
        dicturl[url] = dicturl[url]+1
    elif val == False:
        dicturl[url] = 1
    else:
        print 'error'
        



#url统计函数，操作字符串
#"select * from http_packet"
#"select * from http_packet where timestamp > timevalue1 and timestamp < timevalue2"
def url_Statistics(tablename,cmdStr):
    dicturl.clear()
    #open data
    hel = httpdb.opendata(tablename)
    cur = hel[1].cursor()
    #数据库检索
    cur.execute(cmdStr)
    res = cur.fetchall()
    
    for line in res:
        url_Count(line[6])
    #排序
    l = sorted(dicturl.iteritems(), key=lambda d:d[1], reverse = True )
    #print结果
    for item in l:
        print '%s : %s'%(item[0],item[1])
        
    print '\r\n'
    cur.close()


#b = "select count(*) from http_packet where tcp_packet like '%sina%'"
#c = "select * from http_packet where tcp_packet like '%sina%'"
#关键字统计
tabelStr=['timestamp        :  ',
          'sip              :  ',
          'dip              :  ',
          'sport            :  ',
          'dport            :  ',
          'method           :  ',
          'url              :  ',
          'get              :  ',
          'accept-language  :  ',
          'accept-encoding  :  ',
          'connection       :  ',
          'accept           :  ',
          'host             :  ',
          'referer          :  ',
          'origin           :  ',
          'Cache-Control    :  ',
          'Cookie           :  ',
          'tcp_packet       :  ']

def keyword_statistcis(tablename,keyword,n):
    hel = httpdb.opendata(tablename)
    cur = hel[1].cursor()
    #统计计数
    print '*******查找关键字:  %s ********'%keyword
    #SQL语句，统计总数
    countstr = "select count(*) from %s where url like '%%%s%%' or \
                            get like '%%%s%%' or referer like '%%%s%%'or origin like '%%%s%%' or\
                            host like '%%%s%%'"%(tablename,keyword,keyword,keyword,keyword,keyword)
    cur.execute(countstr)
    res = cur.fetchall()
    for line in res:
        print '关键字总数为 : %s'%line
    print 
    #SQL语句，查找符合条件的记录
    countstr = "select * from %s where url like '%%%s%%' or \
                            get like '%%%s%%' or referer like '%%%s%%'or origin like '%%%s%%' or\
                            host like '%%%s%%'"%(tablename,keyword,keyword,keyword,keyword,keyword)
    cur.execute(countstr)
    res = cur.fetchall()
    i = 0;
    #打印记录
    for line in res:
        i = i+1
        print  commonlib.timeformat_sec_to_date(line[0])
        j = 0
        for h in line:
            print tabelStr[j],h
            j = j+1
        print '\r\n'
        if i == n:
            break

    print '\r\n'





