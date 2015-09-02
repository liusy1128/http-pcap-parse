#-*-encoding:utf-8-*-
import sqlite3
import thread

lock = thread.allocate_lock()           
dataName = "pcapHttpDB.db"
def opendata(tablename):
        conn = sqlite3.connect(dataName)
        cmdStr = """create table if not exists %s(timestamp float primary key , sip integer, dip integer ,
                                        sport integer,dport integer,method varchar(16),url varchar(256),
                                        get varchar(256),accept_language varchar(16) ,accept_encoding varchar(16),connection varchar(16),
                                        accept varchar(16),host varchar(64),referer varchar(64),
                                        origin varchar(64),Cache_Control varchar(16),Cookie varchar(256),
                                        tcp_packet varchar(1500))"""%tablename
        cur = conn.execute(cmdStr)
        return cur, conn

def creatdata(tablename):
        print 'creat data %s'%tablename
        conn = sqlite3.connect(dataName)
        cmdStr = """create table if not exists %s(timestamp float primary key , sip integer, dip integer ,
                                        sport integer,dport integer,method varchar(16),url varchar(256),
                                        get varchar(256),accept_language varchar(16) ,accept_encoding varchar(16),connection varchar(16),
                                        accept varchar(16),host varchar(64),referer varchar(64),
                                        origin varchar(64),Cache_Control varchar(16),Cookie varchar(256),
                                        tcp_packet varchar(1500))"""%tablename
        cur = conn.execute(cmdStr)
        cur.close()
        return 

def closedata(conn):
        conn.close()

                
def insert(tablename,tabel_line):
        #lock.acquire()
        conn = sqlite3.connect(dataName)
        cmdStr = "insert into %s(timestamp, sip,dip,sport,dport,method,url,get,accept_language,accept_encoding,\
                connection,accept,host,referer,origin,Cache_Control,Cookie,tcp_packet) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"%tablename
        conn.execute(cmdStr,(tabel_line['timestamp'], tabel_line['sip'],tabel_line['dip'],
                                         tabel_line['sport'],tabel_line['dport'],tabel_line['method'],tabel_line['url'],
                                tabel_line['get'],tabel_line['accept-language'],tabel_line['accept-encoding'],tabel_line['connection'],
                             tabel_line['accept'],tabel_line['host'],tabel_line['referer'],tabel_line['origin'],
                              tabel_line['Cache-Control'],tabel_line['Cookie'],
                             tabel_line['tcp_packet']))
        conn.commit()

        conn.close()
        #lock.release()

 
def showalldata(dataName):
        
        hel = opendata(dataName)
        cur = hel[1].cursor()
        cur.execute("select * from http_packet")
        res = cur.fetchall()
        for line in res:
                for h in line:
                        print h,
                print
        cur.close()
#select id,riqi,min(shijian) as shijian from kq group by id, riqi
def GetMin_timestamp(dataName):
        hel = opendata(dataName)
        cur = hel[1].cursor()
        cmdStr = "select min(timestamp) from %s"%dataName
        cur.execute(cmdStr) 
        res = cur.fetchone()
        return res[0]

def GetMax_timestamp(dataName):
        hel = opendata(dataName)
        cur = hel[1].cursor()
        cmdStr = "select max(timestamp) from %s"%dataName
        cur.execute(cmdStr) 
        res = cur.fetchone()
        return res[0]

def IsTableExist(tableName):
        conn = sqlite3.connect(dataName)
        print dataName
        cmd = "select count(*) from %s"%tableName
        cur = conn.execute(cmd)
        res = cur.fetchone()
        return res[0]




