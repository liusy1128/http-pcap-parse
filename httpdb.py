#-*-encoding:utf-8-*-
import sqlite3


                
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

                
def insert(tablename,tabel_line,conn):
        #tabel_line = {'time':1.32,'sip':1,'dip':3,'sport':3,'dport':1,'method':'get','url':'www.baidu.com','tcp_packet':'http packet'}
        #tabel_line2 = {'time':1.22,'sip':1,'dip':3,'sport':3,'dport':1,'method':'get','url':'www.sina.com','tcp_packet':'http packetsdjidjsijdisjdisjdijisjdijsidj'}
        
        
        #hel = opendata()

        cmdStr = "insert into %s(timestamp, sip,dip,sport,dport,method,url,get,accept_language,accept_encoding,\
                connection,accept,host,referer,origin,Cache_Control,Cookie,tcp_packet) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"%tablename
        conn.execute(cmdStr,(tabel_line['timestamp'], tabel_line['sip'],tabel_line['dip'],
                                         tabel_line['sport'],tabel_line['dport'],tabel_line['method'],tabel_line['url'],
                                tabel_line['get'],tabel_line['accept-language'],tabel_line['accept-encoding'],tabel_line['connection'],
                             tabel_line['accept'],tabel_line['host'],tabel_line['referer'],tabel_line['origin'],
                              tabel_line['Cache-Control'],tabel_line['Cookie'],
                             tabel_line['tcp_packet']))
        conn.commit()

        #hel[1].execute("insert into http_packet(time, sip,dip,sport,dport,method,url,tcp_packet) values (?,?,?,?,?,?,?,?)",
        #                                (tabel_line2['time'], tabel_line2['sip'],tabel_line2['dip'],
        #                                 tabel_line2['sport'],tabel_line2['dport'],tabel_line2['method'],tabel_line2['url'],tabel_line2['tcp_packet']))
        #hel[1].commit()
        
      
        #showalldata()
        #hel[1].close()        

 
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

#IsTableExist("http-pcap-data3.db")



