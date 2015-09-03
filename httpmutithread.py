
#encoding=utf-8
# -*- coding:gb2312 -*-
import thread
import Queue
import httpparse
import httpdb
import time
lock = thread.allocate_lock()


threadNum = 0
def addThreadNum():
    global threadNum
    lock.acquire()
    threadNum = threadNum +1
    lock.release()
    
    
def delThreadNum():
    global threadNum
    lock.acquire()
    threadNum = threadNum -1
    lock.release()
    

def GetThreadNum():
    global threadNum
    lock.acquire()
    num = threadNum 
    lock.release()
    return num


dataQueue = Queue.Queue(0)
def PutDatatoQueue(tableline):
    global dataQueue
    #队列中不能传入字典类型，转为字符串
    strcmd = str(tableline)
    dataQueue.put(strcmd,0)
   

def GetDatatoQueue():
    tabel = ''
    tabel = dataQueue.get(0)
    return eval(tabel)
     
def httpThreadProcess(buf,dbTableName,ts):
    addThreadNum()
    httpparse.httpPacketParse(buf,dbTableName,ts)
    delThreadNum()
    thread.exit_thread()
finishflag = 0
def httpThreadReadEndSet(value):
    global finishflag
    finishflag = value

def httpThreadReadEndFlag():
    global finishflag
    return finishflag     
    

def httpThreadDataProcess(dbTableName,ts):
    global dataQueue
    i = 0
    while True:
        if False == dataQueue.empty():
            i = i+1
            tabelDB = GetDatatoQueue()
            httpdb.insert(dbTableName,tabelDB)
            
            if i%200 == 0:
                print '正在读取pcap文件到数据库中，请稍等'
        else :
            if httpThreadReadEndFlag() == 1:
                threadnotify()
                thread.exit_thread()
                
            time.sleep(0.1)

import threading
con = threading.Condition()

def threadwait():
    con.acquire()
    con.wait()
    con.release()

def threadnotify():
    con.acquire()
    con.notify()
    con.release()
