
#encoding=utf-8
# -*- coding:gb2312 -*-
import thread
import Queue
import httpparse
import httpdb
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
    
def httpThreadDataProcess(dbTableName,ts):
    global dataQueue
    
    while True:
        if False == dataQueue.empty():
            tabelDB = GetDatatoQueue()
            httpdb.insert(dbTableName,tabelDB)

import threading
con = threading.Condition()

def threadcon():
    con.acquire()
    con.wait()
    con.release()
