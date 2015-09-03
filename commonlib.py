#encoding=utf-8
# -*- coding:gb2312 -*-
import time

mutiThreadFlag = 0

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

def IsSupportMutiThread():
    global mutiThreadFlag
    return mutiThreadFlag

def SupportMutiThreadSet(flag):
    global mutiThreadFlag
    mutiThreadFlag = flag
    return 
