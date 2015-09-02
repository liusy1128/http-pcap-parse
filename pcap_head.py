import struct
fpcap = open('F:/python/2.pcap','rb')
#ftxt = open('result.txt','w')
string_data = fpcap.read()
#pcap�ļ���ͷ����
pcap_header = {}
pcap_header['magic_number'] = string_data[0:4]
pcap_header['version_major'] = string_data[4:6]
pcap_header['version_minor'] = string_data[6:8]
pcap_header['thiszone'] = string_data[8:12]
pcap_header['sigfigs'] = string_data[12:16]
pcap_header['snaplen'] = string_data[16:20]
pcap_header['linktype'] = string_data[20:24]
#��pacp�ļ�ͷ��Ϣд��result.txt
#ftxt.write("Pcap�ļ��İ�ͷ�������£� \n")
#for key in ['magic_number','version_major','version_minor','thiszone',
#            'sigfigs','snaplen','linktype']:
#    ftxt.write(key+ " : " + repr(pcap_header[key])+'\n')
          
#pcap�ļ������ݰ�����
step = 0
packet_num = 0
packet_data = []
pcap_packet_header = {}
i =24
while(i<len(string_data)):
      if i==6:
         break
      #���ݰ�ͷ�����ֶ�
      pcap_packet_header['GMTtime'] = string_data[i:i+4]
      pcap_packet_header['MicroTime'] = string_data[i+4:i+8]
      pcap_packet_header['caplen'] = string_data[i+8:i+12]
      pcap_packet_header['len'] = string_data[i+12:i+16]
      print pcap_packet_header['len']
      #����˰��İ���len
      packet_len = struct.unpack('I',pcap_packet_header['len'])[0]
      print packet_len
      #д��˰�����
      packet_data.append(string_data[i+16:i+16+packet_len])
      i = i+ packet_len+16
      packet_num+=1
   
   
   
   
#��pacp�ļ�������ݰ���Ϣд��result.txt
#for i in range(packet_num):
#    #��дÿһ���İ�ͷ
#    ftxt.write("���ǵ�"+str(i)+"�����ݵİ�ͷ�����ݣ�"+'\n')
#    for key in ['GMTtime','MicroTime','caplen','len']:
#        ftxt.write(key+' : '+repr(pcap_packet_header[key])+'\n')
#    #��д���ݲ���
#    ftxt.write('�˰�����������'+repr(packet_data[i])+'\n')
#ftxt.write('һ����'+str(packet_num)+"������"+'\n')
      
#ftxt.close()
fpcap.close()
