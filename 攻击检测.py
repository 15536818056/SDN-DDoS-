import csv
import py2neo
import pandas as pd
import numpy as np
from py2neo import Graph,Node,Relationship,NodeMatcher




# ICMP

class Detection_ALL(object):
    def __init__(self,SERVER_IP,CONTROLLER_IP,DATA_DIR,NEO_URL,NEO_USER,NEO_PASS):
        self.server_ip = SERVER_IP
        self.controller_ip = CONTROLLER_IP
        self.data_dir = DATA_DIR
        self.neo_url = NEO_URL
        self.neo_u = NEO_USER
        self.neo_p = NEO_PASS

    def detection_icmp(self):
        # 连接数据库
        graph = Graph(self.neo_url, username=self.neo_u, password=self.neo_p)
        # 获取所有向服务器发出ICMP包的节点情况
        CY1 =  "MATCH p=(s:Source)-[r1:`发出`]->(x:Protocol{name:'ICMP'})-[r:`发向`]->(d:Destination{ip:\'"+self.server_ip+"\'}) RETURN s.ip"
        tmp_df_icmp = graph.run(CY1).to_data_frame()
        if len(tmp_df_icmp) == 0:
            print("该时间段内无ICMP数据包")
        else:

            # 获取向服务器发送ICMP包的IP地址
            list_icmp = tmp_df_icmp['s.ip']
            list_icmp.value_counts().index


            # 读取原始数据集
            fpath = self.data_dir
            df = pd.read_csv(fpath)
            df.head()


            # 这里要根据源ip获得原始数据中的所有行,即这些向服务器发送过ICMP包的IP所发送的所有包
            df_2 = df.loc[df['Source'].isin(list_icmp.value_counts().index)]


            # 计算每一个可疑IP向服务器发出的总的包
            df_2["Source"].value_counts()
            list_tongyiip2 = df_2["Source"].value_counts()

            # 计算每一个可疑IP向服务器发出的ICMP包
            result5 = df_2["Protocol"].str.contains("ICMP",regex = False)
            list_5 = df_2[result5].value_counts("Source")
            list_5



            # 计算每一个交换机向控制器发出的OFPT_PACKET_IN消息在其发出的总的OF消息消息中所占比例
            CY2 = "MATCH p=(s:Source)-[r1:`发出`]->()-[r:`发向`]->(d:Destination{ip:\'"+self.server_ip+"\'}) RETURN s.ip"
            tmp_df_packet_in = graph.run(CY2).to_data_frame()

            list_packet_in = tmp_df_packet_in['s.ip']
            list_packet_in.value_counts().index
            fpath =self.data_dir
            df = pd.read_csv(fpath)
            df_3 = df.loc[df['Source'].isin(list_packet_in.value_counts().index)]
            # 获取交换机发向控制器的OFPT包的数量
            result6 = df_3["Protocol"].str.contains("OpenFlow",regex = False)
            list_6 = df_3[result6].value_counts("Source")
            list_6
            # 获取交换机发向控制器的PACKRT_IN包数量
            result7 = df_3["Info"].str.contains("OFPT_PACKET_IN",regex = False)
            list_7 = df_3[result7].value_counts("Source")
            list_7


            # 泛洪检测
            CY3 = "MATCH p=(s:Source)-[r1:`发出`]->()-[r:`发向`]->(d:Destination{ip:\'"+self.controller_ip+"\'}) RETURN s.ip"
            tmp_df_packet_in = graph.run(CY3).to_data_frame()
            if len(tmp_df_packet_in) == 0:
            # 这里指不存在OF消息，更不可能存在PACKET_IN类型的消息，从而不存在伪造IP或分布式的DDoS攻击
                nu = 0
                bili2 = ['']
                for item in list_icmp.value_counts().index:
                    bili2 = list_5[nu]/list_tongyiip2[nu]
                    if bili2 >= 0.5:
                        print(item+":ICMP泛洪,且不是分布式或伪造大量IP地址的攻击")
                    else:
                        print(item+":正常流量")        
                    nu += 1

            else:
            # 存在OF消息
                list_packet_in = tmp_df_packet_in['s.ip']
                list_packet_in.value_counts().index
                fpath = self.data_dir
                df = pd.read_csv(fpath)
                df_3 = df.loc[df['Source'].isin(list_packet_in.value_counts().index)]
                # 获取交换机发向控制器的OFPT包的数量
                result6 = df_3["Protocol"].str.contains("OpenFlow",regex = False)
                list_6 = df_3[result6].value_counts("Source")
                # 获取交换机发向控制器的PACKRT_IN包数量
                result7 = df_3["Info"].str.contains("OFPT_PACKET_IN",regex = False)
                list_7 = df_3[result7].value_counts("Source")

           
                if len(list_7) == 0:
                # 不存在PACKET_IN消息
                    n = 0
                    bili2 = ['']
                    hangshu = 0
                    for item in list_icmp.value_counts().index:
                        bili2 = list_5[n]/list_tongyiip2[n]
                        # 这里计算的是ICMP包在该IP发过的总的包中所占的比例
                        if bili2 > 0.5:
                            print(item+":ICMP泛洪，且不是分布式或伪造大量IP地址的攻击")
                        else:
                            print(item+":正常流量")
                        n += 1
                else:
                # 存在PACKET_IN消息
                    n = 0
                    bili2 = ['']
                    for item in list_icmp.value_counts().index:
                        bili2 = list_5[n]/list_tongyiip2[n]
                        if bili2 >= 0.5:
                            bili3 = ['']
                            num = 0
                            for item in list_packet_in.value_counts().index:
                                bili3 = list_7[num]/list_6[num]
                                if bili3 > 0.1:
                                    print(list_icmp.value_counts().index[n]+":有可能是分布式或伪造大量IP地址的ICMP泛洪攻击")
                                else:
                                    print(list_icmp.value_counts().index[n]+":一般不是分布式或伪造大量IP地址的ICMP泛洪攻击")       
                                num += 1
                        else:
                            print(item+":正常流量")       
                        n += 1



# SYN半连接
    def detection_syn(self):
        # 连接数据库
        graph = Graph(self.neo_url, username=self.neo_u, password=self.neo_p)
        CY1 = "MATCH p=(s:Source)-[r1:`发出`]->(x:Protocol{name:'TCP'})-[r:`发向`]->(d:Destination{ip:\'"+self.server_ip+"\'}) RETURN s.ip"
        # 获取所有向服务器发出TCP包的主体
        tmp_df_tcp_syn = graph.run(CY1).to_data_frame()
        # 获取向服务器发送TCP包的IP地址列表
        if len(tmp_df_tcp_syn) == 0:
            print("该时间段内无TCP包")
        else:
            list_tcp_syn = tmp_df_tcp_syn ['s.ip']
            list_tcp_syn.value_counts().index


            # 读取原始数据集
            fpath = self.data_dir
            df = pd.read_csv(fpath)


            # 这里要根据源ip获得攻击数据集中的所有记录
            df_1 = df.loc[df['Source'].isin(list_tcp_syn.value_counts().index)]
            # 同一IP发出的所有包的数量
            df_1["Source"].value_counts()
            list_tongyiip = df_1["Source"].value_counts()

            # 同一IP发出的所有TCP包的数量
            result4 = df_1["Protocol"].str.contains("TCP",regex = False)
            list_4 = df_1[result4].value_counts("Source")
            list_4

            # 统计发向服务器的RST、SYN、ACK、[ACK,SYN]数据包的数量
            result1 = df_1["Info"].str.contains("[RST]",regex = False)
            list_1 = df_1[result1].value_counts("Source")
            list_1

            result2 = df_1["Info"].str.contains("[SYN]",regex = False)
            list_2 = df_1[result2].value_counts("Source")
            list_2

            result3 = df_1["Info"].str.contains("[ACK]",regex = False)
            list_3 = df_1[result3].value_counts("Source")

            result3 = df_1["Info"].str.contains("[ACK,SYN]",regex = False)
            list_3 = df_1[result3].value_counts("Source")


            # PACKET_IN
            CY2 = "MATCH p=(s:Source)-[r1:`发出`]->()-[r:`发向`]->(d:Destination{ip:\'"+self.controller_ip+"\'}) RETURN s.ip"
            tmp_df_packet_in = graph.run(CY2).to_data_frame()
            if len(tmp_df_packet_in) == 0:
            # 交换机与控制器之间不存在OpenFlow类型消息的交互
                n = 0
                bili = ['']
                for item in list_tcp_syn.value_counts().index:
                    bili = list_2[n]/list_tongyiip[n]
                    # 计算每个IP发出的SYN包在其发出的总的TCP包中所占比例
                    if bili > 0.6:
                        print(item+":SYN泛洪，且不是分布式或伪造大量IP地址的攻击")
                    else:
                        print(item+":正常流量")
                    n += 1
            else:
            # 交换机与控制器之间存在OpenFlow类型消息的交互
                list_packet_in = tmp_df_packet_in['s.ip']
                list_packet_in.value_counts().index
                fpath = self.data_dir
                df = pd.read_csv(fpath)
                df_3 = df.loc[df['Source'].isin(list_packet_in.value_counts().index)]
                # 获取交换机发向控制器的OFPT包的数量
                result6 = df_3["Protocol"].str.contains("OpenFlow",regex = False)
                list_6 = df_3[result6].value_counts("Source")
                list_6
                # 获取交换机发向控制器的PACKRT_IN包数量
                result7 = df_3["Info"].str.contains("OFPT_PACKET_IN",regex = False)
                list_7 = df_3[result7].value_counts("Source")
                list_7

                if len(list_7) == 0:
                # 不存在OFPT_PACKET_IN消息
                    n = 0
                    bili = ['']
                    
                    for item in list_tcp_syn.value_counts().index:
                        bili = list_2[n]/list_tongyiip[n]
                        if bili > 0.6:
                            print(item+":SYN泛洪，且不是分布式或伪造大量IP地址的攻击")
                        else:
                            print(item+":正常流量")
                                
                        n += 1
                
                else:
                # 存在PACKET_IN消息
                    n = 0
                    bili = ['']
                    for item in list_tcp_syn.value_counts().index:
                        bili = list_2[n]/list_tongyiip[n]
                        if bili > 0.6:
                            bili3 = ['']
                            num = 0
                            for item in list_packet_in.value_counts().index:
                                bili3 = list_7[num]/list_6[num]
                                if bili3 > 0.1:
                                    print(list_tcp_syn.value_counts().index[n]+":有可能是分布式或伪造大量IP地址的SYN泛洪攻击")
                                else:
                                    print(list_tcp_syn.value_counts().index[n]+":一般不是分布式或伪造大量IP地址的SYN泛洪攻击")       
                                num += 1
                        else:
                            print(item+":正常流量")
                        n += 1







# UDP泛洪


    def detection_udp(self):
        # 连接数据库
        graph = Graph(self.neo_url, username=self.neo_u, password=self.neo_p)
        # 获取所有向服务器发出ICMP包的节点情况
        CY1 =  "MATCH p=(s:Source)-[r1:`发出`]->(x:Protocol{name:'UDP'})-[r:`发向`]->(d:Destination{ip:\'"+self.server_ip+"\'}) RETURN s.ip"
        tmp_df_udp = graph.run(CY1).to_data_frame()
        if len(tmp_df_udp) == 0:
            print("该时间段内无UDP数据包")
        else:

            # 获取向服务器发送ICMP包的IP地址
            list_udp = tmp_df_udp['s.ip']
            list_udp.value_counts().index


            # 读取原始数据集
            fpath = self.data_dir
            df = pd.read_csv(fpath)

            df.head()


            # 这里要根据源ip获得所有行,即这些向服务器发送过ICMP包的IP所发送的所有包
            df_2 = df.loc[df['Source'].isin(list_udp.value_counts().index)]


            # 计算每一个可疑IP向服务器发出的总的包
            df_2["Source"].value_counts()
            list_tongyiip2 = df_2["Source"].value_counts()

            # 计算每一个可疑IP向服务器发出的UDP包
            result5 = df_2["Protocol"].str.contains("UDP",regex = False)
            list_5 = df_2[result5].value_counts("Source")
            list_5

           
            CY2 = "MATCH p=(s:Source)-[r1:`发出`]->()-[r:`发向`]->(d:Destination{ip:\'"+self.server_ip+"\'}) RETURN s.ip"
            tmp_df_packet_in = graph.run(CY2).to_data_frame()

            list_packet_in = tmp_df_packet_in['s.ip']
            list_packet_in.value_counts().index
            fpath =self.data_dir
            df = pd.read_csv(fpath)
            df_3 = df.loc[df['Source'].isin(list_packet_in.value_counts().index)]
            # 获取交换机发向控制器的OFPT包的数量
            result6 = df_3["Protocol"].str.contains("OpenFlow",regex = False)
            list_6 = df_3[result6].value_counts("Source")
            list_6
            # 获取交换机发向控制器的PACKRT_IN包数量
            result7 = df_3["Info"].str.contains("OFPT_PACKET_IN",regex = False)
            list_7 = df_3[result7].value_counts("Source")
            list_7



            # PACKET_IN
            CY3 = "MATCH p=(s:Source)-[r1:`发出`]->()-[r:`发向`]->(d:Destination{ip:\'"+self.controller_ip+"\'}) RETURN s.ip"
            tmp_df_packet_in = graph.run(CY3).to_data_frame()
            if len(tmp_df_packet_in) == 0:
                nu = 0
                bili2 = ['']
                for item in list_udp.value_counts().index:
                    bili2 = list_5[nu]/list_tongyiip2[nu]
                    if bili2 >= 0.5:
                        print(item+":UDP泛洪,且不是分布式或伪造大量IP地址的攻击")
                    else:
                        print(item+":正常流量")        
                    nu += 1

            else:
                list_packet_in = tmp_df_packet_in['s.ip']
                list_packet_in.value_counts().index
                fpath = self.data_dir
                df = pd.read_csv(fpath)
                df_3 = df.loc[df['Source'].isin(list_packet_in.value_counts().index)]
                # 获取交换机发向控制器的OFPT包的数量
                result6 = df_3["Protocol"].str.contains("OpenFlow",regex = False)
                list_6 = df_3[result6].value_counts("Source")
                # 获取交换机发向控制器的PACKRT_IN包数量
                result7 = df_3["Info"].str.contains("OFPT_PACKET_IN",regex = False)
                list_7 = df_3[result7].value_counts("Source")
            # 存在PACKET_IN消息
                if len(list_7) == 0:
                    n = 0
                    bili2 = ['']
                    hangshu = 0
                    for item in list_udp.value_counts().index:
                        bili2 = list_5[n]/list_tongyiip2[n]
                        if bili2 > 0.5:
                            print(item+":UDP泛洪，且不是分布式或伪造大量IP地址的攻击")
                        else:
                            print(item+":正常流量")
                        n += 1
                else:
                    n = 0
                    bili2 = ['']
                    for item in list_udp.value_counts().index:
                        bili2 = list_5[n]/list_tongyiip2[n]
                        if bili2 >= 0.5:
                            bili3 = ['']
                            num = 0
                            for item in list_packet_in.value_counts().index:
                                bili3 = list_7[num]/list_6[num]
                                if bili3 > 0.1:
                                    print(list_udp.value_counts().index[n]+":有可能是分布式或伪造大量IP地址的UDP泛洪攻击")
                                else:
                                    print(list_udp.value_counts().index[n]+":一般不是分布式或伪造大量IP地址的UDP泛洪攻击")       
                                num += 1
                        else:
                            print(item+":正常流量")       
                        n += 1

