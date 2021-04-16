import csv
import py2neo
from py2neo import Graph,Node,Relationship,NodeMatcher,NodeMatcher
import pandas as pd
import numpy as np

import 知识图谱构建
from 知识图谱构建 import *

import 攻击检测
from 攻击检测 import *




# 连接知识图谱
NEO_URL = input("请输入Neo4j数据库URL地址：")
NEO_USER = input("请输入Neo4j数据库账号：")
NEO_PASS = input("请输入Neo4j数据库密码：")


# 知识图谱构建

# SOURCE_DIR = input("请输入定义起点实体的csv文件所在路径：")
# 生产环境中可以用具有动态绑定的企业级管理型交换机进行该实体及其属性的提取，但实验环境中仅从攻击数据中提取IP作为实体
DATA_DIR = input("请输入数据集路径：")
# DESTINATION_DIR = input("请输入定义终点实体的csv文件所在路径：")
    ## 数据填充，将ARP广播的目的地址全部填充为数据链路层广播地址
df = pd.read_csv(DATA_DIR)
df.fillna({"Destination":"FF:FF:FF:FF:FF:FF"},inplace=True)

# 调用创建知识图谱的模块，利用函数进行节点以及关系的创建
qu = input("是否要进行知识图谱的构建[yes/no]：")
if "yes" in qu:
    neo_1 = Create_Neo(NEO_URL,NEO_USER,NEO_PASS,DATA_DIR)
    neo_1.create_nodes()
    neo_1.create_relationships()
else:
    pass

# ICMP泛洪检测
# 基于对Server以及Controller的发包情况进行检测

SERVER_IP = input("请输入服务器的IP：")
# 10.0.0.1
CONTROLLER_IP = input("请输入控制器IP：")
# 10.0.0.88
dec_all = Detection_ALL(SERVER_IP,CONTROLLER_IP,DATA_DIR,NEO_URL,NEO_USER,NEO_PASS)
dec_all.detection_icmp()

# SYN泛洪检测
dec_all.detection_syn()
# UPD泛洪检测
dec_all.detection_udp()
