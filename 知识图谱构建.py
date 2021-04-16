import csv
from py2neo import Graph,Node,Relationship,NodeMatcher,NodeMatcher
import py2neo

class Create_Neo(object):
    def __init__(self,NEO_URL,NEO_USER,NEO_PASS,DATA_DIR):
        # self.source_dir = SOURCE_DIR
        # self.destination_dir = DESTINATION_DIR
        self.data_dir = DATA_DIR
        self.neo_url = NEO_URL
        self.neo_user = NEO_USER
        self.neo_pass = NEO_PASS
        
    def create_nodes(self):
    # 创建节点
        g = Graph(self.neo_url, username=self.neo_user, password=self.neo_pass)
        with open(self.data_dir,'r',encoding='utf-8') as f:
            reader=csv.reader(f)
            for item in reader:
                #第一行的标签不是咱们需要的内容，line_num表示文件的第几行
                if reader.line_num==1:
                    continue
                print("当前行数：",reader.line_num,"当前内容",item)
                test_node_1=Node("Source",ip=item[2])
                g.merge(test_node_1, "Source", "ip")
                # 这里最好用MAC地址区分不同源，交互机有自己的DDID
                # MAC要是不好表示，我们就直接用data里面的IP来表示
        with open(self.data_dir,'r',encoding='utf-8') as f:
            reader=csv.reader(f)
            for item in reader:
                #第一行的标签不是咱们需要的内容，line_num表示文件的第几行
                if reader.line_num==1:
                    continue
                print("当前行数：",reader.line_num,"当前内容",item)
                test_node_1=Node("Protocol",name=item[4],Info=item[6],length=item[5],time=item[1])
                # Source 和 Destination最好不要加到属性中，因为有的包没有ip（ARP）,如果用MAC代替的话，并且对ARP包进行填充，也是可以的,填充为二层广播地址
                g.merge(test_node_1, "Protocol", "time")
        with open(self.data_dir,'r',encoding='utf-8') as f:
            #数据集除了第一行代表属性外，第一列为实体1，第二列为实体2，第三列是两者英文关系，第四列为两者中文关系
            reader=csv.reader(f)
            for item in reader:
                #第一行的标签不是咱们需要的内容，line_num表示文件的第几行
                if reader.line_num==1:
                    continue
                print("当前行数：",reader.line_num,"当前内容",item)
                test_node_1=Node("Destination",ip=item[3])
                g.merge(test_node_1, "Destination", "ip")
                
            
    def create_relationships(self):
        g = Graph(self.neo_url, username=self.neo_user, password=self.neo_pass)
        with open(self.data_dir,'r',encoding='utf-8') as f:
        #数据集除了第一行代表属性外，第一列为实体1，第二列为实体2，第三列是两者英文关系，第四列为两者中文关系
            reader=csv.reader(f)
            matcher = NodeMatcher(g)
            for item in reader:
                #第一行的标签不是咱们需要的内容，line_num表示文件的第几行
                if reader.line_num==1:
                    continue
                print("当前行数：",reader.line_num,"当前内容",item)
                findnode = matcher.match('Source',ip=item[2]).first()
                endnode = matcher.match('Protocol',time=item[1]).first()
                relationships = Relationship(findnode, "发出", endnode)
                relationships["time"] = item[1]
                g.merge(relationships)
                # 创建关系，分类的方式是根据第二个参数（实体）即Protocol的time属性
        with open(self.data_dir, 'r', encoding='utf-8') as f:
            #数据集除了第一行代表属性外，第一列为实体1，第二列为实体2，第三列是两者英文关系，第四列为两者中文关系
            reader=csv.reader(f)
            for item in reader:
                #第一行的标签不是咱们需要的内容，line_num表示文件的第几行
                if reader.line_num==1:
                    continue
                print("当前行数：",reader.line_num,"当前内容",item)
                findnode = matcher.match('Protocol',time=item[1]).first()
                endnode = matcher.match('Destination',ip=item[3]).first()
                relationships = Relationship(findnode, "发向", endnode)
                relationships["time"] = item[1]
                g.merge(relationships)
