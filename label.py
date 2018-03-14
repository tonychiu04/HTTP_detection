#!/usr/bin/env python
#coding=utf8
#-*-coding:utf-8-*-

import collections
import datetime, pytz
import networkx as nx
import matplotlib.pyplot as plt

class Labeling_processor():
    def __init__(self):
        pass
    
    def load_data(self, file_path, mode):
        '''讀取檔案'''
        print (mode)
        def filter_comment(tmp_str):
            '''去除註解'''
            if tmp_str[0] != '#':
                return tmp_str

        if mode == 'file':
            with open(file_path, 'r') as f:
                ori_data = f.readlines()
                self.field_name = ori_data[6].strip().split('\t')[1:]  # 欄位名稱

                data = filter(filter_comment, ori_data)            
                data = [i.strip().split('\t') for i in data]
            return data

        elif mode == 'list':
            ori_data = file_path
            self.field_name = ori_data[6].strip().split('\t')[1:]
            data = filter(filter_comment, ori_data)            
            data = [i.strip().split('\t') for i in data]
            return data

        else:
            # 修改
            print ('load error')
    
    def proc_data(self, path, mode='file'):
        exfiltration = []
        dataset = self.load_data(path, mode)
        head_node = []
        browser = ['Chrome','Safari','Firefox','Mozilla']

        def check_useragent(tmp_data,tmp_index):
            count = 0
            for j in browser:
                if j in tmp_data[12]:
		    dataset[tmp_index].append('browser')
                    headnode.append(tmp_data)
		    break
            	else:
            	    count += 1
                if count == len(browser):
                    dataset[tmp_index].append('background APP')


        for i in range(len(dataset)):
            if 'http' in dataset[i][10]:
                dataset[i][10] = dataset[i][10].strip('https:')
                if '/' in dataset[i][10]:
                    dataset[i][10] = dataset[i][10].strip('/')
            if dataset[i][10] == '-':
                exfiltration.append(dataset[i])

        for i in range(len(dataset)):
            if dataset[i][28] == 'text/html':
                check_useragent(dataset[i])
            elif dataset[i][28] == 'text/css':
                check_useragent(dataset[i])
            elif dataset[i][28] == 'application/x-javascript':
                check_useragent(dataset[i])
            elif dataset[i][28] == 'application/x-shockwave-flash':
                check_useragent(dataset[i])


            # chek the user-agent of request which was send by browser or not
            else:
                count = 0
                for j in browser:
                    if j in dataset[i][12]:
                        count += 1
                if count > 0:
                    dataset[i].append('browser')
                else:
                    dataset[i].append('background APP')
        self.dataset, self.head_node = dataset, head_node
        return dataset
        #return DataSet ,Features,DisconnectedNodeFilter(exfiltration),HeadNode


    def calc_isolate(self):
        data = self.dataset
        head_nodeset = self.head_node
        G = nx.Graph()
        G.clear()
        head_node = [str(head_nodeset[head][8]) for head in range(len(head_nodeset))]
        for i in range(len(data)):
            try:
                G.add_node(str(data[i][8]))
            except NameError:
                G.add_node(str(data[i][8]))
            if data[i][8] != '-':
                G.add_edge(str(data[i][8]),str(data[i][10]))                                             

        G.remove_node('-')
        # pos = nx.spring_layout(G)
        # for p in pos: 
        #     pos[p][1] += 0.02
        
        points = [isolate_point for isolate_point in nx.isolates(G)]
        
        res = list()
        for i in range(len(self.dataset)):
            for j in points:
                if j in self.dataset[i][8]:
                    tmp_dict = dict()
                    for k in range(len(self.field_name)):
                        tmp_dict[self.field_name[k]] = self.dataset[i][k]
                    res.append(tmp_dict)
                    break
        return res

    def draw_network_plot(self, file_name="graph", show=False):
        plt.figure(figsize=(16,12))
        data = self.dataset
        head_nodeset = self.head_node
        G = nx.Graph()
        G.clear()
        head_node = [str(head_nodeset[head][8]) for head in range(len(head_nodeset))]
        for i in range(len(data)):
            try:
                G.add_node(str(data[i][8]))
            except NameError:
                G.add_node(str(data[i][8]))
            if data[i][8] != '-':
                G.add_edge(str(data[i][8]),str(data[i][10]))                                             

        G.remove_node('-')
        pos = nx.spring_layout(G)
        nx.draw(G, pos) 
        nx.draw_networkx_nodes(G,pos,nodelist=head_node,node_color='b')
        for p in pos: 
            pos[p][1] += 0.02
        nx.draw_networkx_labels(G, pos)

        if show:
            plt.show()
        else:
            plt.savefig("%s.png" % file_name, format="PNG")
            plt.close()

    def tran2dict(self):
        '''轉換成 key-value 的型態'''
        dataset = self.dataset
        
        def clean_url(tmp_url):
            return tmp_url[:-1] if tmp_url[-1] == '/' else tmp_url

        def convert_tz(ts, tz_new='Asia/Taipei', tz_old='UTC'):
            '''timestamp 轉換'''
            tz_old = pytz.timezone(tz_old)
            tz_new = pytz.timezone(tz_new)

            ts = datetime.datetime.fromtimestamp(float(ts))
            return tz_old.localize(ts).astimezone(tz_new).strftime('%Y-%m-%d %H:%M:%S')
     
        field = self.field_name
        field.append('label')
        res = list()
        
        for line in dataset:
            tmp_dict = { c:line[i] if i != 0 else convert_tz(line[0]) for i, c in enumerate(field)}
        
            # 特別處理 ref 的 http:// 和 https://
            tmp_dict['referrer'] = tmp_dict['referrer'].replace('http://', '').replace('https://', '')
            tmp_dict['referrer'], tmp_dict['uri'], tmp_dict['host'] = clean_url(tmp_dict['referrer']), clean_url(tmp_dict['uri']), clean_url(tmp_dict['host'])

            res.append(tmp_dict)
            
        return res
        

    def DisconnectedNodeFilter(self, Data):
        ''' 開發中 '''
        browser =[]
        alerts = []
        for i in range(len(Data)):
            if Data[i][7] == 'GET' or Data[i][7] == 'POST':
                browser.append(Data[i])
            else:
                alerts.append(Data[i])    
        return browser
