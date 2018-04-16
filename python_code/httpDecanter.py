import collections
import datetime, pytz, json
import networkx as nx
import matplotlib.pyplot as plt


class httpDecanter():
    def __init__(self):
        self.headNode = list()
        self.exfiltration = list()
        self.targetFile = str()
    
    def setTargetFile(self, targetFile):
        self.targetFile = targetFile
        
    ## 讀取檔案
    def loadData(self, mode='file', target=list()):
        def filterComment(tmpStr):
            '''去除註解'''
            if tmpStr[0] != '#':
                return tmpStr

        def urlClean(tmpUrl):
            return tmpUrl[:-1] if tmpUrl[-1] == '/' else tmpUrl
        
        def tzConvert(ts, tzNew='Asia/Taipei', tzOld='UTC'):
            '''timestamp 轉換'''
            tzOld = pytz.timezone(tzOld)
            tzNew = pytz.timezone(tzNew)

            ts = datetime.datetime.fromtimestamp(float(ts))
            return tzOld.localize(ts).astimezone(tzNew).strftime('%Y-%m-%d %H:%M:%S')

        # 檢查是否有 set target file
        if not self.targetFile:
            print ('please set the target file')
            assert self.targetFile 
            
        if mode == 'file':
            with open(self.targetFile, 'r') as f:
                oriData = f.readlines()
                fieldName = oriData[6].strip().split('\t')[1:]  # 欄位名稱

                data = filter(filterComment, oriData)            
                data = [i.strip().split('\t') for i in data]

        elif mode == 'list':
            oriData = target
            fieldName = oriData[6].strip().split('\t')[1:]  # 欄位名稱
            
            data = filter(filterComment, oriData)            
            data = [i.strip().split('\t') for i in data]
            

        else:
            # 修改
            print ('load error')
            return None
            
        res = list()
        for line in data:
            tmpDict = { c:line[i] if i != 0 else tzConvert(line[0]) for i, c in enumerate(fieldName)}
            
            # 統一 ref, host 網址格式
            tmpDict['referrer'] = tmpDict['referrer'].replace('http://', '').replace('https://', '').strip('/')
            tmpDict['referrer'], tmpDict['host'] = urlClean(tmpDict['referrer']), urlClean(tmpDict['host'])
            res.append(tmpDict)

#         print (fieldName[10])
        return res

    ## 標記 requests data
    def labeling(self, target):
        browsers = ['Chrome','Safari','Firefox','Mozilla']
#         resTypes = ['text/html', 'text/css', 'application/x-javascript', 'application/x-shockwave-flash']
        
        target['label'] = 'background APP'
        
        if target['referrer'] == '-':
            self.exfiltration.append(target)
            
        # check_useragent
        for b in browsers:
            if b in target['user_agent']:
                target['label'] = 'browser'
                
                self.headNode.append(target)
                break
            
#         if target['resp_mime_types'] in resTypes:
#             self.headNode.append(target)
#             target['label'] = 'browser'
            
        return target
                
    def clear(self):
        self.headNode = list()
        self.exfiltration = list()
    
    def procLabeling(self, allData=True):
        self.clear()
        data = self.loadData()
        
        res = list()
        for r in data:
            r = self.labeling(r)
            
            # 是否跳出特定資料 (background APP)
            if allData:
                res.append(r)
            else:
                if r['label'] == 'background APP':
                    res.append(r)
            
        return res
    
    ## 找出獨立點的資料
    def calcIsolate(self):
        data = self.procLabeling()
        headNode = self.headNode
        G = nx.Graph()
        G.clear()
        head_node = [str(head['host']) for head in headNode]
        
        # 計算連線關係
        for line in data:
            try:
                G.add_node(str(line['host']))
            except NameError:
                G.add_node(str(line['host']))
            if line['host'] != '-':
                G.add_edge(str(line['host']), str(line['referrer']))                                             

        G.remove_node('-')

        # 計算 isolate 的資料
        points = [isolatePoint for isolatePoint in nx.isolates(G)]
        
        res = list()
        # 找出 isolate 的資料
        for line in data:
            for p in points:
                if p == line['host']:
                    res.append(line)
                    break
        return res

    ## 視覺化
    def drawNetworkPlot(self, fileName="graph", show=False):
        plt.figure(figsize=(16,12))
        data = self.procLabeling()
        headNode = self.headNode
        G = nx.Graph()
        G.clear()
        headNode = [str(head['host']) for head in headNode]
        
        # 計算連線關係
        for line in data:
            try:
                G.add_node(str(line['host']))
            except NameError:
                G.add_node(str(line['host']))
            if line['host'] != '-':
                G.add_edge(str(line['host']), str(line['referrer']))                                           

        G.remove_node('-')
        pos = nx.spring_layout(G)
        nx.draw(G, pos) 
        nx.draw_networkx_nodes(G,pos, nodelist=headNode, node_color='b')
        for p in pos: 
            pos[p][1] += 0.02
        nx.draw_networkx_labels(G, pos)

        # 儲存或顯示
        if show:
            plt.show()
        else:
            plt.savefig("%s.png" % fileName, format="PNG")
            plt.close()

    ## 建立 Fingerprint
    def createFingerPrint(self, saveFileName="test"):
        # fingerprint 採用的 keys name
        fgKeys = {
            'ip': 'id.resp_h', 
            'host': 'host', 
            'user_agent': 'user_agent'
        }

        def averageDataLen(label, reqLen, resLen, num):
            # 計算平均流量值，目前去除 0 的值
            averageReq = 0
            averageRes = 0
            if reqLen != 0:
                num[0] += 1
                averageReq = (float(trainDict[label]['request_len']) * (num[0] - 1) + reqLen) / num[0]
            if resLen != 0:
                num[1] += 1
                averageRes = (float(trainDict[label]['respond_len']) * (num[1] - 1) + resLen) / num[1]
        #     if averageRes != 0:
        #         print (averageReq, averageRes, num)
            return averageReq, averageRes, num
        
        data = self.procLabeling(allData=False)
        trainDict = dict()
        for i, r in enumerate(data):
            if r[fgKeys['user_agent']].strip() != "-":
                label = r[fgKeys['user_agent']].strip()
                # 建立 fingerprint info
                if label not in trainDict:
                    trainDict[label] = {
                        'ip': list([r[fgKeys['ip']].strip()]),
                        'host': list([r[fgKeys['host']].strip()]),
                        'user_agent': list([r[fgKeys['user_agent']]]),
                        'num': list([0,0])
                    }
                else:
                    # 如果已有 fringerprint 檢查是否需要增加的 info，如 ip
                    for k in fgKeys:
                        tmpData = r[fgKeys[k]].strip()
                        if tmpData not in trainDict[label][k]:
                            trainDict[label].setdefault(k, list()).append(tmpData)

                #  check requests len
                if int(r['request_body_len'].strip()) != 0:
                    trainDict[label]['request_len'] = float(r['request_body_len'].strip())
                else:
                    trainDict[label]['request_len'] = list()

                # check response len
                if int(r['response_body_len'].strip()) != 0:
                    trainDict[label]['respond_len'] = float(r['response_body_len'].strip())
                else:
                    trainDict[label]['respond_len'] = list()
                
                # 計算平均流量
                trainDict[label]['request_len'], trainDict[label]['respond_len'], trainDict[label]['num'] = averageDataLen(label, float(r['request_body_len']), float(r['response_body_len']), trainDict[label]['num'])
            else:
                pass
            
        with open('%s.json' % saveFileName, 'w') as fpFile:
            fpFile.write(json.dumps(trainDict))
            
    
    def detection(self, fingerPrintFile):
        
        def outgoingInfo(label, req):
            req_len = float(req['request_body_len'])
            res_len = float(req['response_body_len'])

            #label = data[12]
            if req_len > float(train_dict[label]['request_len']):
                print(req_len, train_dict[label]['request_len'])
                #return 
            elif res_len > float(train_dict[label]['respond_len']):
                print(res_len, train_dict[label]['respond_len'])
            else:
                return

        def similarity(targetData, whiteListData):
            fgKeys = {
            'ip': 'id.resp_h', 
            'host': 'host', 
            'user_agent': 'user_agent'
            }

            score = 0
            for key in fgKeys:
                if targetData[fgKeys[key]] in whiteListData[key]:
                    score += 1
            #if score > 1:
            #    WhiteListUpdate(test_data,whiteList_data)
            #else:
            #    outgoingInfo()
            return score
        
        # 讀取白名單的 fingerprint
        with open('%s.json' % fingerPrintFile, 'r') as fp_f:
            fingerPrintDict = json.loads(fp_f.read())
            
        toBeDetermined = list()
        NoHost = list()
        # 載入背景程式的 req
        data = self.procLabeling(allData=False)
        for i, r in enumerate(data):
            similarityScore = 0

            # 檢查是否有 host 資料
            if r['host'] == '-':
                NoHost.append(r)
            else:
                if r['user_agent'] in fingerPrintDict:
                    whiteList = fingerPrintDict[r['user_agent']]
                    similarityScore = similarity(r, whiteList)

                else:
                    maxScore = 0
                    likelihoodAPP = list()  # 較為相近的 application
                    for label in fingerPrintDict:
                        similarityScore = similarity(r, fingerPrintDict[label])

                        if similarityScore > maxScore:
                            likelihoodAPP = [r]
                            maxScore = similarityScore
                        elif (similarityScore > 0) and (similarityScore < maxScore):
                            likelihoodAPP.append(r)
                    if maxScore == 0:
                        toBeDetermined.append(r)
        return toBeDetermined