#!/usr/bin/env python
#coding=utf8
#-*-coding:utf-8-*-

import datetime, pytz
import json

class fingerPrintGen():
    def __init__(self, filePath):
        self.httpLogData = self.loadData(filePath)

    def loadData(self, filePath):
        # 將前面的註解篩掉
        def filterComment(tmpStr):
            if tmpStr[0] != '#':
                return tmpStr
        def tzConvert(ts, tzNew='Asia/Taipei', tzOld='UTC'):
            '''timestamp 轉換'''
            tzOld = pytz.timezone(tzOld)
            tzNew = pytz.timezone(tzNew)

            ts = datetime.datetime.fromtimestamp(float(ts))
            return tzOld.localize(ts).astimezone(tzNew).strftime('%Y-%m-%d %H:%M:%S')

        def urlClean(tmpUrl):
            return tmpUrl[:-1] if tmpUrl[-1] == '/' else tmpUrl
        
        with open(filePath) as f:
            oriData = f.readlines()
            data = filter(filterComment, oriData)

            field = oriData[6].strip().split('\t')[1:]
            # print ('field:', field)  # 欄位名稱

        res = list()
        for i in data:
            line = i.strip().split('\t')

            # 依照欄位名稱轉變成dict的資料型態，其中 ts 有轉變成當地時間
            tmpDict = { c:line[i] if i != 0 else tzConvert(line[0]) for i, c in enumerate(field)}

            # 特別處理 ref 的 http:// 和 https://
            tmpDict['referrer'] = tmpDict['referrer'].replace('http://', '').replace('https://', '')
            tmpDict['referrer'], tmpDict['host'] = urlClean(tmpDict['referrer']), urlClean(tmpDict['host'])
            tmpDict['_id'] = tmpDict['uid']

            try:
                del tmpDict['uid']
            except:
                pass
            res.append(tmpDict)
        return res
    
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
        
        trainDict = dict()
        for i, r in enumerate(self.httpLogData):
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