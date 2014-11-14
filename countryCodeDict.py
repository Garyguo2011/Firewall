import socket

class CountryCodeEntry(object):
    def __init__(self, lowerIPnum, higherIPnum, countryCode):
        self.lowerIPnum = lowerIPnum
        self.higherIPnum = higherIPnum
        self.countryCode = countryCode

    def compareWithLower(self, ipNumber):
        if ipNumber > self.lowerIPnum:
            return 1
        elif ipNumber == self.lowerIPnum:
            return 0
        else:
            return -1

    def compareWithHigher(self, ipNumber):
        if ipNumber > self.higherIPnum:
            return 1
        elif ipNumber < self.higherIPnum:
            return -1
        else:
            return 0

class CountryCodeDict(object):
    def __init__(self, dataBase):
        self.incLst=[]
        # While loop reading file and parse entries and store as CountryCodeEntry
        # Finish in constructor
        inputFile = open(dataBase)
        fileLine = inputFile.readline()
        count = 0
        while fileLine:
            self.add(fileLine)
            fileLine = inputFile.readline()

    def add (self, inputStr):
        # conver every ipaddress into integrer number
        # 1.2.3.4 = 1 << 24 | 2 << 16 | 3 << 8 | 4
        # parse this string
        elem = inputStr[:-1].split()
        llist = elem[0].split('.')
        lowerIPnum = (int(llist[0]) << 24) + (int(llist[1]) << 16) + (int(llist[2])  << 8) + int(llist[3])
        higherIPnum = elem[1]
        hlist = elem[1].split('.')
        higherIPnum = (int(hlist[0]) << 24) + (int(hlist[1]) << 16) + (int(hlist[2])  << 8) + int(hlist[3])
        countrycode = elem[2]
        self.incLst.append(CountryCodeEntry(lowerIPnum, higherIPnum, countrycode))

    def lookup(self, ipNumber):
        # return a countrycode
        # covert ipAddress to integer number and do radix or bineary search
        # print 'reach here'
        # ipStr = self.ip_int_to_str(ipNumber).split('.')
        # ipInt = (int(ipStr[0]) << 24) + (int(ipStr[1]) << 16) + (int(ipStr[2])  << 8) + int(ipStr[3])
        return self.binary_search(ipNumber, 0, len(self.incLst) - 1)

    def binary_search(self, ip, imin, imax):
        if (imax < imin):
            return None
        imid = (imin + imax) / 2
        # if imid == 1119:
            # print '1119 here' + str(imax) + '***' + str(imin)
        if (self.incLst[imid].compareWithLower(ip) == -1):
            return self.binary_search(ip, imin, imid - 1)
        elif (self.incLst[imid].compareWithLower(ip) == 1):
            if (self.incLst[imid].compareWithHigher(ip) != 1):
                return self.incLst[imid].countryCode 
            else:
                return self.binary_search(ip, imid + 1, imax)
        else:
            # print 'reach here'
            return self.incLst[imid].countryCode   

    def ip_int_to_str(self, ipNum):
        ipStrList = []
        ipStrList.append((ipNum >> 24) & 255)
        ipStrList.append((ipNum >> 16) & 255)
        ipStrList.append((ipNum >> 8) & 255)
        ipStrList.append((ipNum >> 0) & 255)
        return "%d.%d.%d.%d" % (ipStrList[0], ipStrList[1], ipStrList[2], ipStrList[3])