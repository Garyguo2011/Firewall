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
        inputFile = open(dataBase)
        fileLine = inputFile.readline()
        count = 0
        while fileLine:
            self.add(fileLine)
            fileLine = inputFile.readline()

    def add (self, inputStr):
        elem = inputStr[:-1].split()
        llist = elem[0].split('.')
        lowerIPnum = (int(llist[0]) << 24) + (int(llist[1]) << 16) + (int(llist[2])  << 8) + int(llist[3])
        higherIPnum = elem[1]
        hlist = elem[1].split('.')
        higherIPnum = (int(hlist[0]) << 24) + (int(hlist[1]) << 16) + (int(hlist[2])  << 8) + int(hlist[3])
        countrycode = elem[2]
        self.incLst.append(CountryCodeEntry(lowerIPnum, higherIPnum, countrycode))

    def lookup(self, ipNumber):
        return self.binary_search(ipNumber, 0, len(self.incLst) - 1)

    def binary_search(self, ip, imin, imax):
        if (imax < imin):
            return None
        imid = (imin + imax) / 2
        if (self.incLst[imid].compareWithLower(ip) == -1):
            return self.binary_search(ip, imin, imid - 1)
        elif (self.incLst[imid].compareWithLower(ip) == 1):
            if (self.incLst[imid].compareWithHigher(ip) != 1):
                return self.incLst[imid].countryCode 
            else:
                return self.binary_search(ip, imid + 1, imax)
        else:
            return self.incLst[imid].countryCode   