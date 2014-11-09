class CountryCodeEntry(object):
    def __init__(self, lowerIPnum, higherIPnum, countryCode):
        self.lowerIPnum
        self.higherIPnum
        self.countryCode

    def compareWithLower(self, ipNumber):
        if ipNumber > self.lowerIPnum:
            return 1
        elif ipNumber == self.lowerIPnum:
            return 0
        else:
            return -1

class CountryCodeDict(object):
    def __init__(self, dataBase):
        self.incLst=[]
        # While loop reading file and parse entries and store as CountryCodeEntry
        # Finish in constructor
        fptr = open (dataBase)
        while fptr.readline():
            self.add (inputStr)

    def add (self, inputStr):
        # conver every ipaddress into integrer number
        # 1.2.3.4 = 1 << 24 | 2 << 16 | 3 << 8 | 4
        # parse this string
        self.incLst.append(CountryCodeEntry(lowerIPnum, higherIPnum, countrycode))

    def lookup(self, ipAddress):
        # return a countrycode
        # covert ipAddress to integer number and do radix or bineary search
        return "CN"