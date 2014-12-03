def compare(seqNo, expectNo):
    if expectNo == None:
        return 0
    upperBound = (expectNo + ((2**32)/2)) % (2**32) 
    if expectNo + ((2**32) / 2) >= 2**32:
        if ((seqNo > expectNo) and (seqNo <= 2**32 -1)) or (seqNo >= 0 and seqNo < upperBound):
            return 1
        elif seqNo == expectNo:
            return 0
        else:
            return -1
    else:
        if (seqNo > expectNo) and (seqNo < upperBound):
            return 1
        elif seqNo == expectNo:
            return 0
        else:
            return -1

    def compare(self, seqNo, expectNo):
        if expectNo == None:
            return 0
        upperBound = (expectNo + ((2**32)/2)) % (2**32) 
        if expectNo + ((2**32) / 2) >= 2**32:
            if ((seqNo > expectNo) and (seqNo <= 2**32 -1)) or (seqNo >= 0 and seqNo < upperBound):
                return 1
            elif seqNo == expectNo:
                return 0
            else:
                return -1
        else:
            if (seqNo > expectNo) and (seqNo < upperBound):
                return 1
            elif seqNo == expectNo:
                return 0
            else:
                return -1

print "expect " + "0"
print compare(2**32/4*3, 2**32/4*3)
print "expect " + "1"
print compare(2**32-1, 2**32/4*3)
print "expect " + "1"
print compare(0, 2**32/4*3)
print "expect " + "1"
print compare(1000, 2**32/4*3)
print "expect " + "-1"
print compare(((2**32/4*3) + (2**32/2)) % (2**32), 2**32/4*3)
print "expect " + "1"
print compare(((2**32/4*3) + (2**32/2) - 1) % (2**32), 2**32/4*3)

# num = 2**32/4
print "expect" + "0"
print  compare(2**32/4,2**32/4)
print "expect" + "1"
print  compare(2**32/4 + 3000,2**32/4)