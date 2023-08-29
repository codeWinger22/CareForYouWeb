#algorithm for assigning doctors to patients
pat = ['p1','p2','p3','p4','p5','p6','p7','p8','p9','p10','p11','p12','p13','p14','p15','p16']
doct = ['d1','d2','d3','d4']
doctorcount = len(doct)
patientcount = len(pat)
if(patientcount <=doctorcount):
    max_capacity = patientcount
else:
    max_capacity = patientcount // doctorcount
print(max_capacity)
d = dict()
if(max_capacity == patientcount):
    for i in range(max_capacity):
        d[i] = doct[i]
        
else:
    print("here")
    count = 1
    maincount =0
    l = []
    for i in range(patientcount):
        if(count>max_capacity):

            count =1

            maincount = maincount + 1

        #d[patval] = doct[maincount
        d[pat[i]] = doct[maincount]
        count = count +1



print("ended")
print(d)

    

    
