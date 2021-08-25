#! /usr/bin/env python3
import pwn
import sys
import base64
encodedata = [None]*14
conn = pwn.process(["nc", "140.138.77.30", "6016"])
rec = conn.recvline()
rec = rec.decode('utf-8')
print(rec)
IV = rec[rec.index('['):rec.index(']')+1]
cipher = rec[rec.index("'")-1:rec.index("'")+26]
IV2 = IV[1:len(IV)-1].split(',')
IV = [None]*16
for i in range(0,16):
    IV2[i]=int(IV2[i])
    IV[i] = IV2[i] 
#print(IV2)
for j in range (0,14):
    for k in range (0,2+j):
        IV2[15-k]=IV2[15-k]^(3+j)^(2+j)
    for i in range (0,255):
        IV2[13-j]=i
        conn.sendline('{}, {}'.format(IV2,cipher))
        r = conn.recvline(keepends =False)
        if r.decode('utf-8') == "RightPadding":
            encodedata[13-j]=(i^(3+j)^IV[13-j])
            break
encodedata = ''.join(chr(i) for i in encodedata)
print(encodedata)
#encodedata = encodedata+'=='
#encodedata = base64.b64decode(encodedata)
#print(encodedata)
#for i in range(0,14):
#    IV2[i]='00'
#IV=','.join(IV2)
#IV = '['+IV+']'
#conn.sendline(base64.b64encode(encodedata))
#print(IV+','+cipher)
#print(conn.recvline())

