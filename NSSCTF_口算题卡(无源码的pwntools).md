NSSCTF_口算题卡(无源码的pwntools)

#知识点（pwntool脚本知识点）

##### 1，while ture，try，except EOFError结构

##### 2，formula = io.recvuntil(b"?", drop=True).decode()中drop = true和decode()

这里的drop = true是指的是放弃"?",decode()的意思是把接收到的字节流作为字符串处理，便于下一步split切割

##### 3，parts = formula.split()把formula切割成三份

split()中无参默认是用空格切割的



