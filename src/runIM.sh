#!/bin/bash
#运行之前kill掉之前的端口
kill $(lsof -ti -c main_node_EC)
#设置堆栈大小
ulimit -s 102400
num=$1
gnome-terminal -t "mainCamera" --window -- ./main_seednode_IM $((num+1))
for i in $(seq 10001 $((num+10000)))
do
    # 使用 valgrind 检查程序内存错误并输出到对应的日志文件中
    valgrind --tool=memcheck --leak-check=full  --log-file=./log/$i.log ./main_node_IM $i &
    #./main_node $i 2>./log/$i.log &
done
wait

#valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --log-file=./log/$i.log ./main_node $i &

#openssl x509 -req -in ./pem2/crt/certreq10001layer1.txt -extfile <(printf "subjectAltName=DNS:localhost,DNS:*.localhost\nbasicConstraints=critical,CA:TRUE") -out ./pem2/crt/device10001layer1.crt -CA ./pem2/crt/device10001layer0.crt -CAkey ./pem2/device10001layer0priv.key -CAcreateserial

#openssl x509 -req -in ./pem2/crt/certreq10001layer0.txt -extfile <(printf "subjectAltName=DNS:localhost,DNS:*.localhost\nbasicConstraints=critical,CA:TRUE") -out ./pem2/crt/device10001layer0.crt -CA ./pem2/crt/root.crt -CAkey ./pem2/crt/root.key -CAcreateserial

#openssl verify -verbose -CAfile <(cat ./pem2/crt/device10001layer0.crt ./pem2/crt/root.crt) ./pem2/crt/device10001layer1.crt
#openssl verify -verbose -CAfile <(cat ./pem2/crt/device%dlayer8.crt ./pem2/crt/device%dlayer7.crt ./pem2/crt/device%dlayer6.crt ./pem2/crt/device%dlayer5.crt ./pem2/crt/device%dlayer4.crt ./pem2/crt/device%dlayer3.crt ./pem2/crt/device%dlayer2.crt ./pem2/crt/device%dlayer1.crt ./pem2/crt/device%dlayer0.crt ./pem2/crt/root.crt) ./pem2/crt/device10001layer9.crt >>./pem2/out.txt 2>&1
