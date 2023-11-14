#!/bin/bash
#运行之前kill掉之前的端口
#kill $(lsof -ti -c main_node)
#设置堆栈大小
ulimit -s 102400
num=$1
#gnome-terminal -t "mainCamera" --window -- ./main_seednode $((num+1))
for i in $(seq 10001 $((num+10000)))
do
    # 使用 valgrind 检查程序内存错误并输出到对应的日志文件中
    valgrind --tool=memcheck --leak-check=full  --log-file=./log/$i.log ./main_node $i &
    #./main_node $i 2>./log/$i.log &
done
wait

#valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --log-file=./log/$i.log ./main_node $i &


