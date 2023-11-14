#!/bin/bash
kill $(lsof -ti -c main_node)
echo "聚合可信测试！"
echo "运行种子节点"
ulimit -s 102400
num=$1
gnome-terminal -t "mainCamera" --window -- ./main_RV $((num+1))
gnome-terminal --window -- ./main_seednode $((num+1))
echo "运行若干个非种子节点"
if [ $num -gt 25 ]
then
parallel -j ${num}  --delay 0.3 ./main_node  ::: $(seq 10001 $((num+10000)))
else
parallel -j ${num} ./main_node  ::: $(seq 10001 $((num+10000)))
fi

#parallel -j 39  valgrind -q ./main_node  {} ::: $(seq 10001 10039)

#杀死mainnode开启的端口
#kill $(lsof -ti -c main_node)
#检测内存泄漏 
#valgrind --leak-check=full ./main_node             valgrind --log-file=result.txt --leak-check=full   
#--delay 0.3   -j ${num}
#批量查找文件内容 grep -rl "malloc" log/    

