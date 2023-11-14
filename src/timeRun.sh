#!/bin/bash
# 运行次数
echo 0>temp.txt
count=29
num=39
# 待执行的脚本
script="test.sh"

# 循环执行脚本
for (( i=1; i<=count; i++ ))
do
    # 输出当前执行的次数
    echo "执行第 $i 次"
    # 执行脚本
    ./$script ${num}
    result=$(cat temp.txt)
     # 循环等待文件中输出值为 2
  while true
  do
    # 检查文件中是否含有 "2"
    if grep -q "2" temp.txt
    then
      #结束时将文件的2抹去
      echo 0>temp.txt
      break  # 如果文件中含有 "2"，则退出循环
    fi

    sleep 1  # 等待 1 秒再检查一次
  done
  
    
done


:<<'COMMENT'
count=20
num=4
# 待执行的脚本
script="test.sh"

START=4
END=39
STEP=5

for (( j=$START; j<=$END; j+=STEP )); do
    # 在这里执行你要执行的命令，例如：
    # 循环执行脚本

	for (( i=1; i<=count; i++ ))
	do
	    # 输出当前执行的次数
	    echo "执行第 $i 次"
	    # 执行脚本
	    ./$script ${j}
	    result=$(cat temp.txt)
	     # 循环等待文件中输出值为 2
	  while true
	  do
	    # 检查文件中是否含有 "2"
	    if grep -q "2" temp.txt
	    then
	      #结束时将文件的2抹去
	      echo 0>temp.txt
	      break  # 如果文件中含有 "2"，则退出循环
	    fi

	    sleep 1  # 等待 1 秒再检查一次
	  done
	done
    
done

COMMENT
