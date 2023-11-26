#! /bin/bash
cd build
make -j8
cd ..

killall ./build/bin/pqc_mpsi_example

dirName="log/$4"

# 检查目录是否存在，如果不存在，则创建它
[ ! -d "$dirName" ] && mkdir "$dirName"

for i in `seq $2 -1 $1`;
do
	nohup ./build/bin/pqc_mpsi_example -r $i -N $3 -F files/addresses -n $4 -t $5 -o $6 -y $7 -R 4 -c $8 > $dirName/$i.log 2>&1 &
	echo "Running $i..." &
done

# ./run_protocol.sh 0 15 16 4096 15 Relaxed Threshold 8
# ./run_protocol.sh 0 15 16 65536 15 Relaxed Threshold 8
# ./run_protocol.sh 0 15 16 262144 15 Relaxed Threshold 8
# ./run_protocol.sh 0 15 16 1048576 15 Relaxed Threshold 8
# ./run_protocol.sh 0 15 16 16777216 15 Relaxed Threshold 8
# ./run_protocol.sh 0 1 2 67108864 1 Relaxed Threshold 1