#! /bin/bash
cd build
make -j8
cd ..

killall ./build/bin/pqc_mpsi_example

for i in `seq $2 -1 $1`;
do
	nohup ./build/bin/pqc_mpsi_example -r $i -N $3 -F files/addresses -n $4 -t $5 -o $6 -y $7 -R 4 -c $8 > log/$i.log 2>&1 &
	echo "Running $i..." &
done

# ./run_protocol.sh 0 14 15 4096 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 65536 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 262144 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 1048576 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 4194304 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 16777216 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 268435456 14 Relaxed Threshold 7
