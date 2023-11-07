#! /bin/bash
cd build
make -j
cd ..


process_name="./build/bin/pqc_mpsi_example"

process_ids=$(ps aux | grep "$process_name" | grep -v "grep" | awk '{print $2}')
for pid in $process_ids; do
  kill -9 $pid
  echo "Killed process $pid with name $process_name"
done

for i in `seq $2 -1 $1`;
do
	nohup ./build/bin/pqc_mpsi_example -r $i -N $3 -F files/addresses -n $4 -t $5 -o $6 -y $7 -R 4 -c $8 > log/$i.log 2>&1 &
	echo "Running $i..." &
done

# ./run_protocol.sh 0 14 15 4096 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 65536 14 Relaxed Threshold 7
# ./run_protocol.sh 0 14 15 262144 14 Relaxed Threshold 7