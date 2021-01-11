#! /bin/bash
#for i in `seq 1 5`;
#do
echo "Trial $1"
nvals=( 4 5 10 15)
for j in "${nvals[@]}"
do
	echo "n = $j"
	last=`expr $j - 1`
	first=0
	mvals=(4096 65536 1048576)
	bvals=(16 248 4002)
	svals=(975 1021 1024)
	for k in `seq 0 2`;
	do
		echo "Starting m = ${mvals[$k]}, beta = ${bvals[$k]}, s = ${svals[$k]}" &&
		(for l in `seq $last -1 $first`;
		do
			system("./build/bin/psi_analytics_eurocrypt19_example -r $l -N $j -F files/addresses -n ${mvals[$k]} -m ${bvals[$k]} -s ${svals[$k]} -t ${last} -o Relaxed -y PSI -R 4 -c $j") &
		done) > "timings/wan/psi/relaxed/test_$1_${j}_${mvals[$k]}" 
	wait 
		echo "Done with m = ${mvals[$k]}, beta = ${bvals[$k]}, s = ${svals[$k]}" ;	
	done 
done
#done

#for i in `seq $2 -1 $1`;
#do
#        ./build/bin/psi_analytics_eurocrypt19_example -r $i -N $3 -F files/addresses -n $4 -m $5 -s $6 -t $7 -o $8 -y $9 -R ${10} -c ${11} &
#        echo "Running $i..." &
#done
