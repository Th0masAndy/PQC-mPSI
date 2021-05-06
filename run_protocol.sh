#! /bin/bash
for i in `seq $2 -1 $1`;
do
	./build/bin/psi_analytics_eurocrypt19_example -r $i -N $3 -F files/addresses -n $4 -t $5 -o $6 -y $7 -R 4 -c $8 &
	echo "Running $i..." &
done

