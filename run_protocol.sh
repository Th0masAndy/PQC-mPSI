#! /bin/bash
for i in `seq $2 -1 $1`;
do
        ./build/bin/psi_analytics_eurocrypt19_example -r $i -N $3 -F files/addresses -n $4 -m $5 &
        echo "Running $i..." &
done
