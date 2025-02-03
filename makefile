all: mitm_parallel.c 
	mpicc -O3 -fopenmp -Wall -o mitm_run mitm_parallel.c


clean:
	rm -f mitm_run