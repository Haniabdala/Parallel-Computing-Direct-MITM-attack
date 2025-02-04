# Golden Collision Search: Meet-in-the-Middle Attack (using MPI and OPENMP)

## Problem Overview

In this project, we are tackling a cryptographic problem where the goal is to find a **"golden collision"** `(x, y)` such that:

- \( f(x) = g(y) \)
- \( \pi(x, y) = 1 \)

Where:
- `f`, `g` are functions that map binary strings of length `n` to binary strings of length `n`.
- `π` is a predicate that checks if the pair `(x, y)` satisfies a condition.

We aim to solve this problem efficiently using an algorithm known as the **Meet-in-the-Middle Attack**. This algorithm allows us to find the golden collision without resorting to brute-force methods. It performs significantly fewer operations than a naive brute-force approach, making it much more feasible for larger values of `n`.

---

## What We Are Trying to Solve

Given two functions \( f \), \( g \) and a predicate \( \pi \), our goal is to find a **pair** `(x, y)` where:

1. **Function Match**: \( f(x) = g(y) \)
2. **Predicate Condition**: \( \pi(x, y) = 1 \)

This is not just a theoretical problem—it's something that can be applied in fields like **cryptanalysis**, where efficient search techniques are essential.

### Why is this Problem Important?

The brute-force approach to solve this would require testing **all pairs** `(x, y)` in the search space, which grows exponentially as `n` increases. This results in \( 2^{2n} \) possible pairs, which is infeasible for large `n` (e.g., \( n \geq 40 \)).

The **Meet-in-the-Middle Attack** solves the problem much more efficiently by reducing the number of operations to \( 3 \times 2^n \) on average, using only \( 2^n \) words of memory. This is a significant improvement over brute-force methods, and it makes solving this problem much more practical for larger values of `n`.

---

## How the Meet-in-the-Middle Attack Works

The Meet-in-the-Middle algorithm works by splitting the problem into two parts:

1. **Step 1**: We create a **dictionary** \( D \) where for each \( x \in \{0, 1\}^n \), we store the pair \( f(x) \to x \).
2. **Step 2**: For each \( y \in \{0, 1\}^n \), we check if there exists any `x` such that \( g(y) = f(x) \) (i.e., check if \( g(y) \) exists in the dictionary \( D \)).
3. **Step 3**: For each matching pair, we check if the predicate \( \pi(x, y) = 1 \). If true, we return the pair `(x, y)` as the **golden collision**.

This algorithm is **efficient** and significantly reduces the complexity of the search, especially for larger values of `n`.

---

## 1 Approach
Our approach takes a structured strategy by breaking the problem into 4 major components:
  1. Dictionary distribution.
  2. Key and value generation.
  3. Data Exchange.
  4. Identifying the solution.

By separating these components, we can independently execute each stage across multiple cores, which
increase scalability and reduces computation time.


## 2 Implementation

### 2.1 Dictionary Setup
In this section, individual cores perform their part of generating the dictionary jointly. This way,
parallel processing is allowed, which helps to save memory as well as improves resource usage without
sacrificing any data or functionalities.
Instead of assigning the entire dictionary of size N to a single core, we divide the global dictionary
evenly across all the available cores. With work being equally divided, processes can be faster and
more efficient without any dependencies, as follows:

#### 2.1.1 Distributed Initialization via OpenMP
The contribution on OpenMP into the dictionary initialization, since this process is done separately on
each core, then we can benefit from threading the initialization for loop using OpenMP, thus we can
reduce the time needed to initialize the local dictionary on each core, leading to faster overall setup.

### 2.2 Key and value generation
Each core will then use the fill function which has been customized to allow more granular control over
the dictionary setup and to increase parallelization potential.
This function includes the ”dict setup” that initialize the dictionary, ”Keys generation using f(x)
that generate Keys and respective values” and ”dict insert” which allow us to insert the generated
keys in the dictionary along side with their respective values.

### 2.3 Data Exchange
Once each node have initialized it local dictionary, it will start going over its (key,value) tuples, generating the ”Keys generation using g(x) ” packing them into an 1D array of (g(x), x). 
All the other nodes, will do exactly the same as these values with be shared between all nodes. There might exist multiple strategy on how to share these values using MPI, but as we noticed that each node must share its value to all other nodes, the most natural and straight forward operation was MPI_ALLGATHER(), this operation shine as it guarantee consistency and integrity of the shared data across all the processors of the communicator, since MPI_ALLGATHER() is a collective operation.

### 2.4 Identifying the solution
After exchanging the generated values between all nodes, each node will iterate individually over its
own generated values and the received ones with its own local dictionary that was previously initialized
and evaluate them to find a solution.


### 2.5 Optimization

#### 2.5.1 Number of nodes
After analyzing our parallel code on different node numbers as its shown in section ”3.2 Efficient number of cores”, it was clear that the best choice of the number of nodes is 2n (power of 2), since as
mentioned in section ”2.1 Dictionary Setup”, the Global dictionary size is 2n.
But note that choosing the highest number of nodes is not always the best option, as the cost of
communication will then increase and become more than the cost of processing and memory organization.

#### 2.5.2 Auto-vectorization
By using Optimization level 3, we can implement Auto-vectorization on our parallel code, along side
with other optimizations done by the compiler, below are the vectorized code blocks, generated by the
vectorization report:
- ~$ mpicc -O3 -fopenmp -fopt-info-vec mitm.c -o run
- mitm.c:240:9: optimized: basic block part vectorized using 16 byte vectors
- mitm.c:256:5: optimized: basic block part vectorized using 16 byte vectors
- mitm.c:274:24: optimized: basic block part vectorized using 16 byte vectors
- mitm.c:400:26: optimized: basic block part vectorized using 16 byte vectors

### 2.6 Bottleneck
Choosing the right number of nodes to execute the parallel code is crucial, as we must take a decision
to choose between better space handling or faster execution time.
Choosing a slow network infrastructure will affect the execution time, as the problem size N increases,
the memory required to store the dictionaries increases, this will then becomes a major bottleneck as
the number of communication between the nodes will massively increase as well, so having a faster
network is highly recommended.






