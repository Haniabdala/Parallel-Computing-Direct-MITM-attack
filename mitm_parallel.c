#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <getopt.h>
#include <err.h>
#include <assert.h>
#include <mpi.h>
#include <omp.h>

typedef uint64_t u64; /* portable 64-bit integer */
typedef uint32_t u32; /* portable 32-bit integer */
struct __attribute__((packed)) entry
{
    u32 k;
    u64 v;
}; /* hash table entry */

/***************************** global variables ******************************/

u64 n = 0;     /* block size (in bits) */
u64 mask;      /* this is 2**n - 1 */
u64 dict_size; /* number of slots in the hash table */



/* (P, C) : two plaintext-ciphertext pairs */
u32 P[2][2] = {{0, 0}, {0xffffffff, 0xffffffff}};
u32 C[2][2];

/************************ tools and utility functions *************************/

double wtime()
{
    struct timeval ts;
    gettimeofday(&ts, NULL);
    return (double)ts.tv_sec + ts.tv_usec / 1E6;
}

// murmur64 hash functions, tailorized for 64-bit ints / Cf. Daniel Lemire
u64 murmur64(u64 x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

/* represent n in 4 bytes */
void human_format(u64 n, char *target)
{
    if (n < 1000)
    {
        sprintf(target, "%" PRId64, n);
        return;
    }
    if (n < 1000000)
    {
        sprintf(target, "%.1fK", n / 1e3);
        return;
    }
    if (n < 1000000000)
    {
        sprintf(target, "%.1fM", n / 1e6);
        return;
    }
    if (n < 1000000000000ll)
    {
        sprintf(target, "%.1fG", n / 1e9);
        return;
    }
    if (n < 1000000000000000ll)
    {
        sprintf(target, "%.1fT", n / 1e12);
        return;
    }
}

/******************************** SPECK block cipher **************************/

#define ROTL32(x, r) (((x) << (r)) | (x >> (32 - (r))))
#define ROTR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

#define ER32(x, y, k) (x = ROTR32(x, 8), x += y, x ^= k, y = ROTL32(y, 3), y ^= x)
#define DR32(x, y, k) (y ^= x, y = ROTR32(y, 3), x ^= k, x -= y, x = ROTL32(x, 8))

void Speck64128KeySchedule(const u32 K[], u32 rk[])
{
    u32 i, D = K[3], C = K[2], B = K[1], A = K[0];
    for (i = 0; i < 27;)
    {
        rk[i] = A;
        ER32(B, A, i++);
        rk[i] = A;
        ER32(C, A, i++);
        rk[i] = A;
        ER32(D, A, i++);
    }
}

void Speck64128Encrypt(const u32 Pt[], u32 Ct[], const u32 rk[])
{
    u32 i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 27;)
        ER32(Ct[1], Ct[0], rk[i++]);
}

void Speck64128Decrypt(u32 Pt[], const u32 Ct[], u32 const rk[])
{
    int i;
    Pt[0] = Ct[0];
    Pt[1] = Ct[1];
    for (i = 26; i >= 0;)
        DR32(Pt[1], Pt[0], rk[i--]);
}

/******************************** dictionary ********************************/

/*
 * "classic" hash table for 64-bit key-value pairs, with linear probing.
 * It operates under the assumption that the keys are somewhat random 64-bit integers.
 * The keys are only stored modulo 2**32 - 5 (a prime number), and this can lead
 * to some false positives.
 */
static const u32 EMPTY = 0xffffffff;
static const u64 PRIME = 0xfffffffb;

/* allocate a hash table with `size` slots (12*size bytes) */
void dict_setup(u64 size, struct entry **A)
{
        dict_size = size;
        char hdsize[8];
        human_format(dict_size * sizeof(struct entry), hdsize);
        printf("Dictionary size: %sB\n", hdsize);

        *A = malloc(sizeof(struct entry) * dict_size);
        if (*A == NULL)
                err(1, "impossible to allocate the dictionnary");
    #pragma omp parallel for
        for (u64 i = 0; i < dict_size; i++)
                (*A)[i].k = EMPTY;
}

/* Insert the binding key |----> value in the dictionnary */
void dict_insert(u64 key, u64 value, struct entry *A)
{
    assert(A != NULL);  // Vérifie que la table est initialisée
    u64 h = murmur64(key) % dict_size;  // Calcul de l'index initial
    for (u64 i = 0; i < dict_size; i++) {  // Limite le nombre d'itérations
        if (A[h].k == EMPTY) {
            A[h].k = key;      // Conserve la clé originale (pas de % PRIME)
            A[h].v = value;    // Insère la valeur
            return;
        }
        h = (h + 1) % dict_size;  // Probing linéaire circulaire
    }
    err(1, "Hash table overflow: no space left to insert key %lu", key);  // Détection d'un dépassement
}

/* Query the dictionnary with this `key`.  Write values (potentially)
 *  matching the key in `values` and return their number. The `values`
 *  array must be preallocated of size (at least) `maxval`.
 *  The function returns -1 if there are more than `maxval` results.
 */

/***************************** MITM problem ***********************************/

/* f : {0, 1}^n --> {0, 1}^n.  Speck64-128 encryption of P[0], using k */
u64 f(u64 k)
{
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);
    u32 Ct[2];
    Speck64128Encrypt(P[0], Ct, rk);
    return ((u64)Ct[0] ^ ((u64)Ct[1] << 32)) & mask;
}

/* g : {0, 1}^n --> {0, 1}^n.  speck64-128 decryption of C[0], using k */
u64 g(u64 k)
{
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);
    u32 Pt[2];
    Speck64128Decrypt(Pt, C[0], rk);
    return ((u64)Pt[0] ^ ((u64)Pt[1] << 32)) & mask;
}

bool is_good_pair(u64 k1, u64 k2)
{
    u32 Ka[4] = {k1 & 0xffffffff, k1 >> 32, 0, 0};
    u32 Kb[4] = {k2 & 0xffffffff, k2 >> 32, 0, 0};
    u32 rka[27];
    u32 rkb[27];
    Speck64128KeySchedule(Ka, rka);
    Speck64128KeySchedule(Kb, rkb);
    u32 mid[2];
    u32 Ct[2];
    Speck64128Encrypt(P[1], mid, rka);
    Speck64128Encrypt(mid, Ct, rkb);
    return (Ct[0] == C[1][0]) && (Ct[1] == C[1][1]);
}

/******************************************************************************/

void fill(u64 rank, u64 newN,struct entry **A)
{
    dict_setup(1.125*newN,A);
    #pragma omp parallel for
    for (u64 x = rank * newN; x < (rank + 1) * newN; x++)
    {
        u64 z = f(x);
        dict_insert(z, x, *A);
    }
}

void seek(u64 key, u64 value, u64 res[2],struct entry *A, int rank)
{

    res[0] = 0; // Aucun résultat trouvé
    res[1] = 0;
    u32 K = key % PRIME;               // Clé modulo la taille du hash
    u64 h = murmur64(key) % dict_size; // Calcul du hachage initial
    
    for (u64 i = 0; i < dict_size; i++)
    { // Parcours limité à la taille de la table
        if (A[h].k == EMPTY)
        {
            break;
        } // Si une entrée vide est rencontrée, arrêt

        if (A[h].k == K) // A[h]
        {
            // Si les clés correspondent
            u64 v = A[h].v; // A[h]
            bool result=is_good_pair(v,value);
            if (result)
            { // Vérification de la condition

                res[0] = value; // value;
                res[1] = v;     // v;
                printf("\nsolution found: (%" PRIx64 ", %" PRIx64 ") for process in s",res[1],res[0]);
                break;

            }
        }
        h = (h + 1) % dict_size; // Passer à la prochaine entrée (probing linéaire)
    }

}

/************************** command-line options ****************************/

void usage(char **argv)
{
    printf("%s [OPTIONS]\n\n", argv[0]);
    printf("Options:\n");
    printf("--n N                       block size [default 24]\n");
    printf("--C0 N                      1st ciphertext (in hex)\n");
    printf("--C1 N                      2nd ciphertext (in hex)\n");
    printf("\n");
    printf("All arguments are required\n");
    exit(0);
}

void process_command_line_options(int argc, char **argv)
{
    struct option longopts[4] = {
        {"n", required_argument, NULL, 'n'},
        {"C0", required_argument, NULL, '0'},
        {"C1", required_argument, NULL, '1'},
        {NULL, 0, NULL, 0}};
    char ch;
    int set = 0;
    while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1)
    {
        switch (ch)
        {
        case 'n':
            n = atoi(optarg);
            mask = (1ull << n) - 1;
            break;
        case '0':
            set |= 1;
            u64 c0 = strtoull(optarg, NULL, 16);
            C[0][0] = c0 & 0xffffffff;
            C[0][1] = c0 >> 32;
            break;
        case '1':
            set |= 2;
            u64 c1 = strtoull(optarg, NULL, 16);
            C[1][0] = c1 & 0xffffffff;
            C[1][1] = c1 >> 32;
            break;
        default:
            errx(1, "Unknown option\n");
        }
    }
    if (n == 0 || set != 3)
    {
        usage(argv);
        exit(1);
    }
}

/******************************************************************************/

int main(int argc, char **argv)
{

    process_command_line_options(argc, argv);
    printf("Running with n=%d, C0=(%08x, %08x) and C1=(%08x, %08x)\n",
           (int)n, C[0][0], C[0][1], C[1][0], C[1][1]);

    int cores;
    int rank;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &cores);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    u64 *potential_solutions;

    u64 N = 1ull << n; // This is 2^n
    u64 localN =N / cores;
    struct entry *A=NULL; /* the hash table */

    fill(rank, localN,&A);


    // This solutions array is 2*cores because each core will generate a tuple (2 items) consisting of g[y],y
    potential_solutions = malloc(2*n * sizeof(u64) * cores);
    u64 y[2*n];
    u64 res[2]={0,0};
    int solved=0;

    u64 limitloop =1.125* localN;
    // This part is to loop over the already filled dictionnary by f(x),x
    double start_search=wtime();

    for (int x = 0; x < limitloop-n; x+=n)
    {

        for (int i=0;i<2*n;i+=2){
        int q=x+(i/2);

        if (A[q].k!=EMPTY && q<limitloop){
            y[i] = g(A[q].v);
            y[i+1] = A[q].v;
        }

        else {
            y[i] = 0;
            y[i+1] = 1;
        }
        }

        MPI_Allgather(&y, 2*n, MPI_UINT64_T, potential_solutions,2*n , MPI_UINT64_T, MPI_COMM_WORLD);

        for (int j=0;j < 2 * n * cores;j+=2)
        {

            if (potential_solutions[j]!=0) {
                seek(potential_solutions[j], potential_solutions[j + 1], res, A, rank);
                if (res[0]!=0 || res[1]!=0) {solved=1; break;}
                }
        }

        MPI_Allreduce(&solved,&solved,1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);
        if (solved>0) {break;}
    }
    double end_search = wtime();
    if (res[0]!=0 || res[1]!=0) printf("\nsolution found: (%" PRIx64 ", %" PRIx64 ") for %d process in %f s",res[1],res[0],cores,end_search-start_search);

    free(A);
    MPI_Finalize();
}
