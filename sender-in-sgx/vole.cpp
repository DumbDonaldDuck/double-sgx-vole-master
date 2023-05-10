#include <iostream>
#include <vector>
#include <ctime>
#include <cmath>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>

//  Common C++ header files
#include <Vole.h>





int main(int argc, char *argv[]){

    /*-------------------------- VOLE-in-SGX Protocol ------------------------

            --generate RSA-key for Sender-TEE

            --Socket Transfer with Receiver-TEE (send pk)

            --share random seed 

            --generate A/B/C/Delta

            --keep B/Delta only
    --------------------------------------------------------------------------*/
 
    // Timer sgxBegin = std::chrono::system_clock::now();

    std::cout << "--------------------------------------------------" << endl;
    std::cout << "Interact with TEE ..." << endl;

    /*----------- Parse arguments -----------*/

    std::cout << "---[In SGX] Parse parameters ";
    Timer parseBegin = std::chrono::system_clock::now();

    //  check if parameters are enough
    if (argc < 5) {
        std::cout << "---[In SGX] ---[Error] Parameters missing in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    
    unsigned char *share_buf_B_ptr     = (unsigned char *) strtoul(argv[1], NULL, 10);     //  shared_buff_ptr
    unsigned char *share_buf_Delta_ptr = (unsigned char *) strtoul(argv[3], NULL, 10);     //  shared_buff_ptr
    size_t share_buf_B_size     = (size_t) strtoul(argv[2], NULL, 10);                     //  shared_buff_size
    size_t share_buf_Delta_size = (size_t) strtoul(argv[4], NULL, 10);                     //  shared_buff_size

   

    //  check if parameters are valid
    if (share_buf_B_ptr == NULL || share_buf_B_size == 0 || share_buf_Delta_ptr == NULL || share_buf_Delta_size == 0){ 
        std::cout << "---[In SGX] ---[Error] Parameters invalid in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    
    Timer parseEnd = std::chrono::system_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(parseEnd - parseBegin).count() << "ms" << std::endl;
    


    /*----------- Generate Key -----------*/

    std::cout << "---[In SGX] Generate RSA-key for Sender ";
    Timer generatepkBegin = std::chrono::system_clock::now();

    RSA *sender_rsa = RSA_new();
    BIGNUM *sender_bne = BN_new();
    BN_set_word(sender_bne, RSA_PBULIC_EXPONENT);
    RSA_generate_key_ex(sender_rsa, RSA_KEY_BIT_LENGTH, sender_bne, NULL);
    
    // RSAPrivateKey ::= SEQUENCE {
    //     version           Version,
    //     modulus           INTEGER,  -- n
    //     publicExponent    INTEGER,  -- e
    //     privateExponent   INTEGER,  -- d
    //     prime1            INTEGER,  -- p
    //     prime2            INTEGER,  -- q
    //     exponent1         INTEGER,  -- d mod (p-1)
    //     exponent2         INTEGER,  -- d mod (q-1)
    //     coefficient       INTEGER,  -- (inverse of q) mod p
    //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
    // }

    //  encrypt: rsa or pk could both be used
    //  decrypt: rsa or sk could both be used

    RSA *sender_pk = RSAPublicKey_dup(sender_rsa);
    RSA *sender_sk = RSAPrivateKey_dup(sender_rsa);

    Timer generatepkEnd = std::chrono::system_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(generatepkEnd - generatepkBegin).count() << "ms" << std::endl;



    /*----------- Socket Transfer -----------*/

    Timer socketBegin = std::chrono::system_clock::now();
    std::cout << "---[In SGX] Socket Transfering ..." << endl;

    //  create socket
    int sender_sockfd;
    if( (sender_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        std::cout << "---[In SGX] ---[Error] Create socket failed." << endl;
        return -1;
    }
    else std::cout << "---[In SGX] --- Create socket" << endl;

    
    //  connect to receiver
    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port = htons(SOCKET_PORT);              //  Sender Port
    sender_addr.sin_addr.s_addr=inet_addr(SOCKET_ADDR);     //  Sender IP
    if ( connect(sender_sockfd, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) != 0 ) // Connect Request to Receiver
    { 
        std::cout << "---[In SGX] ---[Error] Connect to Receiver failed." << endl;
        close(sender_sockfd); 
        return -1; 
    }
    else std::cout << "---[In SGX] --- Connect to Receiver" << endl;



    //  send Sender's pk

    // Timer sendpkBegin = std::chrono::system_clock::now();

    const BIGNUM *sender_n, *sender_e;
    RSA_get0_key(sender_pk, &sender_n, &sender_e, NULL);


    char *big_n = BN_bn2hex(sender_n);     
    char *big_e = BN_bn2hex(sender_e);

    //  send char_n & char_e to Receiver
    int iret;

    //  send n 
    if ( (iret = send(sender_sockfd, big_n, strlen(big_n), 0)) <= 0 ) // send n to server
    { 
        std::cout << "---[In SGX] ---[Error] Send Sender-pk(n) failed." << endl;
        return -1;
    }
    // else std::cout << "---[In SGX] ---Send Sender-pk(n)" << endl;
    

    //  send e 
    if ( (iret = send(sender_sockfd, big_e, strlen(big_e), 0)) <= 0 ) // send e to server
    { 
        std::cout << "---[In SGX] ---[Error] Send Sender-pk(e) failed." << endl;
        return -1;
    }
    // else std::cout << "---[In SGX] ---Send Sender-pk(e)" << endl;
    

    // Timer sendpkEnd = std::chrono::system_clock::now();
    // std::cout << "---[In SGX] Socket Transfer done ";
    // std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(sendpkEnd - sendpkBegin).count() << "ms" << std::endl;
    
    // std::cout << "--------------------------------------------------" << endl;



    //  receive Receiver's pk

    // Timer receivepkBegin = std::chrono::system_clock::now();


    BIGNUM *receiver_n = BN_new();
    BIGNUM *receiver_e = BN_new();
    char char_buff_receiver_n[RSA_BN_BUFF_SIZE];
    char char_buff_receiver_e[RSA_BN_BUFF_SIZE];
    memset(char_buff_receiver_n, 0, sizeof(char_buff_receiver_n));
    memset(char_buff_receiver_e, 0, sizeof(char_buff_receiver_e));

    //  receive n 
    if ( (iret = recv(sender_sockfd, char_buff_receiver_n, sizeof(char_buff_receiver_n), 0)) <= 0 ) // receive n from receiver
    { 
        std::cout << "---[In SGX] ---[Error] Receive Receiver-pk(n) failed." << endl;
        return -1;
    }
    // else std::cout << "---[In SGX] ---Receive Receiver-pk(n) " << endl;
    BN_hex2bn(&receiver_n, char_buff_receiver_n);
    

    //  receive e 
    if ( (iret = recv(sender_sockfd, char_buff_receiver_e, sizeof(char_buff_receiver_e), 0)) <= 0 ) // receive e from receiver
    { 
        std::cout << "---[In SGX] ---[Error] Receive Receiver-pk(e) failed." << endl;
        return -1;
    }
    // else std::cout << "---[In SGX] ---Receive Receiver-pk(e)" << endl;
    BN_hex2bn(&receiver_e, char_buff_receiver_e);


    //  re-construct sender_pk from n&e
    RSA *receiver_pk = RSA_new();
    RSA_set0_key(receiver_pk, BN_dup(receiver_n), BN_dup(receiver_e), NULL); //  must set NULL here for pk
    
    // std::cout << "--------------------------------------------------" << endl;

    // Timer receivepkEnd = std::chrono::system_clock::now();
    // std::cout << "---[In SGX] Socket Transfering done ";
    // std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(receivepkEnd - receivepkBegin).count() << "ms" << std::endl;
    

    std::cout << "---[In SGX] --- Share RSA-pk" << endl;




    // RSA_print_fp(stdout, receiver_pk, 0);
    // RSA_print_fp(stdout, sender_pk, 0);

    /* ---------------------- share random seed -------------------------- */


    unsigned char random_seed_sender[RANDOM_SEED_LENGTH];
    RAND_bytes(random_seed_sender, sizeof(random_seed_sender));




    // srand(time(NULL));

    unsigned char *random_seed_sender_cipher = (unsigned char *)malloc(RSA_size(sender_pk));
    RSA_public_encrypt(RANDOM_SEED_LENGTH, random_seed_sender, random_seed_sender_cipher, receiver_pk, RSA_PKCS1_PADDING);


    unsigned char *random_seed_receiver_cipher_buffer = (unsigned char *)malloc(RSA_size(sender_pk));


    //  receive random_seed_receiver_cipher from Receiver
    if ( (iret = recv(sender_sockfd, random_seed_receiver_cipher_buffer, RSA_size(sender_pk), 0)) <= 0 ) // receive random_seed_receiver_cipher from receiver
    { 
        std::cout << "---[In SGX] ---[Error] Receive random_seed_receiver_cipher failed." << endl;
        return -1;
    }
    // else std::cout << "---[In SGX] ---Receive random_seed_receiver_cipher" << endl;

    //  send random_seed_sender_cipher to Receiver
    if ( (iret = send(sender_sockfd, random_seed_sender_cipher, RSA_size(sender_pk), 0)) <= 0 ) // send random_seed_sender_cipher to receiver
    { 
        std::cout << "---[In SGX] ---[Error] Send random_seed_sender_cipher failed." << endl;
        return -1;
    }
    // else std::cout << "---[In SGX] ---Send random_seed_sender_cipher" << endl;

    //  decrypt random_seed_receiver_cipher with sender_sk
    unsigned char random_seed_receiver[RANDOM_SEED_LENGTH];
    RSA_private_decrypt(RSA_size(sender_pk), random_seed_receiver_cipher_buffer, random_seed_receiver, sender_sk, RSA_PKCS1_PADDING);



    unsigned int *random_seed_sender_ptr = (unsigned int *)random_seed_sender;
    unsigned int *random_seed_receiver_ptr = (unsigned int *)random_seed_receiver;
    // std::cout << "---[In SGX] Random seed: " << *random_seed_sender_ptr << endl;
    // std::cout << "---[In SGX] Random seed: " << *random_seed_receiver_ptr << endl;

    unsigned int radom_seed = *random_seed_sender_ptr ^ *random_seed_receiver_ptr;
    // std::cout << "---[In SGX] Random seed: " << radom_seed << endl;


    std::cout << "---[In SGX] --- Share random seeds" << endl;
    Timer socketEnd = std::chrono::system_clock::now();
    std::cout << "---[In SGX] Socket Transfering done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(socketEnd - socketBegin).count() << "ms" << std::endl;


   /*----------- Generate A/B/C/Δ -----------*/
    /*
            each element in field_B/F:  128 bit <==> 16 Byte
            
            for security, padding 11Bytes
            
            2048-bit key  ==>  256 Bytes  ==>  245 Bytes available
            
            every 240 Bytes(15 elements)
            
            (3m+1) elements
            (3m+1) / 15  *256 Bytes total needed (about 70MB)


    //  type for paras
            RSA                 unsigned char* -> unsigned char*
            random generator    unsigned char*(RAND_bytes)
            BIGNUM memory   

            A       field B     -> receiver
            C       field F     -> receiver
            B       field F     -> sender
            Δ       field B     -> sender

    */


    std::cout << "---[In SGX] Generate A/B/C/Delta ";
    Timer generateBegin = std::chrono::system_clock::now();


    
    int bytes_count_A     = FIELD_B_BYTE;
    int bytes_count_B     = FIELD_F_BYTE;
    int bytes_count_C     = FIELD_F_BYTE;    
    int bytes_count_Delta = FIELD_B_BYTE;

    int bytes_count_A_total     = SIZE_M * bytes_count_A;
    int bytes_count_B_total     = SIZE_M * bytes_count_B;
    int bytes_count_C_total     = SIZE_M * bytes_count_C;
    int bytes_count_Delta_total = bytes_count_Delta;


    unsigned char *randA     = (unsigned char *)malloc(bytes_count_A_total);
    unsigned char *randB     = (unsigned char *)malloc(bytes_count_B_total);
    unsigned char *randC     = (unsigned char *)malloc(bytes_count_C_total);
    unsigned char *randDelta = (unsigned char *)malloc(bytes_count_Delta_total);



    int REAL_RAND_BYTE_COUNT_PER_RAND_INT = 2;
    srand(radom_seed);

    //  generate A

    for(int i = 0; i< bytes_count_A_total; i += REAL_RAND_BYTE_COUNT_PER_RAND_INT){
        unsigned int rand_int = rand();
        memcpy(randA + i, &rand_int, REAL_RAND_BYTE_COUNT_PER_RAND_INT);
    }

    //  generate B
    for(int i = 0; i< bytes_count_B_total; i += REAL_RAND_BYTE_COUNT_PER_RAND_INT){
        unsigned int rand_int = rand();
        memcpy(randB + i, &rand_int, REAL_RAND_BYTE_COUNT_PER_RAND_INT);
    }

    //  generate Delta
    for(int i = 0; i< bytes_count_Delta_total; i += REAL_RAND_BYTE_COUNT_PER_RAND_INT){
        unsigned int rand_int = rand();
        memcpy(randDelta + i, &rand_int, REAL_RAND_BYTE_COUNT_PER_RAND_INT);
    }



    BIGNUM *Delta = BN_new();
    Delta = BN_bin2bn(randDelta, bytes_count_Delta, NULL);


    //  generate C
    BIGNUM *tmpA = BN_new();
    BIGNUM *tmpB = BN_new();
    BIGNUM *tmpC = BN_new();
    unsigned char tmpC2store[bytes_count_C + 1];
    for (int i = 0; i< SIZE_M; i++){
        tmpA = BN_bin2bn((unsigned char*)(randA + (int)(i*bytes_count_A)), bytes_count_A, NULL);   
        tmpB = BN_bin2bn((unsigned char*)(randB + (int)(i*bytes_count_B)), bytes_count_B, NULL);    
        BN_CTX *ctx = BN_CTX_new();
        BN_mul(tmpC, tmpA, Delta, ctx);
        BN_add(tmpC, tmpC, tmpB);
        BN_bn2bin(tmpC, tmpC2store);
        // std::cout << "generate res:" << res << " i = " << i <<  endl;
        memcpy((unsigned char*)(randC + (int)(i*bytes_count_C)), tmpC2store, bytes_count_C);
        BN_CTX_free (ctx);
    }

    Timer generateEnd = std::chrono::system_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(generateEnd - generateBegin).count() << "ms" << std::endl;



    memcpy(share_buf_B_ptr, randB, bytes_count_B_total);
    memcpy(share_buf_Delta_ptr, randDelta, bytes_count_Delta_total);


    // for(int i=0; i< 100; i++){
    //     printf("%02x ", randC[i]);
    // }
    // printf("\n");


    //  close socket
    close(sender_sockfd);

    return EXIT_SUCCESS;

}