#include <iostream>
#include <cstring>
#include <unistd.h>

//  Common C++ header files
#include <Vole.h>

int main(int argc, char *argv[]){

    /*-------------------------- VOLE-in-SGX Protocol ------------------------

            --generate RSA-key for Receiver-TEE

            --Socket Transfer with Sender-TEE (send pk)

            --share random seed 

            --generate A/B/C/Delta

            --keep A/C only
    --------------------------------------------------------------------------*/
 
    std::cout << "-------------------------------------------------------" << endl;
    std::cout << "Interact with TEE ..." << endl;

    /*----------- Parse arguments -----------*/

    std::cout << "---[In SGX] Parse parameters ";
    Timer parseBegin = std::chrono::system_clock::now();

    //  check if parameters are enough
    if (argc < 5) {
        std::cout << "---[In SGX] ---[Error] Parameters missing in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    
    unsigned char *share_buf_A_ptr = (unsigned char *) strtoul(argv[1], NULL, 10);     //  shared_buff_ptr
    unsigned char *share_buf_C_ptr = (unsigned char *) strtoul(argv[3], NULL, 10);     //  shared_buff_ptr
    size_t share_buf_A_size = (size_t) strtoul(argv[2], NULL, 10);                     //  shared_buff_size
    size_t share_buf_C_size = (size_t) strtoul(argv[4], NULL, 10);                     //  shared_buff_size

   

    //  check if parameters are valid
    if (share_buf_A_ptr == NULL || share_buf_A_size == 0 || share_buf_C_ptr == NULL || share_buf_C_size == 0){ 
        std::cout << "---[In SGX] ---[Error] Parameters invalid in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    
    Timer parseEnd = std::chrono::system_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(parseEnd - parseBegin).count() << "ms" << std::endl;
    


    /*----------- Generate Key -----------*/

    std::cout << "---[In SGX] Generate RSA-key for Receiver ";
    Timer generatepkBegin = std::chrono::system_clock::now();

    RSA *receiver_rsa = RSA_new();
    BIGNUM *receiver_bne = BN_new();
    BN_set_word(receiver_bne, RSA_PBULIC_EXPONENT);
    RSA_generate_key_ex(receiver_rsa, RSA_KEY_BIT_LENGTH, receiver_bne, NULL);
    
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

    RSA *receiver_pk = RSAPublicKey_dup(receiver_rsa);
    RSA *receiver_sk = RSAPrivateKey_dup(receiver_rsa);

    Timer generatepkEnd = std::chrono::system_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(generatepkEnd - generatepkBegin).count() << "ms" << std::endl;


    /*----------- Socket Transfer -----------*/

    Timer socketBegin = std::chrono::system_clock::now();
    Timer connectBegin = std::chrono::system_clock::now();
    std::cout << "---[In SGX] Socket Transfering ..." << endl;

    //  create socket
    int receiver_sockfd;
    if( (receiver_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        std::cout << "---[In SGX] ---[Error] Create socket failed." << endl;
        return -1;
    }
    else std::cout << "---[In SGX] --- Create socket" << endl;

    //  bind receiver's port & addr to socket
    struct sockaddr_in receiver_addr;
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(SOCKET_PORT);                //  Receiver Port
    receiver_addr.sin_addr.s_addr = inet_addr(SOCKET_ADDR);     //  Receiver IP

    if( bind(receiver_sockfd, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) != 0 )
    {
        std::cout << "---[In SGX] ---[Error] Bind socket failed." << endl;
        return -1;
    }
    else std::cout << "---[In SGX] --- Bind socket" << endl;

    //  listen: transfer this default-"sender-like" socket to a "listener-like" socket
    if( listen(receiver_sockfd, DEFAULT_RECEIVER_BACKLOG) != 0 )
    {
        std::cout << "---[In SGX] ---[Error] Listen failed." << endl;
        close(receiver_sockfd);
        return -1;
    }
    else std::cout << "---[In SGX] --- Listen" << endl;


    //  wating for the connection from the Sender

    socklen_t socklen=sizeof(struct sockaddr_in);
    struct sockaddr_in sender_addr;
    int sender_sockfd = accept(receiver_sockfd, (struct sockaddr*)&sender_addr, (socklen_t *)&socklen);
    if(sender_sockfd < 0) std::cout << "---[In SGX] ---[Error] Connect from Sender failed." << endl;
    else std::cout << "---[In SGX] --- Connect from Sender " << inet_ntoa(sender_addr.sin_addr) <<  " ";

    Timer connectEnd = std::chrono::system_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(connectEnd - connectBegin).count() << "ms" << std::endl;
    

    /* ---------------------- share RSA-pk -------------------------- */

    //  receive Sender's pk
    BIGNUM *sender_n = BN_new();
    BIGNUM *sender_e = BN_new();
    char char_buff_sender_n[RSA_BN_BUFF_SIZE];
    char char_buff_sender_e[RSA_BN_BUFF_SIZE];
    memset(char_buff_sender_n, 0, sizeof(char_buff_sender_n));
    memset(char_buff_sender_e, 0, sizeof(char_buff_sender_e));

    int iret;
    //  receive n 
    if ( (iret = recv(sender_sockfd, char_buff_sender_n, sizeof(char_buff_sender_n), 0)) <= 0 ) // receive n from Sender
    { 
        std::cout << "---[In SGX] ---[Error] Receive Sender-pk(n) failed." << endl;
        return -1;
    }
    BN_hex2bn(&sender_n, char_buff_sender_n);
    
    //  receive e 
    if ( (iret = recv(sender_sockfd, char_buff_sender_e, sizeof(char_buff_sender_e), 0)) <= 0 ) // receive e from Sender
    { 
        std::cout << "---[In SGX] ---[Error] Receive Sender-pk(e) failed." << endl;
        return -1;
    }
    BN_hex2bn(&sender_e, char_buff_sender_e);


    //  re-construct sender_pk from n&e
    RSA *sender_pk = RSA_new();
    RSA_set0_key(sender_pk, BN_dup(sender_n), BN_dup(sender_e), NULL); //  must set NULL here for pk
    



    //  send Receiver's pk
    const BIGNUM *receiver_n, *receiver_e;
    RSA_get0_key(receiver_pk, &receiver_n, &receiver_e, NULL);


    char *big_n = BN_bn2hex(receiver_n);     
    char *big_e = BN_bn2hex(receiver_e);

    //  send char_n & char_e to Receiver
    //  send n 
    if ( (iret = send(sender_sockfd, big_n, strlen(big_n), 0)) <= 0 ) // send n to receiver
    { 
        std::cout << "---[In SGX] ---[Error] Send Receiver-pk(n) failed." << endl;
        return -1;
    }
    
    //  send e 
    if ( (iret = send(sender_sockfd, big_e, strlen(big_e), 0)) <= 0 ) // send e to receiver
    { 
        std::cout << "---[In SGX] ---[Error] Send Receiver-pk(e) failed." << endl;
        return -1;
    }

    std::cout << "---[In SGX] --- Share RSA-pk" << endl;


   

    /* ---------------------- share random seed -------------------------- */

    //  random seed for Receiver
    unsigned char random_seed_receiver[RANDOM_SEED_LENGTH];
    RAND_bytes(random_seed_receiver, sizeof(random_seed_receiver));

    //  encrypt random seed for Receiver, and send it to Sender
    unsigned char *random_seed_receiver_cipher = (unsigned char *)malloc(RSA_size(sender_pk));
    RSA_public_encrypt(RANDOM_SEED_LENGTH, random_seed_receiver, random_seed_receiver_cipher, sender_pk, RSA_PKCS1_PADDING);

    //  receive random seed for Sender, and decrypt it
    unsigned char *random_seed_sender_cipher_buffer = (unsigned char *)malloc(RSA_size(receiver_pk));



    //  send random_seed_receiver_cipher to Sender
    if ( (iret = send(sender_sockfd, random_seed_receiver_cipher, RSA_size(sender_pk), 0)) <= 0 ) // send random_seed_receiver_cipher to Sender
    { 
        std::cout << "---[In SGX] ---[Error] Send random_seed_receiver_cipher failed." << endl;
        return -1;
    }

    //  receive random_seed_sender_cipher from Sender
    if ( (iret = recv(sender_sockfd, random_seed_sender_cipher_buffer, RSA_size(receiver_pk), 0)) <= 0 ) // receive random_seed_sender_cipher from Sender
    { 
        std::cout << "---[In SGX] ---[Error] Receive random_seed_sender_cipher failed." << endl;
        return -1;
    }

    //  decrypt random_seed_sender_cipher with receiver_sk
    unsigned char random_seed_sender[RANDOM_SEED_LENGTH];
    RSA_private_decrypt(RSA_size(receiver_pk), random_seed_sender_cipher_buffer, random_seed_sender, receiver_sk, RSA_PKCS1_PADDING);


    //  re-compute random seed
    unsigned int *random_seed_sender_ptr = (unsigned int *)random_seed_sender;
    unsigned int *random_seed_receiver_ptr = (unsigned int *)random_seed_receiver;
    unsigned int radom_seed = *random_seed_sender_ptr ^ *random_seed_receiver_ptr;


    std::cout << "---[In SGX] --- Share random seeds" << endl;
    Timer socketEnd = std::chrono::system_clock::now();
    std::cout << "---[In SGX] Socket Transfering done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(socketEnd - socketBegin).count() << "ms" << std::endl;


    /*----------- Generate A/B/C/Δ -----------*/
    
    /*          C = A*Delta + B

            A       field B     -> receiver
            C       field F     -> receiver
            B       field F     -> sender
            Δ       field B     -> sender
    */


    std::cout << "---[In SGX] Generate A/B/C/Delta ";
    Timer generateBegin = std::chrono::system_clock::now();

    //  buffer parameters
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
        memcpy((unsigned char*)(randC + (int)(i*bytes_count_C)), tmpC2store, bytes_count_C);
        BN_CTX_free (ctx);
    }

    Timer generateEnd = std::chrono::system_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(generateEnd - generateBegin).count() << "ms" << std::endl;
    

    //  copy A/C to share buffer
    memcpy(share_buf_A_ptr, randA, bytes_count_A_total);
    memcpy(share_buf_C_ptr, randC, bytes_count_C_total);


    //  close socket
    close(receiver_sockfd);
    close(sender_sockfd);

    
    /*----------- Done -----------*/

    return EXIT_SUCCESS;

}