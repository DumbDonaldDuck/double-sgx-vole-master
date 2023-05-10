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
 
    Timer sgxBegin = std::chrono::system_clock::now();

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

    std::cout << "---[In SGX] Generate RSA-key for Receiver ";
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
    std::cout << "--------------------------------------------------" << endl;



    /*----------- Socket Transfer -----------*/

    Timer connectBegin = std::chrono::system_clock::now();
    std::cout << "Socket Transfering ..." << endl;

    //  create socket
    int sender_sockfd;
    if( (sender_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        std::cout << "---[Error] Create socket failed." << endl;
        return -1;
    }
    else std::cout << "---Create socket" << endl;

    
    //  connect to receiver
    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port = htons(SOCKET_PORT);              //  Sender Port
    sender_addr.sin_addr.s_addr=inet_addr(SOCKET_ADDR);     //  Sender IP
    if ( connect(sender_sockfd, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) != 0 ) // Connect Request to Receiver
    { 
        std::cout << "---[Error] Connect to Receiver failed." << endl;
        close(sender_sockfd); 
        return -1; 
    }
    else std::cout << "---Connect to Receiver" << endl;






    //  send Sender's pk

    Timer sendpkBegin = std::chrono::system_clock::now();

    const BIGNUM *n, *e;
    RSA_get0_key(sender_pk, &n, &e, NULL);


    char *big_n = BN_bn2hex(n);     // big_n 是一块私有空间，不允许直接访问？
    char *big_e = BN_bn2hex(e);

    //  send char_n & char_e to Receiver
    int iret;


    //  send n 
    if ( (iret = send(sender_sockfd, big_n, strlen(big_n), 0)) <= 0 ) // send n to server
    { 
        std::cout << "---[Error] Send Sender-pk(n) failed." << endl;
        return -1;
    }
    else std::cout << "---Send Sender-pk(n)" << endl;
    

    //  send e 
    if ( (iret = send(sender_sockfd, big_e, strlen(big_e), 0)) <= 0 ) // send e to server
    { 
        std::cout << "---[Error] Send Sender-pk(e) failed." << endl;
        return -1;
    }
    else std::cout << "---Send Sender-pk(e)" << endl;
    

    Timer sendpkEnd = std::chrono::system_clock::now();
    std::cout << "Socket Transfer done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(sendpkEnd - sendpkBegin).count() << "ms" << std::endl;
    

    std::cout << "--------------------------------------------------" << endl;



    //  receive Receiver's pk

    Timer receivepkBegin = std::chrono::system_clock::now();

    // int iret;

    //  re-construct n&e from the recv-buffer
        //  we have char_buff_n & char_buff_e sequencial in the memory
        //  so the strlen(char_buff_n) will count (char_buff_e) in
        //  so once receive, consturct BIGNUM


    BIGNUM *receiver_n = BN_new();
    BIGNUM *receiver_e = BN_new();
    char char_buff_receiver_n[RSA_BN_BUFF_SIZE];
    char char_buff_receiver_e[RSA_BN_BUFF_SIZE];
    memset(char_buff_receiver_n, 0, sizeof(char_buff_receiver_n));
    memset(char_buff_receiver_e, 0, sizeof(char_buff_receiver_e));

    //  receive n 
    if ( (iret = recv(sender_sockfd, char_buff_receiver_n, sizeof(char_buff_receiver_n), 0)) <= 0 ) // receive n from Sender
    { 
        std::cout << "---[Error] Receive Sender-pk(n) failed." << endl;
        return -1;
    }
    else std::cout << "---Receive Sender-pk(n) " << endl;
    BN_hex2bn(&receiver_n, char_buff_receiver_n);
    

    //  receive e 
    if ( (iret = recv(sender_sockfd, char_buff_receiver_e, sizeof(char_buff_receiver_e), 0)) <= 0 ) // receive e from Sender
    { 
        std::cout << "---[Error] Receive Sender-pk(e) failed." << endl;
        return -1;
    }
    else std::cout << "---Receive Sender-pk(e)" << endl;
    BN_hex2bn(&receiver_e, char_buff_receiver_e);


    //  re-construct sender_pk from n&e
    RSA *receiver_pk = RSA_new();
    RSA_set0_key(sender_pk, BN_dup(receiver_n), BN_dup(receiver_e), NULL); //  must set NULL here for pk
    
    std::cout << "--------------------------------------------------" << endl;

    Timer receivepkEnd = std::chrono::system_clock::now();
    std::cout << "Socket Transfering done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(receivepkEnd - receivepkBegin).count() << "ms" << std::endl;
    





    RSA_print_fp(stdout, receiver_pk, 0);
    RSA_print_fp(stdout, sender_pk, 0);



    //  close socket
    close(sender_sockfd);

    return EXIT_SUCCESS;








}






















































// int main(int argc, char *argv[]){

//     /*-------------------------- VOLE-in-SGX Protocol ------------------------

//             Parse arguments (m, F, B, pk, pk', shared_buff_ptr, shared_buff_size)
            
//             Generate A/B/C/Δ
                
//             Encryption    
            
//             Store the result in shared memory
//     --------------------------------------------------------------------------*/
 
//     Timer sgxBegin = std::chrono::system_clock::now();

//     std::cout << "--------------------------------------------------" << endl;
//     std::cout << "Interact with TEE ..." << endl;

//     /*----------- Parse arguments -----------*/

//     std::cout << "---[In SGX] Parse parameters ";
//     Timer parseBegin = std::chrono::system_clock::now();

//     //  check if parameters are enough
//     if (argc < 14) {
//         std::cout << "---[In SGX] ---[Error] Parameters missing in VOLE Generation" << endl;
//         return EXIT_FAILURE;
//     }
//                                                                         //  str->unsigned long
//     int OVERALL_PROTOCOL_MODE = (int) strtoul(argv[1], NULL, 10);       //  MODE 0/1/2/3, unsigned long
//     int field_B  = (int) strtoul(argv[2], NULL, 10);                    //  B, unsigned long  
//     int field_F  = (int) strtoul(argv[3], NULL, 10);                    //  F, unsigned long  
//     int size_m   = (int) strtoul(argv[4], NULL, 10);                    //  m, unsigned long
//     RSA* sender_pk  = (RSA *) strtoul(argv[5], NULL, 10);               //  pk'

//     unsigned char *share_buf_B_ptr = (unsigned char *) strtoul(argv[6], NULL, 10);      //  shared_buff_ptr
//     size_t share_buf_B_size = (size_t) strtoul(argv[7], NULL, 10);                      //  shared_buff_size
//     unsigned char *share_buf_Delta_ptr = (unsigned char *) strtoul(argv[8], NULL, 10);  //  shared_buff_ptr
//     size_t share_buf_Delta_size = (size_t) strtoul(argv[9], NULL, 10);                  //  shared_buff_size

//     unsigned char *share_buf_A_ptr = (unsigned char *) strtoul(argv[10], NULL, 10);     //  shared_buff_ptr
//     size_t share_buf_A_size = (size_t) strtoul(argv[11], NULL, 10);                     //  shared_buff_size
//     unsigned char *share_buf_C_ptr = (unsigned char *) strtoul(argv[12], NULL, 10);     //  shared_buff_ptr
//     size_t share_buf_C_size = (size_t) strtoul(argv[13], NULL, 10);                     //  shared_buff_size

//     int PROTOCOL_MODE = OVERALL_PROTOCOL_MODE % 2;
//     int HYBRID_ENCRYPTION_ON = OVERALL_PROTOCOL_MODE / 2;
//     //      HYBRID_ENCRYPTION_ON    PROTOCOL_MODE
//     //  0       0                          0
//     //  1       0                          1
//     //  2       1                          0
//     //  3       1                          1

//     RSA* receiver_pk;
//     unsigned char *AES_buffer_sender_ptr;
//     unsigned char *AES_buffer_receiver_ptr;
//     size_t AES_buffer_sender_size, AES_buffer_receiver_size;


//     //  PROTOCOL_MODE = 1, MUST need receiver_pk
//     if(PROTOCOL_MODE){

//         receiver_pk = (RSA *) strtoul(argv[14], NULL, 10);                              //  receiver_pk

//         //  A/B/C/Delta need to encrypt, so need AES_buffer_receiver & AES_buffer_sender
//         if(HYBRID_ENCRYPTION_ON){
//             AES_buffer_sender_ptr = (unsigned char *) strtoul(argv[15], NULL, 10);      //  AES_buffer_sender_ptr
//             AES_buffer_sender_size = (size_t) strtoul(argv[16], NULL, 10);              //  AES_buffer_sender_size
//             AES_buffer_receiver_ptr = (unsigned char *) strtoul(argv[17], NULL, 10);    //  AES_buffer_receiver_ptr
//             AES_buffer_receiver_size = (size_t) strtoul(argv[18], NULL, 10);            //  AES_buffer_receiver_size
//         }

//     }

//     //  PROTOCOL_MODE = 0, NO need receiver_pk
//     else{
//         if(HYBRID_ENCRYPTION_ON){
//             AES_buffer_sender_ptr = (unsigned char *) strtoul(argv[14], NULL, 10);      //  AES_buffer_sender_ptr
//             AES_buffer_sender_size = (size_t) strtoul(argv[15], NULL, 10);              //  AES_buffer_sender_size
//         }
//     }
       
//     //  check if parameters are valid
//     if (share_buf_A_ptr == NULL || share_buf_A_size == 0 || share_buf_B_ptr == NULL || share_buf_B_size == 0 || \
//         share_buf_C_ptr == NULL || share_buf_C_size == 0 || share_buf_Delta_ptr == NULL || share_buf_Delta_size == 0 || \
//         field_B == 0 || field_F == 0 || size_m == 0 || sender_pk == NULL || \
//         (PROTOCOL_MODE == 1 &&  receiver_pk == NULL) || \

//         (PROTOCOL_MODE == 1 && HYBRID_ENCRYPTION_ON == 1 && (AES_buffer_sender_ptr == NULL || AES_buffer_sender_size == 0 || \
//                                                             AES_buffer_receiver_ptr == NULL || AES_buffer_receiver_size == 0)) || \

//         (PROTOCOL_MODE == 0 && HYBRID_ENCRYPTION_ON == 1 && (AES_buffer_sender_ptr == NULL || AES_buffer_sender_size == 0)) ){
            
//         std::cout << "---[In SGX] ---[Error] Parameters invalid in VOLE Generation" << endl;
//         return EXIT_FAILURE;
//     }
    
//     Timer parseEnd = std::chrono::system_clock::now();
//     std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(parseEnd - parseBegin).count() << "ms" << std::endl;
    

//     /*----------- Generate A/B/C/Δ -----------*/
//     /*
//             each element in field_B/F:  128 bit <==> 16 Byte
            
//             for security, padding 11Bytes
            
//             2048-bit key  ==>  256 Bytes  ==>  245 Bytes available
            
//             every 240 Bytes(15 elements)
            
//             (3m+1) elements
//             (3m+1) / 15  *256 Bytes total needed (about 70MB)


//     //  type for paras
//             RSA                 unsigned char* -> unsigned char*
//             random generator    unsigned char*(RAND_bytes)
//             BIGNUM memory   

//             A       field B     -> receiver
//             C       field F     -> receiver
//             B       field F     -> sender
//             Δ       field B     -> sender

//     */


//     std::cout << "---[In SGX] Generate A/B/C/Delta ";
//     Timer generateBegin = std::chrono::system_clock::now();

//     int byte_length_field_B = (int)(field_B/8);
//     int byte_length_field_F = (int)(field_F/8);

    
//     int bytes_count_A = byte_length_field_B;
//     int bytes_count_B = byte_length_field_F;
//     int bytes_count_C = byte_length_field_F;    

//     int bytes_count_A_total = size_m * bytes_count_A;
//     int bytes_count_B_total = size_m * bytes_count_B;
//     int bytes_count_C_total = size_m * bytes_count_C;
//     int bytes_count_Delta = byte_length_field_B;


//     unsigned char *randA = (unsigned char *)malloc(bytes_count_A_total);
//     unsigned char *randB = (unsigned char *)malloc(bytes_count_B_total);
//     unsigned char *randC = (unsigned char *)malloc(bytes_count_C_total);
//     unsigned char *randDelta = (unsigned char *)malloc(bytes_count_Delta);

//     int rand_res_1 = RAND_bytes(randA,bytes_count_A_total);
//     int rand_res_2 = RAND_bytes(randB,bytes_count_B_total);
//     int rand_res_3 = RAND_bytes(randDelta,bytes_count_Delta);

//     //  check if random generation success
//     if(rand_res_1 == 0 || rand_res_2 == 0 || rand_res_3 == 0){
//         std::cout << "---[In SGX] ---[Error] Randomness malloc generation failure" << endl;
//         return EXIT_FAILURE;
//     }

//     //  generate Delta
//     BIGNUM *Delta = BN_new();
//     Delta = BN_bin2bn(randDelta, bytes_count_Delta, NULL);


//     //  generate C
//     BIGNUM *tmpA = BN_new();
//     BIGNUM *tmpB = BN_new();
//     BIGNUM *tmpC = BN_new();
//     unsigned char tmpC2store[bytes_count_C + 1];
//     for (int i = 0; i< size_m; i++){
//         tmpA = BN_bin2bn((unsigned char*)(randA + (int)(i*bytes_count_A)), bytes_count_A, NULL);   
//         tmpB = BN_bin2bn((unsigned char*)(randB + (int)(i*bytes_count_B)), bytes_count_B, NULL);    
//         BN_CTX *ctx = BN_CTX_new();
//         BN_mul(tmpC, tmpA, Delta, ctx);
//         BN_add(tmpC, tmpC, tmpB);
//         BN_bn2bin(tmpC, tmpC2store);
//         // std::cout << "generate res:" << res << " i = " << i <<  endl;
//         memcpy((unsigned char*)(randC + (int)(i*bytes_count_C)), tmpC2store, bytes_count_C);
//         BN_CTX_free (ctx);
//     }

//     Timer generateEnd = std::chrono::system_clock::now();
//     std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(generateEnd - generateBegin).count() << "ms" << std::endl;
    
    
    
//     /*----------- Encryption -----------*/
//     if(PROTOCOL_MODE) std::cout << "---[In SGX] Encrypt A/B/C/Delta ..." << endl;
//     else std::cout << "---[In SGX] Encrypt B/Delta ";

//     Timer encryptBDeltaBegin = std::chrono::system_clock::now();


//     int sender_pk_size = RSA_size(sender_pk);       //  count in byte
    
//     //  Encrypt B/Delta
//         //  each cipher text contains (element_B_count_per_cipher) elements B
//         //  plaintext   in  randB/Delta/A/C
//         //  ciphertext  in  buffer_B/Delta(A/C)

    
//     //  sender_pk must be inside the sgx, so we create a new RSA object
//     //  transfer outside rsa-key object into an inside object
//     RSA *sender_pk_inside = RSA_new();
//     const BIGNUM *n, *e;
//     RSA_get0_key(sender_pk, &n, &e, NULL);
//     RSA_set0_key(sender_pk_inside, BN_dup(n), BN_dup(e), NULL);


//     //  HYBRID_ENCRYPTION_ON = 1, need to encrypt AES key
//     if(HYBRID_ENCRYPTION_ON){
//         /*  Hybrid encryption
//                 RSA + AES
//                 RSA:    encrypt AES key
//                 AES:    encrypt data
//                 AES key:   AES_KEY_LENGTH bit
//                 AES data:  A/B/C/Delta
//                 RSA key:   KEY_LENGTH bit
//                 RSA data:  aes key & ivec
//         */
//         //  During the encryption, ivec cahnges, so need to store original ivec  
//         //  AES key could only be used once, so need to use different key for different plaintext

//         //  AES key & ivec generation
//         unsigned char *aes_sender_key_buffer1 = (unsigned char *)malloc(AES_KEY_LENGTH_BYTE);
//         unsigned char *aes_sender_key_buffer2 = (unsigned char *)malloc(AES_KEY_LENGTH_BYTE);
//         unsigned char *aes_sender_ivec1 = (unsigned char *)malloc(AES_IV_LENGTH_BYTE);
//         unsigned char *aes_sender_ivec2 = (unsigned char *)malloc(AES_IV_LENGTH_BYTE);

//         int rand_res_4 = RAND_bytes(aes_sender_key_buffer1,AES_KEY_LENGTH_BYTE);
//         int rand_res_5 = RAND_bytes(aes_sender_key_buffer2,AES_KEY_LENGTH_BYTE);
//         int rand_res_6 = RAND_bytes(aes_sender_ivec1,AES_IV_LENGTH_BYTE);
//         int rand_res_7 = RAND_bytes(aes_sender_ivec2,AES_IV_LENGTH_BYTE);

//         //  check if random generation success
//         if(rand_res_4 == 0 || rand_res_5 == 0 || rand_res_6 == 0 || rand_res_7 == 0) 
//             std::cout << "---[In SGX] ---[Error] AES key generation for Sender failure" << endl;
        
//         //  Encrypt AES key & ivec
//         RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_sender_key_buffer1, (unsigned char*)(AES_buffer_sender_ptr + 0*sender_pk_size), sender_pk_inside, PADDING_MODE);
//         RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_sender_key_buffer2, (unsigned char*)(AES_buffer_sender_ptr + 1*sender_pk_size), sender_pk_inside, PADDING_MODE);
//         RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_sender_ivec1,        (unsigned char*)(AES_buffer_sender_ptr + 2*sender_pk_size), sender_pk_inside, PADDING_MODE);
//         RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_sender_ivec2,        (unsigned char*)(AES_buffer_sender_ptr + 3*sender_pk_size), sender_pk_inside, PADDING_MODE);

//         //  Set AES key
//         AES_KEY sender_aes_encrypt_key1, sender_aes_encrypt_key2;
//         AES_set_encrypt_key(aes_sender_key_buffer1, AES_KEY_LENGTH_BIT, &sender_aes_encrypt_key1);
//         AES_set_encrypt_key(aes_sender_key_buffer2, AES_KEY_LENGTH_BIT, &sender_aes_encrypt_key2);

//         //  Encrypt B
//         AES_cbc_encrypt(randB, share_buf_B_ptr, bytes_count_B_total, &sender_aes_encrypt_key1, aes_sender_ivec1, AES_ENCRYPT);
//         //  Encrypt Delta
//         AES_cbc_encrypt(randDelta, share_buf_Delta_ptr, bytes_count_Delta, &sender_aes_encrypt_key2, aes_sender_ivec2, AES_ENCRYPT);

//     }
//     //  HYBRID_ENCRYPTION_ON = 0, RSA only
//     else{

//         //  Encrypt B
//         int element_B_count_per_cipher = (sender_pk_size   - DEFAULT_PADDING_LENGTH) / bytes_count_B;
//         int cipher_count_B = ceil(size_m *1.0/ element_B_count_per_cipher);

//         int real_element_in_cipher_count_B = element_B_count_per_cipher;
//         int iter;
//         for(iter = 0; iter < cipher_count_B - 1; iter ++){
//             RSA_public_encrypt(real_element_in_cipher_count_B * bytes_count_B, \
//             (unsigned char*)(randB + (iter * bytes_count_B * element_B_count_per_cipher)), \
//             (unsigned char*)(share_buf_B_ptr + (iter * sender_pk_size)) , \
//             sender_pk_inside, PADDING_MODE);
            
//         }
//         real_element_in_cipher_count_B = size_m - iter * element_B_count_per_cipher;
//         RSA_public_encrypt(real_element_in_cipher_count_B, \
//         (const unsigned char*)(randB + (iter * bytes_count_B * element_B_count_per_cipher)), \
//         (unsigned char*)(share_buf_B_ptr + (iter * sender_pk_size)) , \
//         sender_pk_inside, PADDING_MODE);

//         //  Encrypt Delta
//         RSA_public_encrypt(bytes_count_Delta, randDelta, share_buf_Delta_ptr, sender_pk_inside, PADDING_MODE);
//     }
    
    
    
//     Timer encryptBDeltaEnd = std::chrono::system_clock::now();
//     if(PROTOCOL_MODE) std::cout << "---[In SGX] ---Encrypt B/Delta " << std::chrono::duration_cast<std::chrono::milliseconds>(encryptBDeltaEnd - encryptBDeltaBegin).count() << "ms" << std::endl;
//     else     std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(encryptBDeltaEnd - encryptBDeltaBegin).count() << "ms" << std::endl;

    

//     //  Encrypt A/C (Optional)     

//     //  PROTOCOL_MODE = 1, Need to encrypt A/C
//     if(PROTOCOL_MODE){  

//         Timer encryptACBegin = std::chrono::system_clock::now();
//         RSA *receiver_pk_inside = RSA_new();
//         const BIGNUM *n, *e;
//         RSA_get0_key(receiver_pk, &n, &e, NULL);
//         RSA_set0_key(receiver_pk_inside, BN_dup(n), BN_dup(e), NULL);
//         int receiver_pk_size = RSA_size(receiver_pk);   //  count in byte

//         //  HYBRID_ENCRYPTION_ON = 1, AES + RSA
//         if(HYBRID_ENCRYPTION_ON){

//             //  AES key & ivec generation
//             unsigned char aes_receiver_key_buffer1[AES_KEY_LENGTH_BYTE];
//             unsigned char aes_receiver_key_buffer2[AES_KEY_LENGTH_BYTE];
//             unsigned char aes_receiver_ivec1[AES_IV_LENGTH_BYTE];
//             unsigned char aes_receiver_ivec2[AES_IV_LENGTH_BYTE];


//             int rand_res_4 = RAND_bytes(aes_receiver_key_buffer1,AES_KEY_LENGTH_BYTE);
//             int rand_res_5 = RAND_bytes(aes_receiver_key_buffer1,AES_KEY_LENGTH_BYTE);
//             int rand_res_6 = RAND_bytes(aes_receiver_ivec1,AES_IV_LENGTH_BYTE);
//             int rand_res_7 = RAND_bytes(aes_receiver_ivec2,AES_IV_LENGTH_BYTE);

//             //  check if random generation success
//             if(rand_res_4 == 0 || rand_res_5 == 0 || rand_res_6 == 0 || rand_res_7 == 0) 
//                 std::cout << "---[In SGX] ---[Error] AES key generation for Receiver failure" << endl;
            
//             //  Encrypt AES key & ivec
//             RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_receiver_key_buffer1, (unsigned char*)(AES_buffer_receiver_ptr + 0*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
//             RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_receiver_key_buffer2, (unsigned char*)(AES_buffer_receiver_ptr + 1*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
//             RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_receiver_ivec1,        (unsigned char*)(AES_buffer_receiver_ptr + 2*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
//             RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_receiver_ivec2,        (unsigned char*)(AES_buffer_receiver_ptr + 3*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
            
//             //  Set AES key 
//             AES_KEY receiver_aes_encrypt_key1, receiver_aes_encrypt_key2;
//             AES_set_encrypt_key(aes_receiver_key_buffer1, AES_KEY_LENGTH_BIT, &receiver_aes_encrypt_key1);
//             AES_set_encrypt_key(aes_receiver_key_buffer2, AES_KEY_LENGTH_BIT, &receiver_aes_encrypt_key2);

//             //  Encrypt A
//             AES_cbc_encrypt(randA, share_buf_A_ptr, bytes_count_A_total, &receiver_aes_encrypt_key1, aes_receiver_ivec1, AES_ENCRYPT);
//             //  Encrypt C
//             AES_cbc_encrypt(randC, share_buf_C_ptr, bytes_count_C_total, &receiver_aes_encrypt_key2, aes_receiver_ivec2, AES_ENCRYPT);

//         }

//         //  HYBRID_ENCRYPTION_ON = 0, RSA only
//         else{
//             int element_A_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_A;
//             int element_C_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_C;
//             int cipher_count_A = ceil(size_m *1.0/ element_A_count_per_cipher);
//             int cipher_count_C = ceil(size_m *1.0/ element_C_count_per_cipher);

//             int iter;

//             //  Encrypt A
//             int real_element_in_cipher_count_A = element_A_count_per_cipher;
//             for(iter = 0; iter < cipher_count_A - 1; iter ++){
//                 RSA_public_encrypt(real_element_in_cipher_count_A * bytes_count_A, \
//                 (unsigned char*)(randA + (iter * bytes_count_A * element_A_count_per_cipher)), \
//                 (unsigned char*)(share_buf_A_ptr + (iter * receiver_pk_size)) , \
//                 receiver_pk_inside, PADDING_MODE);
//             }
//             real_element_in_cipher_count_A = size_m - iter * element_A_count_per_cipher;
//             RSA_public_encrypt(real_element_in_cipher_count_A, \
//             (const unsigned char*)(randA + (iter * bytes_count_A * element_A_count_per_cipher)), \
//             (unsigned char*)(share_buf_A_ptr + (iter * receiver_pk_size)) , \
//             receiver_pk_inside, PADDING_MODE);

//             //  Encrypt C
//             int real_element_in_cipher_count_C = element_C_count_per_cipher;
//             for(iter = 0; iter < cipher_count_C - 1; iter ++){
//                 RSA_public_encrypt(real_element_in_cipher_count_C * bytes_count_C, \
//                 (unsigned char*)(randC + (iter * bytes_count_C * element_C_count_per_cipher)), \
//                 (unsigned char*)(share_buf_C_ptr + (iter * receiver_pk_size)) , \
//                 receiver_pk_inside, PADDING_MODE);
                
//             }

//             real_element_in_cipher_count_C = size_m - iter * element_C_count_per_cipher;
//             RSA_public_encrypt(real_element_in_cipher_count_C, \
//             (const unsigned char*)(randC + (iter * bytes_count_C * element_C_count_per_cipher)), \
//             (unsigned char*)(share_buf_C_ptr + (iter * receiver_pk_size)) , \
//             receiver_pk_inside, PADDING_MODE);
//         }


//         Timer encryptACEnd = std::chrono::system_clock::now();
//         std::cout << "---[In SGX] ---Encrypt A/C ";
//         std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(encryptACEnd - encryptACBegin).count() << "ms" << std::endl;
//         std::cout << "---[In SGX] Encrypt A/B/C/Delta done" << endl;
//     }
//     //  PROTOCOL_MODE = 0    No need to decrypt. Just copy.
//     else{
//         memcpy(share_buf_A_ptr, randA, bytes_count_A_total);
//         memcpy(share_buf_C_ptr, randC, bytes_count_C_total);
//     }

    
//     Timer sgxEnd = std::chrono::system_clock::now();
//     std::cout << "Interact with TEE done ";
//     std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(sgxEnd - sgxBegin).count() << "ms" << std::endl;
//     std::cout << "--------------------------------------------------" << endl;


//     /*----------- Done -----------*/

//     return EXIT_SUCCESS;

// }