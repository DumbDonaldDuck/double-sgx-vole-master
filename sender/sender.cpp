#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

//  Common C++ header files
#include <Vole.h>

//  for sgx process
#include <occlum_pal_api.h>
#include <linux/limits.h>

int main(int argc, char *argv[]) {

    
    /*--------------------------- Sender Protocol ------------------------------

        out TEE
            --set parameters(buffer for B/Delta) for sgx
        in TEE
            --generate RSA-key for Sender-TEE
            --Socket Transfer with Receiver-TEE (send pk)
            --share random seed 
            --generate A/B/C/Delta
            --keep B/Delta only
        out TEE
            --get B/Delta from sgx

    --------------------------------------------------------------------------*/

    std::cout << "--------------------------------------------------" << endl;
    Timer totalBegin = std::chrono::system_clock::now();


    /*----------- Connect with TEE process -----------*/

    // Init Occlum PAL
    occlum_pal_attr_t pal_attr = OCCLUM_PAL_ATTR_INITVAL;
    pal_attr.instance_dir = "occlum_instance_sender";
    pal_attr.log_level = "off";
    if (occlum_pal_init(&pal_attr) < 0) {
        return EXIT_FAILURE;
    }

    
    /* --------------  Prepare cmd path and arguments -----------------
        cmd_path,
       
        buffer_B_ptr_str
        buffer_B_size_str
        buffer_Delta_ptr_str
        buffer_Delta_size_str
    ----------------------------------------------------------------- */


    //  cmd_path   
    const char *cmd_path = "/bin/vole_sender";         //  in-sgx app name

    //  buffer B/Delta      -> ptr & size              

    int bytes_count_B = FIELD_F_BYTE;
    int bytes_count_Delta = FIELD_B_BYTE;    

    int buffer_size_B = SIZE_M * bytes_count_B;    
    int buffer_size_Delta = bytes_count_Delta;
    unsigned char *buffer_B = (unsigned char*)malloc(buffer_size_B);
    unsigned char *buffer_Delta = (unsigned char*)malloc(buffer_size_Delta);


    char share_buf_B_ptr_str[32] = {0};
    char share_buf_B_size_str[32] = {0};
    snprintf(share_buf_B_ptr_str, sizeof(share_buf_B_ptr_str), "%lu", (unsigned long) buffer_B);
    snprintf(share_buf_B_size_str, sizeof(share_buf_B_size_str), "%lu", sizeof(buffer_B));

    char share_buf_Delta_ptr_str[32] = {0};
    char share_buf_Delta_size_str[32] = {0};
    snprintf(share_buf_Delta_ptr_str, sizeof(share_buf_Delta_ptr_str), "%lu", (unsigned long) buffer_Delta);
    snprintf(share_buf_Delta_size_str, sizeof(share_buf_Delta_size_str), "%lu", sizeof(buffer_Delta));


    const char *cmd_args[] = {  
        cmd_path,                       //  cmd_path            0
        share_buf_B_ptr_str,            //  shared_buf_ptr      1
        share_buf_B_size_str,           //  shared_buf_size     2
        share_buf_Delta_ptr_str,        //  shared_buf_ptr      3
        share_buf_Delta_size_str,       //  shared_buf_size     4
        NULL
    };

    struct occlum_stdio_fds io_fds = {
        .stdin_fd = STDIN_FILENO,
        .stdout_fd = STDOUT_FILENO,
        .stderr_fd = STDERR_FILENO,
    };

    // Use Occlum PAL to create new process
    int libos_tid = 0;
    struct occlum_pal_create_process_args create_process_args = {
        .path = cmd_path,
        .argv = cmd_args,
        .env = NULL,
        .stdio = (const struct occlum_stdio_fds *) &io_fds,
        .pid = &libos_tid,
    };

    if (occlum_pal_create_process(&create_process_args) < 0) {
        return EXIT_FAILURE;
    }

    // Use Occlum PAL to execute the cmd
    int exit_status = 0;
    struct occlum_pal_exec_args exec_args = {
        .pid = libos_tid,
        .exit_value = &exit_status,
    };
    if (occlum_pal_exec(&exec_args) < 0) {
        return EXIT_FAILURE;
    }

    // Destroy Occlum PAL
    occlum_pal_destroy();

    //  free all heap space
    free(buffer_B);
    free(buffer_Delta);

    std::cout << "--------------------------------------------------" << endl;
    Timer totalEnd = std::chrono::system_clock::now();
    std::cout << "Total time: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(totalEnd - totalBegin).count() << "ms" << std::endl;
    

    /*----------- Done -----------*/

    return exit_status;                 //  According to occlum-exec result to return
}