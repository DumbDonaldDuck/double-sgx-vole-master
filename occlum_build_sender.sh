#! /bin/bash

FOLDER=occlum_instance_sender

exist=0
if [  test -f "${FOLDER}" ]
then
    exist=1
fi



if [ $exist -ne 1 ]
then
    mkdir -p ${FOLDER}
fi

cd ${FOLDER}


if [ $exist -ne 1 ]
then
    occlum init 
fi


rm -rf image 
rm -r Occlum.json 
cp ../occlum_default.json . 
mv occlum_default.json Occlum.json 
copy_bom -f ../sender.yaml --root image --include-dir /opt/occlum/etc/template
occlum build



# "resource_limits": {
#     "kernel_space_heap_size": "64MB",
#     "kernel_space_stack_size": "4MB",
#     "user_space_size": "512MB",
#     "max_num_of_threads": 32
# },
# "process": {
#     "default_stack_size": "16MB",
#     "default_heap_size": "256MB",
#     "default_mmap_size": "128MB"
# },