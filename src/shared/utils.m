#include <time.h>
#include <spawn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

// credits to tihmstar
void suspend_all_threads()
{
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;
    
    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        return;
    }
    
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_suspend(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                }
            }
        }
    }
}

// credits to tihmstar
void resume_all_threads()
{
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;
    
    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_resume(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                }
            }
        }
    }
}

// creds to stek29 on this one
int execprog(const char *prog, const char* args[]) {
    if (args == NULL) {
        args = (const char **)&(const char*[]){ prog, NULL };
    }
    
    if (access("/tmp/exec_logs", F_OK) != 0)
    {
        mkdir("/tmp/exec_logs", 0755);
    }
    
    char logfile[1024] = { 0 };
    strcat(logfile, "/tmp/exec_logs/");
    sprintf(logfile + strlen(logfile), "%lu", time(NULL));
    
    printf("spawning %s ( ", prog);
    for (const char **arg = args; *arg != NULL; ++arg)
    {
        printf("%s ", (char *)*arg);
    }
    printf(") to logfile %s\n", logfile);
    
    int rv;
    posix_spawn_file_actions_t child_fd_actions;
    if ((rv = posix_spawn_file_actions_init (&child_fd_actions))) {
        perror ("posix_spawn_file_actions_init");
        return rv;
    }
    if ((rv = posix_spawn_file_actions_addopen (&child_fd_actions, STDOUT_FILENO, logfile,
                                                O_WRONLY | O_CREAT | O_TRUNC, 0666))) {
        perror ("posix_spawn_file_actions_addopen");
        return rv;
    }
    if ((rv = posix_spawn_file_actions_adddup2 (&child_fd_actions, STDOUT_FILENO, STDERR_FILENO))) {
        perror ("posix_spawn_file_actions_adddup2");
        return rv;
    }
    
    pid_t pd;
    if ((rv = posix_spawn(&pd, prog, &child_fd_actions, NULL, (char**)args, NULL))) {
        printf("posix_spawn error: %d (%s)\n", rv, strerror(rv));
        return rv;
    }
    
    int ret, status;
    do {
        ret = waitpid(pd, &status, 0);
        if (ret > 0) {
            printf("%s exited with %d (sig %d)\n", prog, WEXITSTATUS(status), WTERMSIG(status));
        } else if (errno != EINTR) {
            printf("waitpid error %d: %s\n", ret, strerror(errno));
        }
    } while (ret < 0 && errno == EINTR);
    
    int fd = open(logfile, O_RDONLY);
    if (fd == -1) {
        perror("open logfile");
        return 1;
    }
    
    printf("contents of %s:\n", logfile);
    printf("---\n");
    char buf[1] = {0};
    while (read(fd, buf, sizeof(buf)) == sizeof(buf)) {
        printf("%s", buf);
    }
    printf("---\n");
    
    close(fd);
    remove(logfile);
    return (int8_t)WEXITSTATUS(status);
}
