//
//  Injector.m
//  iMITMProtect
//
//  Created by Cyril on 04/09/13.
//
//

#import "Injector.h"
#import "inject.h"
#include <sys/sysctl.h>
#include <syslog.h>

@implementation Injector
static pid_t getpidof(char* process_name) {
    int err = 0;
    struct kinfo_proc *proc_list = NULL;
    size_t length = 0;
    
    static const int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    
    // Call sysctl with a NULL buffer to get proper length
    err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0);
    if (err) goto ERROR;
    
    // Allocate buffer
    proc_list = malloc(length);
    if (!proc_list) goto ERROR;
    
    // Get the actual process list
    err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, proc_list, &length, NULL, 0);
    if (err) goto ERROR;
    
    size_t proc_count = length / sizeof(struct kinfo_proc);
    
    // use getpwuid_r() if you want to be thread-safe
    
    uid_t my_uid = getuid();
    pid_t found = 0;
    for (int i = 0; i < proc_count && found == 0; i++) {
        char* name = proc_list[i].kp_proc.p_comm;
        pid_t pid = proc_list[i].kp_proc.p_pid;
        uid_t uid = proc_list[i].kp_eproc.e_ucred.cr_uid;
        
        if (my_uid == uid && !strcmp(name, process_name)) {
            found = pid;
        }
    }
    
    free(proc_list);
    
    return found;
    
ERROR:
    perror(NULL);
    free(proc_list);
    return EXIT_FAILURE;
}

static void send_notification(NSString* title, NSString* text) {
    NSUserNotification *notification = [[NSUserNotification alloc] init];
    notification.title = title;
    notification.informativeText = text;
    notification.soundName = NSUserNotificationDefaultSoundName;
    [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification: notification];
}

- (id) init {
    if (self = [super init]) {
        self->overriden_imagent = 0;
    }
    return self;
}

- (void) main {
    while (true) {
        pid_t pid = getpidof("imagent");
        if (pid != 0 && pid != self->overriden_imagent) {
            NSURL *url = [[NSBundle mainBundle] URLForResource:@"override" withExtension:@"dylib"];
            kern_return_t ret;
            if (!(ret = inject(pid, [url.path UTF8String]))) {
                self->overriden_imagent = pid;
                syslog(LOG_INFO, "%s: code successfully injected into imagent.", APP_NAME);
                send_notification(@APP_NAME, @"Now protecting you against iMessage MITM attacks.");
            } else {
                syslog(LOG_INFO, "%s: code injection failed: %d.", APP_NAME, ret);
            }
        }
        sleep(1);
    }
}
@end
