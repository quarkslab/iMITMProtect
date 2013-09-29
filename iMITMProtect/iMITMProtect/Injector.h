//
//  Injector.h
//  iMITMProtect
//
//  Created by Cyril on 04/09/13.
//
//

#import <Foundation/Foundation.h>

@interface Injector : NSThread {
@private
    pid_t overriden_imagent;
}


@end
