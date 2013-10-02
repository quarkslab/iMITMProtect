#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sqlite3.h> 
#include <sys/types.h>
#include <pwd.h>
#include <assert.h>

#define DYLD_INTERPOSE(_replacement,_replacee) \
        __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
        __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

#ifndef TARGET_OS_IPHONE
#include "interpose.h"
#include <xpc/xpc.h>
#else
@interface NSUnarchiver : NSCoder {
}
+ (id)unarchiveObjectWithData:(NSData *)data;
@end
#define xpc_object_t void*
//#define NSUnarchiver NSKeyedUnarchiver
extern const void* xpc_dictionary_get_data(xpc_object_t dictionary, const char *key, size_t *length);
extern void xpc_dictionary_set_data(xpc_object_t dictionary, const char *key, const void *value, size_t length);
#endif

#define APP_NAME "iMITMProtect"
#define DB_DIR_REL "Library/Application Support/" APP_NAME
#define DB_FILE "database.db"

#define DB_PATH_REL DB_DIR_REL "/" DB_FILE

void send_notification(NSString* title, NSString* text) {
#ifndef TARGET_OS_IPHONE
	NSUserNotification *notification = [[NSUserNotification alloc] init];
	notification.title = title;
	notification.informativeText = text;
	notification.soundName = NSUserNotificationDefaultSoundName;
	[[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification: notification];
	[notification release];
#else
	NSLog(@"%@: %@", title, text);
#endif
}

NSString *current_user_home() {
    struct passwd *pw = getpwuid(getuid());
    assert(pw);
    return [NSString stringWithUTF8String: pw->pw_dir];
}

static int select_callback(void *param, int argc, char **argv, char **azColName){
	char ** result = (char **) param;
	assert(argc == 1);
	if (*result != NULL) free(*result);
	if (argv[0] != NULL) {
		*result = malloc(strlen(argv[0]));
		strcpy(*result, argv[0]);
	}
	return 0;
}

NSString* save_token_key(NSString* identity, NSString* token, NSString* key) {
	NSString* ret = nil;
	sqlite3 *db = NULL;
	char* error = NULL;
	char *sql = NULL;
	NSError *oerror = NULL;
	NSString* dbDir = [NSString stringWithFormat: @"%@/%@", current_user_home(), @DB_DIR_REL];
	NSString* dbPath = [NSString stringWithFormat: @"%@/%@", current_user_home(), @DB_PATH_REL];

	NSFileManager* fm = [NSFileManager defaultManager];
	if (![fm fileExistsAtPath: dbDir] && ![fm createDirectoryAtPath: dbDir
                                   withIntermediateDirectories: YES
                                                    attributes: nil
                                                         error: &oerror]) {
		syslog(LOG_ERR, "%s: failed to create directory: %s. error: %s", APP_NAME, [dbDir UTF8String], [[oerror localizedDescription] cStringUsingEncoding: NSASCIIStringEncoding]);
		goto end;
	}

	if (sqlite3_open([dbPath UTF8String], &db) != SQLITE_OK) {
		syslog(LOG_ERR, "%s: failed to connect to sqlite database %s", APP_NAME, [dbPath UTF8String]);
		goto end;
	}

	if (sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS pub_keys (token TEXT PRIMARY KEY, identity TEXT, pub_key TEXT)", NULL, 0, &error) != SQLITE_OK) {
		syslog(LOG_ERR, "%s: failed to create table: %s", APP_NAME, error);
		goto end;
	}
	
	if  ([token rangeOfString:@"'"].location != NSNotFound || [key rangeOfString:@"'"].location != NSNotFound
		|| [token rangeOfString:@"\\"].location != NSNotFound || [key rangeOfString:@"\\"].location != NSNotFound) {
		syslog(LOG_ERR, "%s: it smells like an SQL injection.", APP_NAME);
		goto end;
	}

	sql = sqlite3_mprintf("SELECT pub_key FROM pub_keys WHERE token = '%q'", [token UTF8String]);
	char *db_pub_key = NULL;
	if (sqlite3_exec(db, sql, select_callback, (void*) &db_pub_key, &error) != SQLITE_OK) {
		syslog(LOG_ERR, "%s: failed to query table: %s", APP_NAME, error);
		goto end;
	}
	if (db_pub_key != NULL) {
		if (strcmp(db_pub_key, [key UTF8String])) {
			syslog(LOG_WARNING, "%s: iMessage MITM attempt detected!", APP_NAME);
			send_notification(@APP_NAME, @"iMessage MITM attempt detected! Protecting you using saved identity key.");
			ret = [[NSString stringWithUTF8String: db_pub_key] retain];
		}
		free(db_pub_key);
	} else {
		sqlite3_free(sql);
		sql = sqlite3_mprintf("INSERT INTO pub_keys (token, identity, pub_key) VALUES ('%q', '%q', '%q')", [token UTF8String], [identity UTF8String], [key UTF8String]);
		if (sqlite3_exec(db, sql, NULL, 0, &error) != SQLITE_OK) {
			syslog(LOG_ERR, "%s: failed to insert into table: %s", APP_NAME, error);
			goto end;
		}
	}
		
end:
	if (sql != NULL) sqlite3_free(sql);
	if (db != NULL) sqlite3_close(db);
	return ret;
}

static bool inContactQuery = false;
static NSString* contactURI = nil;

void my_xpc_dictionary_set_data(xpc_object_t dictionary, const char *key, const void *value, size_t length) {
	if (key != NULL && !strcmp(key, "request") && value != NULL && length > 0) {
		NSData *data = [NSData dataWithBytes: value length: length];
		id obj = [NSUnarchiver unarchiveObjectWithData: data];
		if (obj != nil && [obj class] == [NSMutableURLRequest class] && [obj URL] != nil) {
			NSString *sURL = [[obj URL] absoluteString];
			inContactQuery = [sURL hasPrefix: @"https://service1.ess.apple.com/WebObjects/QueryService.woa/wa/query"];
			if (inContactQuery) {
				NSRegularExpression *rURI = [NSRegularExpression regularExpressionWithPattern: @"\\?uri=(.*)$" options: 0 error: nil];
				NSArray *uriMatches = [rURI matchesInString: sURL options: 0 range: NSMakeRange(0, [sURL length])];
				if ([uriMatches count] == 1) {
					NSString* uri = [[sURL substringWithRange: [[uriMatches objectAtIndex: 0] rangeAtIndex: 1]] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
					if (contactURI != nil) [contactURI release];
					contactURI = [uri retain];
				} else {
					syslog(LOG_ERR, "%s: can't get the contact query URI", APP_NAME);
					inContactQuery = false;
					if (contactURI != nil) [contactURI release];
					contactURI = nil;
				}
			}
		}
	}
	xpc_dictionary_set_data(dictionary, key, value, length);
}
const void *my_xpc_dictionary_get_data(xpc_object_t dictionary, const char *key, size_t *length) {
	size_t my_length;
	const void* value = xpc_dictionary_get_data(dictionary, key, &my_length);
	*length = my_length;
	if (inContactQuery && key != NULL && !strcmp(key, "resultData") && value != NULL && my_length > 5 && !strncmp(value, "<?xml", 5)) {
		NSData *data = [NSData dataWithBytes: value length: my_length];
		NSString *xml = [[NSString alloc] initWithData: data encoding: NSASCIIStringEncoding];
		NSRegularExpression *rTokens = [NSRegularExpression regularExpressionWithPattern: @"<key>push-token</key><data>(.*)</data>" options: 0 error: nil];
		NSRegularExpression *rKeys = [NSRegularExpression regularExpressionWithPattern: @"<key>public-message-identity-key</key><data>(.*)</data>" options: 0 error: nil];
		NSArray *tokenMatches = [rTokens matchesInString: xml options: 0 range: NSMakeRange(0, [xml length])];
		NSArray *keyMatches = [rKeys matchesInString: xml options: 0 range: NSMakeRange(0, [xml length])];
		if ([tokenMatches count] == [keyMatches count]) {
			NSMutableString *new_xml = nil;
			NSUInteger i = 0;
			for (NSTextCheckingResult *tokenMatch in tokenMatches) {
				NSString* token = [xml substringWithRange: [tokenMatch rangeAtIndex: 1]];
				NSRange pikRange = [[keyMatches objectAtIndex: i] rangeAtIndex: 1];
				NSString* pik = [xml substringWithRange: pikRange];
				NSString* prefered_pik = save_token_key(contactURI, token, pik);
				if (prefered_pik != nil) {
					if (new_xml == nil) {
						new_xml = [[NSMutableString alloc] init];
						[new_xml appendString: xml];
					}
					[new_xml replaceCharactersInRange: pikRange withString: prefered_pik];
					[prefered_pik release];
				}
				i++;
			}
			if (new_xml != nil) {
				const char *c_new_xml = [new_xml cStringUsingEncoding: NSASCIIStringEncoding];
				xpc_dictionary_set_data(dictionary, key, c_new_xml, strlen(c_new_xml));
				value = c_new_xml;
				*length = strlen(c_new_xml);
			}
		}
		[xml release];
	}
	return value;
}

DYLD_INTERPOSE(my_xpc_dictionary_set_data, xpc_dictionary_set_data)
DYLD_INTERPOSE(my_xpc_dictionary_get_data, xpc_dictionary_get_data)

#ifndef TARGET_OS_IPHONE
__attribute__((constructor)) void init() {
	interpose("_xpc_dictionary_set_data", my_xpc_dictionary_set_data);
	interpose("_xpc_dictionary_get_data", my_xpc_dictionary_get_data); 
}
#endif
