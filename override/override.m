#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sqlite3.h> 
#include <sys/types.h>
#include <pwd.h>
#include <assert.h>
#import <objc/runtime.h>

#define DYLD_INTERPOSE(_replacement,_replacee) \
        __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
        __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

#define DEBUG 1

#if !TARGET_OS_IPHONE
#warning - building Mac lib
#else
#warning - building iPhone lib
#endif
#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
#warning - building imagent override
#else
#warning - building IMRemoteURLConnectionAgent override
#endif
#if DEBUG
#warning - building debug version
#endif

#if !TARGET_OS_IPHONE
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

extern void* IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID(void* r0, void* r1);

#define APP_NAME "iMITMProtect"
#define DB_DIR_REL "Library/Application Support/" APP_NAME
#define DB_FILE "database.db"

#define DB_PATH_REL DB_DIR_REL "/" DB_FILE

void send_notification(NSString* title, NSString* text) {
#if !TARGET_OS_IPHONE
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

#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
void my_xpc_dictionary_set_data(xpc_object_t dictionary, const char *key, const void *value, size_t length) {
#else
const void *my_xpc_dictionary_get_data(xpc_object_t dictionary, const char *key, size_t *out_length) {
	if (DEBUG) syslog(LOG_WARNING, "%s: entering xpc_dictionary_get_data(%s, )", APP_NAME, key);
	size_t length;
	const void* value = xpc_dictionary_get_data(dictionary, key, &length);
	*out_length = length;
#endif
	if (key != NULL && !strcmp(key, "request") && value != NULL && length > 0) {
		NSData *data = [NSData dataWithBytes: value length: length];
		id obj = [NSUnarchiver unarchiveObjectWithData: data];
		if (obj != nil && [obj class] == [NSMutableURLRequest class] && [obj URL] != nil) {
			NSString *sURL = [[obj URL] absoluteString];
#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
			if (DEBUG) syslog(LOG_WARNING, "%s: xpc_dictionary_get_data for requesting URL: %s", APP_NAME, [sURL UTF8String]);
#else
			if (DEBUG) syslog(LOG_WARNING, "%s: xpc_dictionary_set_data for requesting URL: %s", APP_NAME, [sURL UTF8String]);
#endif
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
#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
	xpc_dictionary_set_data(dictionary, key, value, length);
#else
	return value;
#endif
}

#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
const void *my_xpc_dictionary_get_data(xpc_object_t dictionary, const char *key, size_t *out_length) {
	size_t length;
	if (DEBUG) syslog(LOG_WARNING, "%s: entering xpc_dictionary_get_data(%s, )", APP_NAME, key);
	const void* value = xpc_dictionary_get_data(dictionary, key, &length);
	*out_length = length;
#else
void my_xpc_dictionary_set_data(xpc_object_t dictionary, const char *key, const void *value, size_t length) {
	if (DEBUG) syslog(LOG_WARNING, "%s: entering xpc_dictionary_set_data(%s, )", APP_NAME, key);
#endif
	if (inContactQuery && key != NULL && !strcmp(key, "resultData") && value != NULL && length > 5 && !strncmp(value, "<?xml", 5)) {
		NSData *data = [NSData dataWithBytes: value length: length];
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
#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
				xpc_dictionary_set_data(dictionary, key, c_new_xml, strlen(c_new_xml));
#endif
				value = c_new_xml;
#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
				*out_length = strlen(c_new_xml);
#else
				length = strlen(c_new_xml);
#endif
			}
		}
		[xml release];
	}
#if !TARGET_OS_IPHONE || __IPHONE_OS_VERSION_MIN_REQUIRED < 70000
	return value;
#else
	xpc_dictionary_set_data(dictionary, key, value, length);
#endif
}

void* my_IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID(void* r0, void* r1) {
	syslog(LOG_WARNING, "entering IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID(%p, %p)", r0, r1);
	void* ret = IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID(r0, r1);
	syslog(LOG_WARNING, "exiting IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID(%p, %p) return value=%p", r0, r1, ret);
	return ret;
}

DYLD_INTERPOSE(my_xpc_dictionary_set_data, xpc_dictionary_set_data)
DYLD_INTERPOSE(my_xpc_dictionary_get_data, xpc_dictionary_get_data)

DYLD_INTERPOSE(my_IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID, IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID)
//_IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID

#if 0
static IMP g_IMRemoteURLConnection_load_orig = nil;
static id my_IMRemoteURLConnection_load(id self, SEL selector, id p1, id p2) {
	syslog(LOG_WARNING, "[IMRemoteURLConnection load] called");
        return g_IMRemoteURLConnection_load_orig(self, selector, p1, p2);
}
#endif

__attribute__((constructor)) void init() {
	if (DEBUG) syslog(LOG_WARNING, "%s: initializing override.dylib", APP_NAME);
#if !TARGET_OS_IPHONE
	syslog(LOG_WARNING, "Interposition of IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID");
	interpose("IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID", my_IMDMessageRecordCopyNewestUnreadIncomingMessagesToLimitAfterRowID);
	interpose("_xpc_dictionary_set_data", my_xpc_dictionary_set_data);
	interpose("_xpc_dictionary_get_data", my_xpc_dictionary_get_data); 
#endif
#if 0
	Class class = NSClassFromString(@"IMRemoteURLConnection");
	SEL sel = @selector(load);
	g_IMRemoteURLConnection_load_orig = class_replaceMethod(class,
                                                sel,
                                                (IMP) my_IMRemoteURLConnection_load,
                                                method_getTypeEncoding(class_getInstanceMethod(class, sel)));
#endif
}
