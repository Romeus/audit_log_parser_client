#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libaudit.h>
#include <unistd.h>
#include <auparse.h>
#include <syslog.h>
#include <sys/stat.h>
#include <json/json.h>
#include <curl/curl.h>
#include <stdbool.h>

#define BUF_LEN 524288
#define RECORD_BUF_LEN 102400
#define MAX_DESCRIPTORS 8192
#define CONNECTION_URL "localhost:8888"
#define POLLING_DELAY 1

void fetch_next_event(auparse_state_t *au, json_object *json)
{
	do {
		const char *type = auparse_get_type_name(au);
		json_object *json_type = json_object_new_string(type);

		json_object_object_add(json, "type", json_type);

		do {
			json_object *json_field_value = json_object_new_string(auparse_get_field_str(au));
			json_object_object_add(json, auparse_get_field_name(au), json_field_value);
		} while (auparse_next_field(au) > 0);

	} while (auparse_next_record(au) > 0);
}

int main(int argc, char *argv[])
{
	int err;
	int free_buf_space;
	auparse_state_t *au;
	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = NULL;
	static char temp_buf[BUF_LEN], record_buf[RECORD_BUF_LEN];
	bool buf_overflow;


	curl_global_init(CURL_GLOBAL_ALL);

	openlog("audit_log_parser", LOG_PID, LOG_DAEMON);

	curl = curl_easy_init();

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, CONNECTION_URL);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

		headers = curl_slist_append(headers, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);

		au = auparse_init(AUSOURCE_LOGS, NULL);
		if (au == NULL) {
			syslog(LOG_ERR, "You should run that program with the root privelegies\n");
			exit(1);
		}

		err = auparse_first_record(au);
		if (err == -1) {
			syslog(LOG_ERR, "Couldn't initialize auparse");
			exit(1);
		}

		temp_buf[0] = '\0';
		buf_overflow = false;

		for (;;) {
			while (auparse_next_event(au) > 0 && !buf_overflow) {
				json_object *json = json_object_new_object();

				fetch_next_event(au, json);

				record_buf[0] = '\0';
				strcat(record_buf, json_object_to_json_string(json));
				free_buf_space  = BUF_LEN - strlen(temp_buf) - 2;

				if (free_buf_space >= strlen(record_buf)) {
					strcat(temp_buf, record_buf);
					strcat(temp_buf, ",\n\n");
				} else {
					buf_overflow = true;
				}

				json_object_put(json);
			};

			if (strlen(temp_buf)) {
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, temp_buf);
				res = curl_easy_perform(curl);

				if (res != CURLE_OK)
					syslog(LOG_ERR, "Transfer to the server has failed: %s", curl_easy_strerror(res));
			}

			if (buf_overflow) {
				strcat(temp_buf, record_buf);
				strcat(temp_buf, ",\n\n");
				buf_overflow = false;
			} else {
				sleep(POLLING_DELAY);
			}

			temp_buf[0] = '\0';
		}

	} else {
		syslog(LOG_ERR, "curl library initialization has failed");
	}

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return 0;
}
