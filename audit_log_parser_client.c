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
#include <sys/types.h>
#include <signal.h>
#include <json/json.h>
#include <curl/curl.h>
#include <stdbool.h>

#define BUF_LEN 524288
#define RECORD_BUF_LEN 102400
#define MAX_DESCRIPTORS 8192
#define CONNECTION_URL "localhost:8888"
#define POLLING_DELAY 1
#define SHUTDOWN_OPTION "-shutdown"

#define LOCKFILE "/var/run/audit_client_parser.pid"
#define LOCKMODE 0644

void clear_daemon_resources(void)
{
	remove(LOCKFILE);
}

int lockfile(int fd)
{
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	return fcntl(fd, F_SETLK, &fl);
}

int kill_daemon(void)
{
	pid_t pid;
	char daemon_pid[16];
	int daemon_fd;

	daemon_fd = open(LOCKFILE, O_RDONLY);

	if (daemon_fd == -1)
		return -1;

	if (read(daemon_fd, daemon_pid, 16) == -1)
		return -1;

	close(daemon_fd);

	pid = (pid_t)atol(daemon_pid);

	if (kill(pid, SIGKILL) != 0)
		return -1;

	clear_daemon_resources();

	return true;
}

bool is_daemon_running(void)
{
	int daemon_fd;

	daemon_fd = open(LOCKFILE, O_RDONLY);

	if (daemon_fd < 0)
		syslog(LOG_ERR, "can't open %s: %s", LOCKFILE, strerror(errno));

	close(daemon_fd);

	return (daemon_fd > 0);
}

int daemonize(void)
{
	int maxfd, fd, daemon_fd;
	char pid_buf[16];

	/* daemonize itself */
	switch (fork()) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		_exit(EXIT_SUCCESS);
	}

	if (setsid() == -1)
		return -1;

	/* prevents itself from become process leader */
	switch (fork()) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		_exit(EXIT_SUCCESS);
	}

	umask(0);
	chdir("/");

	daemon_fd = open(LOCKFILE, O_RDWR|O_CREAT, LOCKMODE);
	if (fd < 0) {
		syslog(LOG_ERR, "can't open %s: %s", LOCKFILE, strerror(errno));
		exit(-1);
	}

	ftruncate(daemon_fd, 0);
	sprintf(pid_buf, "%ld", (long)getpid());
	write(daemon_fd, pid_buf, strlen(pid_buf)+1);
	close(daemon_fd);

	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd == -1)
		maxfd = MAX_DESCRIPTORS;

	for (fd = 0; fd < maxfd; fd++)
		close(fd);

	close(STDIN_FILENO);

	fd = open("/dev/null", O_RDWR);

	if (fd != STDIN_FILENO)
		return -1;
	if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
		return -1;
	if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
		return -1;

	return 0;
}

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
	bool daemon_is_running;

	daemon_is_running = is_daemon_running();

	if (argc > 1) {
		if (strcmp(argv[1], SHUTDOWN_OPTION) == 0) {
			if (daemon_is_running) {
				kill_daemon();
				printf("Daemon has been stopped\n");
			} else {
				printf("Daemon wasn't running\n");
			}
			exit(1);
		};
	};

	if (daemon_is_running) {
		printf("Daemon is already running\n");
		exit(0);
	}

	if (daemonize() == -1) {
		perror("Couldn't create the daemon\n");
		exit(1);
	}

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
			clear_daemon_resources();
			exit(1);
		}

		err = auparse_first_record(au);
		if (err == -1) {
			syslog(LOG_ERR, "Couldn't initialize auparse");
			clear_daemon_resources();
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
