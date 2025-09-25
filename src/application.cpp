#include <argparse/argparse.hpp>
#include <csignal>
#include <iostream>
#include <unistd.h>// sleep

static bool stop_app = false;

void
handle_sigint(
	int /* signal */)
{
	stop_app = true;
}

int main(int argc, char *argv[])
{
	signal(SIGINT, handle_sigint);// ctrl+c to stop application

	argparse::ArgumentParser program("application");

	program.add_argument("--cfg-file")
		.help("path to a config file")
		.default_value("default.cfg");
	
	program.add_argument("--daemon")
		.help("run as daemon process")
		.default_value(false)
		.implicit_value(true);
	
	program.add_argument("--verbose")
		.help("increase output verbosity")
		.default_value(false)
		.implicit_value(true);

	try
	{
    	program.parse_args(argc, argv);
	}
	catch (const std::exception & e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << program;
		return 1;
	}

	printf("cfg-file  = %s\n", program.get("cfg-file").c_str());
	printf("daemon    = %d\n", program.get<bool>("daemon"));
	printf("verbose   = %d\n", program.get<bool>("verbose"));

	while ( ! stop_app)
	{
		printf("hello!\n");
		sleep(1);
	}

	printf("goodbye!\n");

	return 0;
}