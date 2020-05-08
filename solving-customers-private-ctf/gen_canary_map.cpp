#include <random>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdio>
#include <unistd.h>

int main()
{
	for (unsigned int seed = 0; seed < 0xFFFFF; seed++)
	{
		std::mt19937 gen(seed);
		unsigned int key = gen();
		unsigned int canary = gen() ^ key;
		printf("%u:%X\n", key, canary);
	}
	return 0;
}

