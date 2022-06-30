#include <Windows.h>
#include <kernel/driver.h>
#include <iostream>
#include <string>



int main()
{
	SetConsoleTitle("Usermode Driver Test");
	printf("Welcome to Usermode.\n");


	kernel::driver driver;
	//if (!driver.init())
	//{
	//	printf("Initialization or communication test failed.\nPlease make sure driver is loaded.\n");
	//	Sleep(1500);
	//	return 1;
	//}
	driver.init();

	printf("operation: ");
	std::string str = "";
	std::getline(std::cin, str);
	if (str == "unhook")
	{
		driver.unload();
		return 0;
	}

	driver.attach( GetCurrentProcessId( ) );

	std::cout << driver.get_process_module( "UnityPlayer.dll" ) << std::endl;
	

	printf("Testing read/write:\n");
	printf("PID: ");


	std::string pid_str = "";
	std::getline(std::cin, pid_str);
	driver.attach(stoi(pid_str));

	std::cout << driver.get_process_module( "UnityPlayer.dll" ) << std::endl;
	std::cin.get( );

	printf("getting base...\n");
	uintptr_t base = driver.get_process_module(NULL);
	printf("base: %p\n", base);
	
	uintptr_t varInt = 0x7FF6134F60D0 - 0x00007FF6134F0000 + base;
	uintptr_t arrChar128 = 0x7FF6134F6050 - 0x00007FF6134F0000 + base;
	uintptr_t memoryPtr = 0x7FF6134F6788 - 0x00007FF6134F0000 + base;
	
	
	printf("Testing bad write...\n");
	driver.write<int>(0x69, 0xDEADBEEF);
	printf("Bad write passed.\n");

	printf("Writing to varInt: (%i) -> 654321\n", driver.read<int>(varInt));
	driver.write<int>(varInt, 654321);
	
	char arrChar[128];
	driver.read_buffer(arrChar128, (uint8_t *)arrChar, sizeof(arrChar));
	printf("Writing to arrChar[128]: \"%s\" -> HeLlO\n", arrChar);
	
	memcpy(arrChar, "HeLlO\0\0\0\0\0\0\0\0", sizeof("HeLlO\0\0\0\0\0\0\0\0"));
	driver.write_buffer(arrChar128, (uint8_t *)arrChar, sizeof(arrChar));

	printf("INTERP = DONKEY.\n");

	uintptr_t addr = driver.alloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	driver.write(memoryPtr, addr);
	MessageBox(NULL, "Press OK to free\n", "", MB_OK);
	driver.free(addr);

	MessageBox(NULL, "Press OK to stress test reading\n", "", MB_OK);
	printf("Stress testing...\n");
	while (true)
	{
		int thing = driver.read<int>(varInt);
		printf("%i\n", thing);
	}
	
	std::cin.get();
	return 0;
}