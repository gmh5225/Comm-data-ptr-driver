#pragma once
#include <driver/defs.h>



namespace kernel
{
	class driver
	{
	public:
		driver();
		~driver();

	public:
		uint32_t pid;

		void attach(uint32_t pid) { this->pid = pid; }
		bool init();


		void unload();

		uintptr_t get_process_module(const char *name);
		uintptr_t get_process_base(uint32_t _pid = 0);

		bool read_buffer(uintptr_t addr, uint8_t *buffer, size_t size, size_t *transfer = nullptr);
		bool write_buffer(uintptr_t addr, uint8_t *buffer, size_t size, size_t *transfer = nullptr);

		template<typename Value_T>
		Value_T read(uintptr_t addr)
		{
			Value_T val;
			if (!this->read_buffer(addr, (uint8_t *)&val, sizeof(Value_T)))
				memset((void *)&val, 0, sizeof(val));
			return val;
		}

		template<typename Value_T>
		void write(uintptr_t addr, Value_T val) { this->write_buffer(addr, (uint8_t *)&val, sizeof(Value_T)); }



		uintptr_t alloc(uintptr_t addr, size_t size, uint32_t alloc_flags, uint32_t protection);
		void free(uintptr_t addr);
		void protect(uintptr_t addr, size_t size, uint32_t protection);
	};
}