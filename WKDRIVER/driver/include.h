#pragma once
#include <stdint.h>
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>

#include <driver/xorstr.h>


#define printf(text, ...) DbgPrintEx(DPFLTR_IHVBUS_ID, 0, XORS("[WKD]: " text), ##__VA_ARGS__)