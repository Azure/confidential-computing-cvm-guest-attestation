#include "pch.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#ifdef PLATFORM_UNIX
#include <fstream>
#else PLATFORM_UNIX
#include <windows.h>


struct RawSMBIOSData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Size;
    BYTE    SMBIOSTableData[];
};

struct SmBiosStructure
{
    BYTE    Type;
    BYTE    Length;
    WORD    Handle;
};

struct SystemInfo : SmBiosStructure
{
    BYTE    Manufacturer;
    BYTE    ProductName;
    BYTE    Version;
    BYTE    SerialNumber;
    // Ver 2.1+
    BYTE    UUID[16];
    BYTE    Wakeup_Type;
    // Ver 2.4+
    BYTE    SKUNumber;
    BYTE    Family;
};

#endif

struct UUID
{
    unsigned long   Data1;
    unsigned short  Data2;
    unsigned short  Data3;
    unsigned char   Data4[8];
};

unsigned int GetSystemSmBios(unsigned char **outUuid)
{
#ifndef PLATFORM_UNIX
    DWORD smbiosSize = 0;
    UINT actualSize = GetSystemFirmwareTable('RSMB', 0, NULL, smbiosSize);

    if (actualSize == 0)
    {
        return 0;
    }

    PUCHAR smbiosBuffer = (PUCHAR)malloc(actualSize);

    if (smbiosBuffer == NULL)
    {
        return 0;
    }

    smbiosSize = GetSystemFirmwareTable('RSMB', 0, smbiosBuffer, actualSize);
    RawSMBIOSData* smbiosData = (RawSMBIOSData*)smbiosBuffer;
    ULONG i = 0;
    SmBiosStructure* smBiosStructure = NULL;
    bool properTermination = false;

    do
    {
        properTermination = false;

        // Check that the buffer contains at least one whole structure header
        if (i + sizeof(SmBiosStructure) < smbiosData->Size)
        {
            if (smbiosData->SMBIOSTableData[i] == 1)
            {
                // Found structure that matches type
                smBiosStructure = (SmBiosStructure*)&smbiosData->SMBIOSTableData[i];
            }

            // Jump to the end of the structure header
            i += smbiosData->SMBIOSTableData[i + 1];

            // Look for a double-null (\0\0), which indicates the end of the structure
            while (i + 1 < smbiosData->Size)
            {
                if ((smbiosData->SMBIOSTableData[i] == 0) && (smbiosData->SMBIOSTableData[i + 1] == 0))
                {
                    properTermination = true;
                    i += 2;
                    break;
                }

                ++i;
            }
        }
    } while (properTermination && !smBiosStructure);

    *outUuid = ((SystemInfo*)smBiosStructure)->UUID;

    return 16;
#else
#endif
}

std::string formatUUID(char* uuid, int size) {
    if (size == 0)
    {
        return "";
    }

    std::string uuidStr = "";
    struct UUID* uuid_t = (struct UUID*)uuid;

    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::right << std::setfill('0');
    oss << std::setw(8) << uuid_t->Data1 << "-";
    oss << std::setw(4) << uuid_t->Data2 << "-";
    oss << std::setw(4) << uuid_t->Data3 << "-";
    oss << std::setw(2) << (int)uuid_t->Data4[0];
    oss << std::setw(2) << (int)uuid_t->Data4[1] << "-";
    for (int i = 2; i < 8; i++)
    {
        oss << std::setw(2) << (int)uuid_t->Data4[i];
    }
    return oss.str();
}

std::string GetSystemUuid()
{
#ifndef PLATFORM_UNIX
    unsigned char* uuid = NULL;
    unsigned int size = GetSystemSmBios(&uuid);

    return formatUUID((char*)uuid, size);
#else
    std::ifstream file("/sys/class/dmi/id/product_uuid");
    std::string uuid;

    if (file.is_open()) {
        std::getline(file, uuid);
        file.close();
    } else {
        throw std::runtime_error("Unable to open /sys/class/dmi/id/product_uuid");
    }

    return uuid;
#endif
}

unsigned int GetVmid()
{
    unsigned char* uuid = NULL;
    unsigned int size = GetSystemSmBios(&uuid);

    if (size == 0)
    {
        return 0;
    }

    unsigned int vmid = 0;

    for (int i = 0; i < 16; i++)
    {
        printf("%02X", uuid[i]);
    }
    printf("\n");

    return vmid;
}