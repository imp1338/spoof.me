#pragma once
#include <execute/handlers/cpu/control_handler.hxx>
#include <definitions/definitions.hxx>

namespace gen_globals {
	inline e_structures::s_entries<GUID> PartitionInfoExGuidEntries[128] = {};
	inline e_structures::s_entries<char[21]> wwn_entries[128] = {};
	inline e_structures::s_entries<char[50]> serial_entries[128] = {};
}

namespace serial_gen
{
    char digitMap[10] = { 0 };
    char charMap[256] = { 0 };

    ULONG lcg(ULONG& value) {
        const ULONG a = 1664525;
        const ULONG c = 1013904223;
        value = a * value + c;
        return value;
    }

    void wwn_ch(ULONG seed) {
        for (char ch = '0'; ch <= '9'; ++ch) {
            if (digitMap[ch - '0'] != 0) {
                continue;
            }

            char newChar;
            do {
                newChar = '0' + (lcg(seed) % 10);
            } while (newChar == '0');
            digitMap[ch - '0'] = newChar;
        }

        for (char ch = 'A'; ch <= 'Z'; ++ch) {
            if (charMap[ch] != 0) {
                continue;
            }

            char newChar;
            do {
                newChar = 'A' + (lcg(seed) % 26);
            } while (newChar == ' ' || newChar == ' ' || newChar == ' ');
            charMap[ch] = newChar;
        }
    }

    void modify_wwn(PUCHAR buffer, size_t offset, size_t length) {
        ULONG seed = i_s_globals::global_seed;
        wwn_ch(seed);

        for (size_t i = offset; i < offset + length; i++) {

            if (buffer[i] >= '0' && buffer[i] <= '9') {
                buffer[i] = digitMap[buffer[i] - '0'];
            }
            if (buffer[i] == 0x0) {
                continue;
            }
            else if (buffer[i] >= 'A' && buffer[i] <= 'Z') {
                buffer[i] = charMap[buffer[i]];
            }
        }
    }

    VOID gen_detguid(_Out_ GUID* Guid, _In_ ULONG Seed)
    {
        RtlZeroMemory(Guid, sizeof(GUID));

        ULONG s = Seed;
        s ^= (s << 13);
        s ^= (s >> 17);
        s ^= (s << 5);

        Guid->Data1 = s;
        Guid->Data2 = (USHORT)(s >> 16);
        Guid->Data3 = (USHORT)(s ^ 0xBEEF);

        for (int i = 0; i < 8; i++)
        {
            s = (s * 1664525) + 1013904223;
            Guid->Data4[i] = (UCHAR)(s & 0xFF);
        }

        Guid->Data3 = (Guid->Data3 & 0x0FFF) | 0x4000;
        Guid->Data4[0] = (Guid->Data4[0] & 0x3F) | 0x80;
    }

    void gen_charmap(ULONG seed) {
        for (char ch = '0'; ch <= '9'; ++ch) {
            if (digitMap[ch - '0'] != 0) {
                continue;
            }

            char newChar;
            do {
                newChar = '0' + (lcg(seed) % 10);
            } while (newChar == '0' || newChar == 'W' || newChar == 'D' || newChar == 'C' || newChar == '-' || newChar == ' ' ||
                newChar == '_' || newChar == '"' || newChar == '.' || newChar == ';');
            digitMap[ch - '0'] = newChar;
        }

        for (char ch = 'A'; ch <= 'Z'; ++ch) {
            if (charMap[ch] != 0) {
                continue;
            }

            char newChar;
            do {
                newChar = 'A' + (lcg(seed) % 26);
            } while (newChar == 'W' || newChar == 'D' || newChar == 'C' || newChar == '-' || newChar == ' ' || newChar == '_' ||
                newChar == '"' || newChar == '.' || newChar == ';');
            charMap[ch] = newChar;
        }
    }

    __forceinline void normalize(char* s)
    {
        if (!s)
            return;

        size_t len = strlen(s);
        while (len > 0)
        {
            char c = s[len - 1];
            if (c == '.' || c == ' ' || c == '\t')
            {
                s[len - 1] = '\0';
                --len;
            }
            else
            {
                break;
            }
        }
    }

    bool IsAlphaNumeric(PUCHAR buffer, size_t length, bool allowdots = true)
    {
        for (size_t i = 0; i < length; i++)
        {
            if (!((buffer[i] >= '0' && buffer[i] <= '9') ||
                (buffer[i] >= 'A' && buffer[i] <= 'Z') ||
                (buffer[i] >= 'a' && buffer[i] <= 'z') ||
                (allowdots && buffer[i] == '.')))
            {
                return false;
            }
        }
        return true;
    }

    bool remove_trail(char* s)
    {
        if (!s)
            return false;

        size_t len = strlen(s);
        if (len == 0)
            return false;

        if (s[len - 1] == '.')
        {
            s[len - 1] = '\0';
            return true;
        }

        return false;
    }

    template <typename T>
    void swap_wwn(PUCHAR buffer, size_t offset, size_t length, e_structures::s_entries<T>(&entries)[128])
    {
        if (!buffer || length == 0 || length > 21)
            return;

        if (!IsAlphaNumeric(buffer + offset, length, true))
            return;

        for (int i = 0; i < 128; ++i)
        {
            if (!entries[i].InUse)
                continue;

            if (RtlCompareMemory(entries[i].g_Original, buffer + offset, length) == length || RtlCompareMemory(entries[i].g_Modified, buffer + offset, length) == length)
            {
                RtlCopyMemory(buffer + offset, entries[i].g_Modified, length);
                return;
            }
        }

        for (int i = 0; i < 128; ++i)
        {
            if (entries[i].InUse)
                continue;

            RtlZeroMemory(entries[i].g_Original, sizeof(entries[i].g_Original));
            RtlZeroMemory(entries[i].g_Modified, sizeof(entries[i].g_Modified));

            RtlCopyMemory(entries[i].g_Original, buffer + offset, length);
            RtlCopyMemory(entries[i].g_Modified, buffer + offset, length);

            modify_wwn((PUCHAR)entries[i].g_Modified, 0, length);
            entries[i].InUse = true;

            RtlCopyMemory(buffer + offset, entries[i].g_Modified, length);
            return;
        }
    }

    template <typename T>
    void swap_guid(GUID* guid, e_structures::s_entries<T>(&entries)[128])
    {
        if (!guid)
        {
            return;
        }

        for (int i = 0; i < 128; ++i)
        {
            if (!entries[i].InUse)
            {
                continue;
            }

            if (RtlCompareMemory(&entries[i].g_Original, guid, sizeof(GUID)) == sizeof(GUID) || RtlCompareMemory(&entries[i].g_Modified, guid, sizeof(GUID)) == sizeof(GUID))
            {
                *guid = entries[i].g_Modified;
                return;
            }
        }

        for (int i = 0; i < 128; ++i)
        {
            if (entries[i].InUse)
            {
                continue;
            }

            entries[i].g_Original = *guid;
            gen_detguid(&entries[i].g_Modified, i_s_globals::global_seed ^ guid->Data1);
            entries[i].InUse = true;
            *guid = entries[i].g_Modified;

            return;
        }
    }

    template <typename T>
    void swap_serial(char* serial, size_t length, e_structures::s_entries<T>(&entries)[128])
    {
        if (!serial || length == 0 || length > 50)
            return;

        char tmp[64] = { 0 };
        const size_t copyLen = min(length, sizeof(tmp));
        RtlCopyMemory(tmp, serial, copyLen);

        for (int i = 0; i < 128; ++i)
        {
            if (!entries[i].InUse)
                continue;

            if (RtlCompareMemory(entries[i].g_Original, tmp, copyLen) == copyLen ||
                RtlCompareMemory(entries[i].g_Modified, tmp, copyLen) == copyLen)
            {
                RtlCopyMemory(serial, entries[i].g_Modified, copyLen);
                return;
            }
        }

        for (int i = 0; i < 128; ++i)
        {
            if (entries[i].InUse)
                continue;

            RtlCopyMemory(entries[i].g_Original, tmp, copyLen);
            RtlCopyMemory(entries[i].g_Modified, tmp, copyLen);

            for (size_t j = 0; j < copyLen; ++j)
            {
                char& c = entries[i].g_Modified[j];

                if (c == ' ' || c == '-' || c == '_' || c == '"' ||
                    c == '.' || c == 'W' || c == 'D' || c == 'C' ||
                    c == ';' || c == '0')
                    continue;

                if (c >= '0' && c <= '9')
                    c = digitMap[c - '0'];
                else if (c >= 'A' && c <= 'Z')
                    c = charMap[c];
            }

            RtlCopyMemory(serial, entries[i].g_Modified, copyLen);

            entries[i].InUse = true;

            break;
        }
    }

    template <typename T>
    void swap_mac(char* mac, size_t length, e_structures::s_entries<T>(&entries)[128])
    {
#define MAC_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ARG(x) \
    (UCHAR)(x)[0], (UCHAR)(x)[1], (UCHAR)(x)[2], \
    (UCHAR)(x)[3], (UCHAR)(x)[4], (UCHAR)(x)[5]

        if (!mac || length == 0 || length > 6)
            return;

        char tmp[6] = { 0 };
        const size_t copyLen = min(length, sizeof(tmp));
        RtlCopyMemory(tmp, mac, copyLen);

        for (int i = 0; i < 128; ++i)
        {
            if (!entries[i].InUse)
                continue;

            if (RtlCompareMemory(entries[i].g_Original, tmp, copyLen) == copyLen ||
                RtlCompareMemory(entries[i].g_Modified, tmp, copyLen) == copyLen)
            {

                RtlCopyMemory(mac, entries[i].g_Modified, copyLen);
                return;
            }
        }

        for (int i = 0; i < 128; ++i)
        {
            if (entries[i].InUse)
                continue;

            RtlCopyMemory(entries[i].g_Original, tmp, copyLen);
            RtlCopyMemory(entries[i].g_Modified, tmp, copyLen);

            unsigned int seed = global_seed;

            for (size_t j = 0; j < copyLen; ++j)
            {
                seed ^= static_cast<unsigned char>(tmp[j]);
                seed *= 16777619u;
            }

            for (size_t j = 0; j < copyLen; ++j)
            {
                seed = seed * 1664525u + 1013904223u;
                entries[i].g_Modified[j] =
                    static_cast<char>(seed & 0xFF);
            }

            entries[i].g_Modified[0] &= 0xFE; // mcast bit
            entries[i].g_Modified[0] |= 0x02; // laa bit

            RtlCopyMemory(mac, entries[i].g_Modified, copyLen);

            entries[i].InUse = true;

            break;
        }
    }
}