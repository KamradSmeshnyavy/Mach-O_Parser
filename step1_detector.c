#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Использование: %s <файл>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file)
    {
        printf("Ошибка: не могу открыть файл %s\n", argv[1]);
        return 1;
    }

    // Читаем магическое число (первые 4 байта)
    uint32_t magic;
    if (fread(&magic, sizeof(uint32_t), 1, file) != 1)
    {
        printf("Ошибка: не могу прочитать файл\n");
        fclose(file);
        return 1;
    }

    fclose(file);

    // Проверяем магические числа
    printf("Магическое число: 0x%x\n", magic);

    switch (magic)
    {
    case MH_MAGIC:
        printf("Это 32-битный Mach-O файл (little-endian)\n");
        break;
    case MH_CIGAM:
        printf("Это 32-битный Mach-O файл (big-endian)\n");
        break;
    case MH_MAGIC_64:
        printf("Это 64-битный Mach-O файл (little-endian)\n");
        break;
    case MH_CIGAM_64:
        printf("Это 64-битный Mach-O файл (big-endian)\n");
        break;
    case FAT_MAGIC:
        printf("Это Universal Binary (Fat) - несколько архитектур\n");
        break;
    default:
        printf("Это не Mach-O файл\n");
    }

    return 0;
}
