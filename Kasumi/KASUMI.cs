using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kasumi
{
    /// <summary>
    /// Реализация алгоритма шифрования KASUMI
    /// </summary>
    static class KASUMI
    {
        static Encoding encoding = Encoding.Default; // тип кодировки символов

        /// <summary>
        /// Исходный ключ
        /// </summary>
        static ushort[] key = { 0x123A, 0xCA70, 0xD8B6, 0x8F4A,
                               0x5E3D, 0xFCBA, 0x7233, 0xBCB9 };

        /// <summary>
        /// Раундовый ключ
        /// </summary>
        static ushort[] keyRound = new ushort[8];

        /// <summary>
        /// Массив для получения раундового ключа
        /// </summary>
        static ushort[] c ={ 0x0123, 0x4567, 0x89AB, 0xCDEF,
                             0xFEDC, 0xBA98, 0x7654, 0x3210};

        /// <summary>
        /// 7-битные s-блоки для замены
        /// </summary>
        static ushort[] s7 = {
            54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33,
            55, 113, 39, 114, 21, 67, 65, 12, 47, 73, 46, 27, 25, 111, 124, 81,
            53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40, 120, 104, 70, 71, 43,
            20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
            117, 116, 76, 11, 89, 106, 0, 125, 118, 99, 86, 69, 30, 57, 126, 87,
            112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35, 103, 32, 97, 28, 66,
            102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29, 115, 44,
            64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3 };

        /// <summary>
        /// 9-битные s-блоки для замены
        /// </summary>
        static ushort[] s9 = {
            167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
            183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
            175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
            95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
            165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
            501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421, 350, 163,
            232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
            344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,
            487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
            475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
            363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
            439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
            465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61, 244, 282,
            173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330,
            280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
            132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,
            35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
            50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
            72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
            185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
            1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
            336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
            47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
            414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
            266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
            311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
            485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
            312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
            284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
            97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
            438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
            43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461 };

        /// <summary>
        /// Зашифровка текста
        /// </summary>
        public static string Encode(string input)
        {
            ulong[] blocks = StringToBlocks64(input); // Преобразование строки в массив 64-битных блоков
            ulong[] result = new ulong[blocks.Length]; // Массив для результата зашифровки
            for (int j = 0; j < blocks.Length; j++) // Цикл для поблочной зашифровки
            {
                uint left = (uint)(blocks[j] >> 32); // Получение левой части блока
                uint right = (uint)blocks[j]; // Получение правой части блока

                uint temp;
                uint func;
                for (int i = 1; i < 9; i++) // Цикл для зашифровки
                {
                    GetKeyRound(i - 1); // Получение раундового ключа
                    temp = right;
                    right = left;
                    func = i % 2 == 1 ? FO(FL(left)) : FL(FO(left)); // вычисление раундовой функции в зависимости от чётности раунда
                    left = temp ^ func; // исключающее или
                }

                result[j] = ((ulong)left << 32) + right; // получение зашифрованного блока
            }

            return Blocks64ToString(result); // Преобразование массива 64-битных блоков в строку и возвращение результата
        }

        /// <summary>
        /// Дешифровка текста
        /// </summary>
        public static string Decode(string input)
        {
            ulong[] blocks = StringToBlocks64(input); // Преобразование строки в массив 64-битных блоков
            ulong[] result = new ulong[blocks.Length]; // Массив для результата зашифровки
            for (int j = 0; j < blocks.Length; j++) // Цикл для поблочной зашифровки
            {
                uint left = (uint)(blocks[j] >> 32); // Получение левой части блока
                uint right = (uint)blocks[j]; // Получение правой части блока

                uint temp;
                uint func;
                for (int i = 8; i > 0; i--) // Обратный цикл для дешифровки
                {
                    GetKeyRound(i - 1); // Получение раундового ключа
                    temp = left;
                    left = right;
                    func = i % 2 == 1 ? FO(FL(right)) : FL(FO(right)); // вычисление раундовой функции в зависимости от чётности раунда
                    right = temp ^ func; // исключающее или
                }

                result[j] = ((ulong)left << 32) + right; // получение дешифрованного блока
            }

            return Blocks64ToString(result); // Преобразование массива 64-битных блоков в строку и возвращение результата
        }

        /// <summary>
        /// Преобразование строки в массив 64-битных блоков данных
        /// </summary>
        static ulong[] StringToBlocks64(string text)
        {
            byte[] bytes = encoding.GetBytes(text); // Преобразование строки в массив байтов
            Array.Resize(ref bytes, (int)Math.Ceiling((double)bytes.Length / 8) * 8); // Добавление пустых байтов в массив для кратности 8
            ulong[] blocks = new ulong[bytes.Length / 8];
            for (int i = 0; i < bytes.Length; i += 8)
            {
                blocks[i / 8] = BitConverter.ToUInt64(bytes, i); // Считывание по 8 байтов в 64-битные блоки
            }

            return blocks;
        }

        /// <summary>
        /// Преобразование массива 64-битных блоков данных в строку
        /// </summary>
        static string Blocks64ToString(ulong[] blocks)
        {
            List<byte> bytes = new List<byte>(); // Пустой список для получения байтов из 64-битных блоков
            for (int i = 0; i < blocks.Length; i++) // Цикл для получения байтов
            {
                for (int j = 0; j <= 56; j += 8)
                {
                    bytes.Add(Convert.ToByte(blocks[i] << (56 - j) >> 56));
                }
            }
            return encoding.GetString(bytes.ToArray<byte>()); // Преобразование массива байтов в строку и возвращение результата
        }

        /// <summary>
        /// Получение раундового ключа
        /// </summary>
        static void GetKeyRound(int round)
        {
            ushort[] keyArr = new ushort[8]; // Временный массив для получения раундового ключа

            for (int i = 0; i < 8; i++)
            {
                keyArr[i] = ((ushort)(key[i] ^ c[i])); // исключающее или между массивом ключа и массивом C
            }

            keyRound[0] = ROL(keyArr[round], 1);
            keyRound[1] = keyArr[(round + 2) % 8];
            keyRound[2] = ROL(keyArr[(round + 1) % 8], 5);
            keyRound[3] = ROL(keyArr[(round + 5) % 8], 8);
            keyRound[4] = ROL(keyArr[(round + 6) % 8], 13);
            keyRound[5] = keyArr[(round + 4) % 8];
            keyRound[6] = keyArr[(round + 3) % 8];
            keyRound[7] = keyArr[(round + 7) % 8];
        }

        static uint FL(uint data)
        {
            ushort left = (ushort)(data >> 16); // получение левой части блока данных
            ushort right = (ushort)data; // получение правой части блока данных
            ushort a = (ushort)(left & keyRound[0]); // конъюнкция
            ushort b = (ushort)(right | keyRound[1]); // дизъюнкция
            right ^= ROL(a, 1); // исключающее или
            left ^= ROL(b, 1); // исключающее или

            data = ((uint)left << 16) + right; // получение цельного блока данных

            return data;
        }

        static uint FO(uint data)
        {
            ushort left = (ushort)(data >> 16); // получение левой части блока данных
            ushort right = (ushort)data; // получение правой части блока данных
            ushort temp = 0;
            for (int i = 1; i < 4; i++)
            {
                temp = right; // сохранение старого значения правой части
                right = (ushort)(FI((ushort)(left ^ keyRound[1 + i]), keyRound[4 + i]) ^ right);
                left = temp;
            }

            data = ((uint)left << 16) + right; // получение цельного блока данных

            return data;
        }

        static ushort FI(ushort data, ushort k)
        {
            ushort left = (ushort)(data >> 7); // получение левой части блока данных
            ushort right = (ushort)((ushort)(data << 9) >> 9); // получение правой части блока данных

            ushort k1 = (ushort)((ushort)(data << 9) >> 9); // получение левой части блока данных
            ushort k2 = (ushort)(data >> 7); // получение правой части блока данных

            // s9[index] и s7[index] получение соответствующих s-блоков
            ushort temp = left;
            left = right;
            right = (ushort)(s9[temp] ^ right);

            temp = left;
            left = (ushort)(right ^ k2);
            right = (ushort)(s7[temp] ^ TR(right) ^ k1);

            temp = left;
            left = right;
            right = (ushort)(s9[temp] ^ right);

            left = (ushort)(s7[left] ^ TR(right));

            data = (ushort)((left << 9) + right);

            return data;
        }

        /// <summary>
        /// Циклический сдвиг на n бит влево
        /// </summary>
        static ushort ROL(ushort num, int n)
        {
            return (ushort)(num << n | num >> (16 - n)); // дизъюнкция для перемещения первого бита в конец
        }

        /// <summary>
        /// Преобразует 9-битное значение x в 7-битное вычеркиванием из него двух старших битов
        /// </summary>
        static ushort TR(ushort num)
        {
            return (ushort)((ushort)(num << 9) >> 9);
        }
    }
}
