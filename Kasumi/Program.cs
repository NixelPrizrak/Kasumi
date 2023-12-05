using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kasumi
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("Введите строку для зашифровки:");
                string input = Console.ReadLine();
                input = KASUMI.Encode(input);
                Console.WriteLine($"Строка после зашифровки: \n{input}");
                input = KASUMI.Decode(input);
                Console.WriteLine($"Строка после дешифровки: \n{input}");
                Console.WriteLine();
            }
        }
    }
}
