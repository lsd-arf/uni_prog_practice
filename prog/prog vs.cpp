#include <iostream>
#include <string>
#include <fstream>
#include <regex>
#include <curl/curl.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;
const int NUM_FIELD = 7;

struct user
{
    //uni[0] = last_name;
    //uni[1] = first_name;
    //uni[2] = middle_name;
    //uni[3] = phone;
    //uni[4] = email;
    //uni[5] = login;
    //uni[6] = password;
    string* uni = new string[NUM_FIELD];
    int index;
    user* next;
};

// главное меню
char func_list_menu()
{
    char item_list_menu;
    cout << "a)View user list\n";
    cout << "b)Add user\n";
    cout << "c)Delete user\n";
    cout << "d)Edit user\n";
    cout << "e)Save editing in file\n";
    cout << "f)Send message to user email\n";
    cout << "g)Sort by selected field\n";
    cout << "h)Exit\n";
    cout << "--> ";
    cin >> item_list_menu;
    cout << '\n';
    return item_list_menu;
}

// подменю некоторых пунктов
int func_list_submenu()
{
    int item_list_menu;
    cout << "1)by last-first name\n";
    cout << "2)by login\n";
    cout << "3)by phone\n";
    cout << "--> ";
    cin >> item_list_menu;
    cout << '\n';
    return item_list_menu;
}

// получение хеш-кода пароля
string get_hash(string& s_password) {
    MD5 hash;
    byte digest[MD5::DIGESTSIZE];

    hash.CalculateDigest(digest, (byte*)s_password.c_str(), s_password.length());

    HexEncoder encoder;
    string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;
}

// получение хэш-кода пароля LITE VERSION
long long lite_get_hash(string password)
{
    const int coeff = 63; // параметр последовательности суммы
    long long hash = 0, coeff_pow = 1;
    for (size_t i = 0; i < password.size(); ++i)
    {
        // отнимаем '!' от кода буквы
        // единицу прибавляем, чтобы у строки вида '!!!!!' хэш был ненулевой
        hash += (password[i] - '!' + 1) * coeff_pow;
        coeff_pow *= coeff;
    }
    return hash;
}

// проверка полей регулярными выражениями
void func_regex(user* list_beg, int item_for_editing)
{
    string s_universal = "";  // строка для заполнения поля
    bool b_universal = false; // флаг проверки соответствия введенных данных с шаблоном regex

    string s_field_name;  // имя поля
    string s_regex_parms; // параметр regex

    // идентификация выбранного пункта меню
    switch (item_for_editing)
    {
    case 1:
        s_regex_parms = "[a-zA-Z]+";
        s_field_name = "Last name";
        break;
    case 2:
        s_regex_parms = "[a-zA-Z]+";
        s_field_name = "First name";
        break;
    case 3:
        s_regex_parms = "[a-zA-Z]+";
        s_field_name = "Middle name";
        break;
    case 4:
        s_regex_parms = "[0-9]{11}";
        s_field_name = "Phone";
        break;
    case 5:
        s_regex_parms = "[0-9a-zA-Z-._]+@[0-9a-zA-Z-._]+[.][a-zA-Z]+";
        s_field_name = "Email";
        break;
    case 7:
        s_regex_parms = "(?=.*[0-9])(?=.*[!\"#$%&'()*+,-./:;<=>?@{\\]^_{|}])(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z!\"#$%&'()*+,-./:;<=>?@{\\]^_{|}]{8,}";
        s_field_name = "Password";
        break;
    }

    // вводим, пока поле не будет верным
    while (!b_universal)
    {
        s_universal = "";
        b_universal = true;

        regex regular(s_regex_parms);

        cout << s_field_name + " --> ";
        cin >> s_universal;

        // вытаскиваем цифры из поля номера
        if (item_for_editing == 4) {
            regex reg_replace("[^0-9]*"); // то что заменяем
            s_universal = regex_replace(s_universal, reg_replace, "");
        }

        // проверяем данные
        if (!regex_match(s_universal.c_str(), regular))
        {
            // если неверны
            b_universal = false;
            cout << '\n';
            cout << "----- " + s_field_name + " is incorrect, try again -----\n";
            if (item_for_editing == 1) {
                cout << "Correct last name must consist of lowercase and uppercase letters\n";
            }
            else if (item_for_editing == 2) {
                cout << "Correct first name must consist of lowercase and uppercase letters\n";
            }
            else if (item_for_editing == 3) {
                cout << "Correct middle name must consist of lowercase and uppercase letters\n";
            }
            else if (item_for_editing == 4) {
                cout << "Correct phone must consist 11 digits\n";
            }
            else if (item_for_editing == 5) {
                cout << "Correct email must be such as: username@example.com\n";
            }
            else if (item_for_editing == 7) {
                cout << "Correct password must consist of the following characters:\n";
                cout << "At least 1 lowercase letter\n";
                cout << "At least 1 uppercase letter\n";
                cout << "At least 1 digit\n";
                cout << "At least 1 other char\n";
                cout << "At least 8 char\n";
            }
            cout << '\n';
        }
        else
        {
            // если верны
            // каждому пункту сопоставляем соответствующие действия
            // если пароль, получаем хеш
            if (item_for_editing == 7)
                list_beg->uni[item_for_editing - 1] = get_hash(s_universal);
            // если номер телефона, приводим в красивый вид
            else if (item_for_editing == 4)
            {
                // приводим номер к красивому виду
                regex reg_replace(R"((\d{1})(\d{3})(\d{3})(\d{2})(\d{2}))");
                s_universal = regex_replace(s_universal, reg_replace, "+$1-($2)-$3-$4-$5");

                list_beg->uni[item_for_editing - 1] = s_universal;
            }
            // если фио, приводим также в красивый вид
            else if (item_for_editing >= 1 && item_for_editing <= 3)
            {
                // меняем регистры букв
                s_universal[0] = toupper(s_universal[0]);

                for (int i = 1; i < s_universal.size(); i++)
                    s_universal[i] = tolower(s_universal[i]);

                list_beg->uni[item_for_editing - 1] = s_universal;
            }
            // если емейл, просто записываем
            else
                list_beg->uni[item_for_editing - 1] = s_universal;
        }
    }
}

// считывание списка пользователей
user* func_read_file(string users_name, int& num_users)
{
    fstream check_file_data(users_name);
    // если файл непустой, считываем
    if (check_file_data.peek() != EOF)
    {
        ifstream users_in(users_name);
        user* list_beg = new user;
        int user_index = 0; // индекс пользователя

        for (int i = 0; i < NUM_FIELD; i++)
            users_in >> list_beg->uni[i];
        list_beg->index = user_index;
        list_beg->next = NULL;
        user* clone_list_beg = list_beg;

        while (!users_in.eof())
        {
            user* local_list_beg = new user;
            user_index++;
            for (int i = 0; i < NUM_FIELD; i++)
                users_in >> local_list_beg->uni[i];
            local_list_beg->index = user_index;
            local_list_beg->next = NULL;
            clone_list_beg->next = local_list_beg;
            clone_list_beg = clone_list_beg->next;
        }

        num_users = clone_list_beg->index + 1;
        users_in.close();
        return list_beg;
    }
    // иначе возвращаем NULL, список пользователей пуст
    else
    {
        check_file_data.close();
        return NULL;
    }
}

// добавляем в матрицу коды текущих символов полей пользователей
void func_add_ascii(user* list_beg, int** ascii_matrix, int index_cur_sym, int item_list_submenu)
{
    string s_field; // строка выбранных полей
    while (list_beg != NULL)
    {
        if (item_list_submenu == 1)
            s_field = list_beg->uni[0] + list_beg->uni[1];
        else if (item_list_submenu == 2)
            s_field = list_beg->uni[5];
        else if (item_list_submenu == 3)
            s_field = list_beg->uni[3];

        ascii_matrix[list_beg->index][index_cur_sym] = (int)(s_field)[index_cur_sym];
        list_beg = list_beg->next;
    }
}

// флаг ascii_matrix
void func_f_ascii(int** ascii_matrix, int index_cur_sym, bool& f_ascii, int cur_user1, int cur_user2)
{
    for (int i = 0; i < index_cur_sym && f_ascii; i++)
        // если хотя бы один из предыдущих кодов меньше, то он на своем месте
        if (ascii_matrix[cur_user1][i] < ascii_matrix[cur_user2][i])
            f_ascii = false;
}

// выводим список пользователей
void func_view_users(user* list_beg)
{
    while (list_beg != NULL)
    {
        for (int i = 0; i < NUM_FIELD; i++)
            cout << list_beg->uni[i] << endl;
        cout << endl;
        list_beg = list_beg->next;
    }
}

// добавление пользователя
void func_add_user(user*& list_beg, int& num_users)
{
    user* clone_list_beg = list_beg;

    // если список существует
    // переходим к крайнему
    if (clone_list_beg != NULL)
        while (clone_list_beg->next != NULL)
            clone_list_beg = clone_list_beg->next;

    user* local_list_beg = new user;
    // идентифицируем нового пользователя
    cout << "***** New user *****\n";
    for (int i = 1; i < NUM_FIELD + 1; i++)
    {
        // отдельный логин, т.к неограничен
        if (i == 6)
        {
            cout << "Login --> ";
            cin >> local_list_beg->uni[i - 1];
        }
        else
            func_regex(local_list_beg, i);
    }

    // новый индекс
    local_list_beg->index = num_users;
    local_list_beg->next = NULL;
    // если ненулевой, то крайнему ставим ссылку на нового пользователя
    if (list_beg != NULL)
        clone_list_beg->next = local_list_beg;
    // иначе новый пользователь - верхняя ссылка
    else
        list_beg = local_list_beg;

    cout << "***** User was added *****\n\n";
    num_users++;
}

// удаление пользователя
void func_delete_user(user*& list_beg, int& num_users)
{
    int item_list_submenu = func_list_submenu(); // выбираем пункт меню
    user* clone_list_beg = list_beg;
    int cur_del_index = 0;   // индекс текущего удаляемого пользователя
    string s_field1;         // вводимые данные
    string s_field2;         // вводимые данные
    bool b1_field = false;   // флаг сравнения полей с введенными данными первого пользователя
    bool b2_field = false;   // флаг сравнения полей с введенными данными остальных пользователей
    bool b_find_user = true; // проверка существования пользователя

    switch (item_list_submenu)
    {
    case 1:
        cout << "Last name --> ";
        cin >> s_field1;
        cout << "First name --> ";
        cin >> s_field2;
        b1_field = list_beg->uni[0] == s_field1 && list_beg->uni[1] == s_field2;
        break;
    case 2:
        cout << "Login --> ";
        cin >> s_field1;
        b1_field = list_beg->uni[5] == s_field1;
        break;
    case 3:
        cout << "Phone --> ";
        cin >> s_field1;
        b1_field = list_beg->uni[3] == s_field1;
        break;
    }

    // если найденный пользователь - первый
    if (b1_field)
    {
        string check_password;
        cout << "Password --> ";
        cin >> check_password;

        // сравниваем хеш
        if (get_hash(check_password) == list_beg->uni[6])
        {
            // удаляем
            cur_del_index = list_beg->index;
            list_beg = list_beg->next;
            cout << "***** User was deleted *****\n\n";
        }
        else
            cout << "----- Password wrong -----\n\n";
    }
    // если не первый
    else
    {
        while (clone_list_beg->next != NULL)
        {
            if (item_list_submenu == 1)
                b2_field = clone_list_beg->next->uni[0] == s_field1 && clone_list_beg->next->uni[1] == s_field2;
            else if (item_list_submenu == 2)
                b2_field = clone_list_beg->next->uni[5] == s_field1;
            else if (item_list_submenu == 3)
                b2_field = clone_list_beg->next->uni[3] == s_field1;

            // проверяем найденного пользователя
            if (b2_field)
            {
                string check_password;
                cout << "Password --> ";
                cin >> check_password;

                // проверяем хеши
                if (get_hash(check_password) == clone_list_beg->next->uni[6])
                {
                    // удаляем
                    cur_del_index = clone_list_beg->next->index;
                    clone_list_beg->next = clone_list_beg->next->next;
                    cout << "***** User was deleted *****\n\n";
                }
                else
                    cout << "----- Password wrong -----\n\n";

                break;
            }
            else
                clone_list_beg = clone_list_beg->next;
        }

        // если пользователь не найден - отмечаем, как не найденного
        if (!b2_field)
            b_find_user = false;
    }

    // если не найден, выводим сообщение об этом
    if (!b_find_user)
        cout << "----- User is not found -----\n\n";
    // иначе, если найден
    else
    {
        clone_list_beg = list_beg;
        while (clone_list_beg != NULL)
        {
            // все индексы больше текущего уменьшаем на 1 (сдвигаем)
            if (clone_list_beg->index > cur_del_index)
                clone_list_beg->index--;
            clone_list_beg = clone_list_beg->next;
        }

        // уменьшам количество пользователей
        num_users--;
    }
}

// изменение пользователя
void func_edit_user(user* list_beg)
{
    int item_list_submenu = func_list_submenu();
    string s_field1;      // вводимые данные
    string s_field2;      // вводимые данные
    bool b_field = false; // флаг сравнения полей с введенными данными первого пользователя

    switch (item_list_submenu)
    {
    case 1:
        cout << "Last name --> ";
        cin >> s_field1;
        cout << "First name --> ";
        cin >> s_field2;
        break;
    case 2:
        cout << "Login --> ";
        cin >> s_field1;
        break;
    case 3:
        cout << "Phone --> ";
        cin >> s_field1;
        break;
    }

    while (list_beg != NULL)
    {
        if (item_list_submenu == 1)
            b_field = list_beg->uni[0] == s_field1 && list_beg->uni[1] == s_field2;
        else if (item_list_submenu == 2)
            b_field = list_beg->uni[5] == s_field1;
        else if (item_list_submenu == 3)
            b_field = list_beg->uni[3] == s_field1;

        // если нашли, то выходим из цикла, сохраняя ссылку на текущего редактируемого пользователя
        if (b_field)
            break;
        else
            list_beg = list_beg->next;
    }

    // если нашли
    if (b_field)
    {
        string check_password;
        cout << "Password --> ";
        cin >> check_password;

        // проверяем хеши
        if (get_hash(check_password) == list_beg->uni[6])
        {
            // редактируем
            int item_for_editing;

            cout << "\n***** Editing for user *****\n";
            cout << "1)Last name\n";
            cout << "2)First name\n";
            cout << "3)Middle name\n";
            cout << "4)Phone\n";
            cout << "5)Email\n";
            cout << "6)Login\n";
            cout << "7)Password\n";
            cout << "--> ";
            cin >> item_for_editing;

            if (item_for_editing != 6)
                func_regex(list_beg, item_for_editing);
            else
                cin >> list_beg->uni[item_for_editing - 1];
            cout << "***** User was edited *****\n\n";
        }
        else
            cout << "----- Password wrong -----\n\n";
    }
    else
        cout << "----- User is not found -----\n\n";
}

// добавление пробелов в строки
void func_add_space(user* list_beg, int& max_field1_size, int& max_field2_size, int item_list_submenu)
{
    user* clone_list_beg = list_beg->next;
    int num1_space = 0; // количество добавленных пробелов в поле
    int num2_space = 0; // количество добавленных пробелов в поле

    switch (item_list_submenu)
    {
    case 1:
        max_field1_size = list_beg->uni[0].size();
        max_field2_size = list_beg->uni[1].size();
        break;
    case 2:
        max_field1_size = list_beg->uni[5].size();
        break;
    case 3:
        max_field1_size = list_beg->uni[3].size();
        break;
    }

    // ищем максимальную
    while (clone_list_beg != NULL)
    {
        if (item_list_submenu == 1)
        {
            if (clone_list_beg->uni[0].size() > max_field1_size)
                max_field1_size = clone_list_beg->uni[0].size();
            if (clone_list_beg->uni[1].size() > max_field2_size)
                max_field2_size = clone_list_beg->uni[1].size();
        }
        else if (item_list_submenu == 2)
        {
            if (clone_list_beg->uni[5].size() > max_field1_size)
                max_field1_size = clone_list_beg->uni[5].size();
        }
        else if (item_list_submenu == 3)
        {
            if (clone_list_beg->uni[3].size() > max_field1_size)
                max_field1_size = clone_list_beg->uni[3].size();
        }

        clone_list_beg = clone_list_beg->next;
    }

    // добавляем пробелы
    while (list_beg != NULL)
    {
        if (item_list_submenu == 1)
        {
            num1_space = max_field1_size - list_beg->uni[0].size();
            num2_space = max_field2_size - list_beg->uni[1].size();
            for (int i = 0; i < num1_space; i++)
                list_beg->uni[0] += ' ';
            for (int i = 0; i < num2_space; i++)
                list_beg->uni[1] += ' ';
        }
        else if (item_list_submenu == 2)
        {
            num1_space = max_field1_size - list_beg->uni[5].size();
            for (int i = 0; i < num1_space; i++)
                list_beg->uni[5] += ' ';
        }
        else if (item_list_submenu == 3)
        {
            num1_space = max_field1_size - list_beg->uni[3].size();
            for (int i = 0; i < num1_space; i++)
                list_beg->uni[3] += ' ';
        }

        list_beg = list_beg->next;
    }
}

// сортировка списка пользователей
void func_sort_list(user*& list_beg, int num_users, int max_field1_size, int max_field2_size)
{
    int item_list_submenu = func_list_submenu();

    func_add_space(list_beg, max_field1_size, max_field2_size, item_list_submenu); // добавляем пробелы для правильной сортировки

    int** ascii_matrix = new int* [num_users]; // матрица кодов символов каждого пользователя для сортировки

    user* clone_list_beg = list_beg;
    user* helper;          // вспомогательный указатель
    bool f_check_sort;     // флаг для проверки упорядоченности списка
    int index_cur_sym;     // индекс текущего символа
    int ascii_matrix_size; // количество символов поля сортировки

    // инициализируем количество символов, считываемых матрицей
    if (item_list_submenu == 1)
        ascii_matrix_size = max_field1_size + max_field2_size;
    else if (item_list_submenu == 2 || item_list_submenu == 3)
        ascii_matrix_size = max_field1_size;

    // обнуляем
    for (int i = 0; i < num_users; i++)
    {
        ascii_matrix[i] = new int[ascii_matrix_size];
        for (int j = 0; j < ascii_matrix_size; j++)
            ascii_matrix[i][j] = 0;
    }

    f_check_sort = true; // флаг для проверки упорядоченности списка
    index_cur_sym = 0;   // индекс текущего символа

    // сортируем, пока не будут проверены все символы строки
    while (index_cur_sym != ascii_matrix_size)
    {
        do
        {
            f_check_sort = true;
            clone_list_beg = list_beg;
            bool f_ascii = true; // флаг проверки упорядоченности уже установленных символов матрицы
            string s_field1;     // сравниваемые поля
            string s_field2;     // сравниваемые поля

            // проверяем
            func_f_ascii(ascii_matrix, index_cur_sym, f_ascii, clone_list_beg->index, clone_list_beg->next->index);

            if (item_list_submenu == 1)
            {
                s_field1 = clone_list_beg->uni[0] + clone_list_beg->uni[1];
                s_field2 = clone_list_beg->next->uni[0] + clone_list_beg->next->uni[1];
            }
            else if (item_list_submenu == 2)
            {
                s_field1 = clone_list_beg->uni[5];
                s_field2 = clone_list_beg->next->uni[5];
            }
            else if (item_list_submenu == 3)
            {
                s_field1 = clone_list_beg->uni[3];
                s_field2 = clone_list_beg->next->uni[3];
            }

            // проверяем поля первого и второго пользователей
            // если код поля текущего пользователя больше следующего,
            // и нарушен порядок до них (>=), то меняем местами
            if ((int)s_field1[index_cur_sym] > (int)s_field2[index_cur_sym] && f_ascii)
            {
                helper = clone_list_beg->next;
                clone_list_beg->next = clone_list_beg->next->next;
                helper->next = clone_list_beg;
                list_beg = helper;
                f_check_sort = false;
            }

            // проверяем остальных
            // идём от начального пользователя, проверяя
            // ссылки тройки пользователей (несуществующего тоже)
            clone_list_beg = list_beg;
            if (clone_list_beg->next != NULL)
                while (clone_list_beg->next->next != NULL)
                {
                    f_ascii = true;
                    func_f_ascii(ascii_matrix, index_cur_sym, f_ascii, clone_list_beg->next->index, clone_list_beg->next->next->index);

                    if (item_list_submenu == 1)
                    {
                        s_field1 = clone_list_beg->next->uni[0] + clone_list_beg->next->uni[1];
                        s_field2 = clone_list_beg->next->next->uni[0] + clone_list_beg->next->next->uni[1];
                    }
                    else if (item_list_submenu == 2)
                    {
                        s_field1 = clone_list_beg->next->uni[5];
                        s_field2 = clone_list_beg->next->next->uni[5];
                    }
                    else if (item_list_submenu == 3)
                    {
                        s_field1 = clone_list_beg->next->uni[3];
                        s_field2 = clone_list_beg->next->next->uni[3];
                    }

                    if ((int)s_field1[index_cur_sym] > (int)s_field2[index_cur_sym] && f_ascii)
                    {
                        helper = clone_list_beg->next->next;
                        clone_list_beg->next->next = clone_list_beg->next->next->next;
                        helper->next = clone_list_beg->next;
                        clone_list_beg->next = helper;
                        f_check_sort = false;
                    }
                    clone_list_beg = clone_list_beg->next;
                }

        } while (!f_check_sort); // false - список еще не упорядочен

        // добавляем код текущих символов в матрицу
        func_add_ascii(list_beg, ascii_matrix, index_cur_sym, item_list_submenu);
        // добавляем 1, чтобы проверять следующие символы
        index_cur_sym++;
    }

    // удаляем пробелы
    clone_list_beg = list_beg;
    while (clone_list_beg != NULL) {
        int num_field;
        int num_spaces = 0;
        int uni_field_size = 0;

        if (item_list_submenu == 1) {
            num_field = 0;
        }
        else if (item_list_submenu == 2) {
            num_field = 5;
        }
        else if (item_list_submenu == 3) {
            num_field = 3;
        }

        uni_field_size = clone_list_beg->uni[num_field].size();

        for (int i = uni_field_size - 1; i >= 0; i--) {
            if (clone_list_beg->uni[num_field][i] == ' ')
                num_spaces++;
            else
                break;
        }

        clone_list_beg->uni[num_field].erase(uni_field_size - num_spaces, num_spaces);

        if (item_list_submenu == 1) {
            num_field = 1;
            num_spaces = 0;
            uni_field_size = clone_list_beg->uni[num_field].size();

            for (int i = clone_list_beg->uni[num_field].size() - 1; i >= 0; i--) {
                if (clone_list_beg->uni[num_field][i] == ' ')
                    num_spaces++;
                else
                    break;
            }

            clone_list_beg->uni[num_field].erase(uni_field_size - num_spaces, num_spaces);
        }

        clone_list_beg = clone_list_beg->next;
    }

    cout << "***** Sort was completed *****\n\n";
}

// сохраняем данные в файл
void func_save_list(string users_name, user* list_beg)
{
    ofstream users_out(users_name);
    while (list_beg != NULL)
    {
        for (int i = 0; i < NUM_FIELD - 1; i++)
            users_out << list_beg->uni[i] << endl;
        users_out << list_beg->uni[6];
        if (list_beg->next != NULL)
            users_out << endl
            << endl;
        list_beg = list_beg->next;
    }
    users_out.close();

    cout << "***** User list was saved *****\n\n";
}

int main()
{
    system("cls");
    string users_name = "users.txt";                        // список пользователей
    int num_users = 0;                                      // количество пользователей
    char item_list_menu;                                    // пункт главного меню
    int max_field1_size = 0;                                // максимальный размер поля для сортировки
    int max_field2_size = 0;                                // максимальный размер поля сортировки
    user* list_beg = func_read_file(users_name, num_users); // инициализация списка

    do
    {
        system("cls");
        item_list_menu = func_list_menu();
        switch (item_list_menu)
        {
        case 'a':
            if (list_beg == NULL)
                cout << "----- User list is empty -----\n\n";
            else
                func_view_users(list_beg);
            break;
        case 'b':
            func_add_user(list_beg, num_users);
            break;
        case 'c':
            if (list_beg == NULL)
                cout << "----- User list is empty -----\n\n";
            else
                func_delete_user(list_beg, num_users);
            break;
        case 'd':
            if (list_beg == NULL)
                cout << "----- User list is empty -----\n\n";
            else
                func_edit_user(list_beg);
            break;
        case 'e':
            func_save_list(users_name, list_beg);
            break;
        case 'f':
            break;
        case 'g':
            if (list_beg == NULL)
                cout << "----- User list is empty -----\n\n";
            else if (list_beg->next == NULL)
                cout << "***** Sort was completed *****\n\n";
            else
                func_sort_list(list_beg, num_users, max_field1_size, max_field2_size);
            break;
        }
        if (item_list_menu != 'h')
            system("pause");
    } while (item_list_menu != 'h');
}