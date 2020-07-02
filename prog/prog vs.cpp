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

// ������� ����
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

// ������� ��������� �������
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

// ��������� ���-���� ������
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

// ��������� ���-���� ������ LITE VERSION
long long lite_get_hash(string password)
{
    const int coeff = 63; // �������� ������������������ �����
    long long hash = 0, coeff_pow = 1;
    for (size_t i = 0; i < password.size(); ++i)
    {
        // �������� '!' �� ���� �����
        // ������� ����������, ����� � ������ ���� '!!!!!' ��� ��� ���������
        hash += (password[i] - '!' + 1) * coeff_pow;
        coeff_pow *= coeff;
    }
    return hash;
}

// �������� ����� ����������� �����������
void func_regex(user* list_beg, int item_for_editing)
{
    string s_universal = "";  // ������ ��� ���������� ����
    bool b_universal = false; // ���� �������� ������������ ��������� ������ � �������� regex

    string s_field_name;  // ��� ����
    string s_regex_parms; // �������� regex

    // ������������� ���������� ������ ����
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

    // ������, ���� ���� �� ����� ������
    while (!b_universal)
    {
        s_universal = "";
        b_universal = true;

        regex regular(s_regex_parms);

        cout << s_field_name + " --> ";
        cin >> s_universal;

        // ����������� ����� �� ���� ������
        if (item_for_editing == 4) {
            regex reg_replace("[^0-9]*"); // �� ��� ��������
            s_universal = regex_replace(s_universal, reg_replace, "");
        }

        // ��������� ������
        if (!regex_match(s_universal.c_str(), regular))
        {
            // ���� �������
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
            // ���� �����
            // ������� ������ ������������ ��������������� ��������
            // ���� ������, �������� ���
            if (item_for_editing == 7)
                list_beg->uni[item_for_editing - 1] = get_hash(s_universal);
            // ���� ����� ��������, �������� � �������� ���
            else if (item_for_editing == 4)
            {
                // �������� ����� � ��������� ����
                regex reg_replace(R"((\d{1})(\d{3})(\d{3})(\d{2})(\d{2}))");
                s_universal = regex_replace(s_universal, reg_replace, "+$1-($2)-$3-$4-$5");

                list_beg->uni[item_for_editing - 1] = s_universal;
            }
            // ���� ���, �������� ����� � �������� ���
            else if (item_for_editing >= 1 && item_for_editing <= 3)
            {
                // ������ �������� ����
                s_universal[0] = toupper(s_universal[0]);

                for (int i = 1; i < s_universal.size(); i++)
                    s_universal[i] = tolower(s_universal[i]);

                list_beg->uni[item_for_editing - 1] = s_universal;
            }
            // ���� �����, ������ ����������
            else
                list_beg->uni[item_for_editing - 1] = s_universal;
        }
    }
}

// ���������� ������ �������������
user* func_read_file(string users_name, int& num_users)
{
    fstream check_file_data(users_name);
    // ���� ���� ��������, ���������
    if (check_file_data.peek() != EOF)
    {
        ifstream users_in(users_name);
        user* list_beg = new user;
        int user_index = 0; // ������ ������������

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
    // ����� ���������� NULL, ������ ������������� ����
    else
    {
        check_file_data.close();
        return NULL;
    }
}

// ��������� � ������� ���� ������� �������� ����� �������������
void func_add_ascii(user* list_beg, int** ascii_matrix, int index_cur_sym, int item_list_submenu)
{
    string s_field; // ������ ��������� �����
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

// ���� ascii_matrix
void func_f_ascii(int** ascii_matrix, int index_cur_sym, bool& f_ascii, int cur_user1, int cur_user2)
{
    for (int i = 0; i < index_cur_sym && f_ascii; i++)
        // ���� ���� �� ���� �� ���������� ����� ������, �� �� �� ����� �����
        if (ascii_matrix[cur_user1][i] < ascii_matrix[cur_user2][i])
            f_ascii = false;
}

// ������� ������ �������������
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

// ���������� ������������
void func_add_user(user*& list_beg, int& num_users)
{
    user* clone_list_beg = list_beg;

    // ���� ������ ����������
    // ��������� � ��������
    if (clone_list_beg != NULL)
        while (clone_list_beg->next != NULL)
            clone_list_beg = clone_list_beg->next;

    user* local_list_beg = new user;
    // �������������� ������ ������������
    cout << "***** New user *****\n";
    for (int i = 1; i < NUM_FIELD + 1; i++)
    {
        // ��������� �����, �.� �����������
        if (i == 6)
        {
            cout << "Login --> ";
            cin >> local_list_beg->uni[i - 1];
        }
        else
            func_regex(local_list_beg, i);
    }

    // ����� ������
    local_list_beg->index = num_users;
    local_list_beg->next = NULL;
    // ���� ���������, �� �������� ������ ������ �� ������ ������������
    if (list_beg != NULL)
        clone_list_beg->next = local_list_beg;
    // ����� ����� ������������ - ������� ������
    else
        list_beg = local_list_beg;

    cout << "***** User was added *****\n\n";
    num_users++;
}

// �������� ������������
void func_delete_user(user*& list_beg, int& num_users)
{
    int item_list_submenu = func_list_submenu(); // �������� ����� ����
    user* clone_list_beg = list_beg;
    int cur_del_index = 0;   // ������ �������� ���������� ������������
    string s_field1;         // �������� ������
    string s_field2;         // �������� ������
    bool b1_field = false;   // ���� ��������� ����� � ���������� ������� ������� ������������
    bool b2_field = false;   // ���� ��������� ����� � ���������� ������� ��������� �������������
    bool b_find_user = true; // �������� ������������� ������������

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

    // ���� ��������� ������������ - ������
    if (b1_field)
    {
        string check_password;
        cout << "Password --> ";
        cin >> check_password;

        // ���������� ���
        if (get_hash(check_password) == list_beg->uni[6])
        {
            // �������
            cur_del_index = list_beg->index;
            list_beg = list_beg->next;
            cout << "***** User was deleted *****\n\n";
        }
        else
            cout << "----- Password wrong -----\n\n";
    }
    // ���� �� ������
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

            // ��������� ���������� ������������
            if (b2_field)
            {
                string check_password;
                cout << "Password --> ";
                cin >> check_password;

                // ��������� ����
                if (get_hash(check_password) == clone_list_beg->next->uni[6])
                {
                    // �������
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

        // ���� ������������ �� ������ - ��������, ��� �� ����������
        if (!b2_field)
            b_find_user = false;
    }

    // ���� �� ������, ������� ��������� �� ����
    if (!b_find_user)
        cout << "----- User is not found -----\n\n";
    // �����, ���� ������
    else
    {
        clone_list_beg = list_beg;
        while (clone_list_beg != NULL)
        {
            // ��� ������� ������ �������� ��������� �� 1 (��������)
            if (clone_list_beg->index > cur_del_index)
                clone_list_beg->index--;
            clone_list_beg = clone_list_beg->next;
        }

        // �������� ���������� �������������
        num_users--;
    }
}

// ��������� ������������
void func_edit_user(user* list_beg)
{
    int item_list_submenu = func_list_submenu();
    string s_field1;      // �������� ������
    string s_field2;      // �������� ������
    bool b_field = false; // ���� ��������� ����� � ���������� ������� ������� ������������

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

        // ���� �����, �� ������� �� �����, �������� ������ �� �������� �������������� ������������
        if (b_field)
            break;
        else
            list_beg = list_beg->next;
    }

    // ���� �����
    if (b_field)
    {
        string check_password;
        cout << "Password --> ";
        cin >> check_password;

        // ��������� ����
        if (get_hash(check_password) == list_beg->uni[6])
        {
            // �����������
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

// ���������� �������� � ������
void func_add_space(user* list_beg, int& max_field1_size, int& max_field2_size, int item_list_submenu)
{
    user* clone_list_beg = list_beg->next;
    int num1_space = 0; // ���������� ����������� �������� � ����
    int num2_space = 0; // ���������� ����������� �������� � ����

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

    // ���� ������������
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

    // ��������� �������
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

// ���������� ������ �������������
void func_sort_list(user*& list_beg, int num_users, int max_field1_size, int max_field2_size)
{
    int item_list_submenu = func_list_submenu();

    func_add_space(list_beg, max_field1_size, max_field2_size, item_list_submenu); // ��������� ������� ��� ���������� ����������

    int** ascii_matrix = new int* [num_users]; // ������� ����� �������� ������� ������������ ��� ����������

    user* clone_list_beg = list_beg;
    user* helper;          // ��������������� ���������
    bool f_check_sort;     // ���� ��� �������� ��������������� ������
    int index_cur_sym;     // ������ �������� �������
    int ascii_matrix_size; // ���������� �������� ���� ����������

    // �������������� ���������� ��������, ����������� ��������
    if (item_list_submenu == 1)
        ascii_matrix_size = max_field1_size + max_field2_size;
    else if (item_list_submenu == 2 || item_list_submenu == 3)
        ascii_matrix_size = max_field1_size;

    // ��������
    for (int i = 0; i < num_users; i++)
    {
        ascii_matrix[i] = new int[ascii_matrix_size];
        for (int j = 0; j < ascii_matrix_size; j++)
            ascii_matrix[i][j] = 0;
    }

    f_check_sort = true; // ���� ��� �������� ��������������� ������
    index_cur_sym = 0;   // ������ �������� �������

    // ���������, ���� �� ����� ��������� ��� ������� ������
    while (index_cur_sym != ascii_matrix_size)
    {
        do
        {
            f_check_sort = true;
            clone_list_beg = list_beg;
            bool f_ascii = true; // ���� �������� ��������������� ��� ������������� �������� �������
            string s_field1;     // ������������ ����
            string s_field2;     // ������������ ����

            // ���������
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

            // ��������� ���� ������� � ������� �������������
            // ���� ��� ���� �������� ������������ ������ ����������,
            // � ������� ������� �� ��� (>=), �� ������ �������
            if ((int)s_field1[index_cur_sym] > (int)s_field2[index_cur_sym] && f_ascii)
            {
                helper = clone_list_beg->next;
                clone_list_beg->next = clone_list_beg->next->next;
                helper->next = clone_list_beg;
                list_beg = helper;
                f_check_sort = false;
            }

            // ��������� ���������
            // ��� �� ���������� ������������, ��������
            // ������ ������ ������������� (��������������� ����)
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

        } while (!f_check_sort); // false - ������ ��� �� ����������

        // ��������� ��� ������� �������� � �������
        func_add_ascii(list_beg, ascii_matrix, index_cur_sym, item_list_submenu);
        // ��������� 1, ����� ��������� ��������� �������
        index_cur_sym++;
    }

    // ������� �������
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

// ��������� ������ � ����
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
    string users_name = "users.txt";                        // ������ �������������
    int num_users = 0;                                      // ���������� �������������
    char item_list_menu;                                    // ����� �������� ����
    int max_field1_size = 0;                                // ������������ ������ ���� ��� ����������
    int max_field2_size = 0;                                // ������������ ������ ���� ����������
    user* list_beg = func_read_file(users_name, num_users); // ������������� ������

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