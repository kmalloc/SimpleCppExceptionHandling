#include <iostream>
#include <stddef.h>
#include <string>

using namespace std;

class cs
{
    public:

        explicit cs(int i) :i_(i) { cout << "cs constructor:" << i << endl; }
        ~cs() { cout << "cs destructor:" << i_ << endl; }

    private:

        int i_;
};

void test_func3()
{
    cs c(33);
    cs c2(332);

    throw 3;

    cs c3(333);
    cout << "test func3" << endl;
}

void test_func3_2()
{
    cs c(32);
    cs c2(322);

    test_func3();

    cs c3(323);

    test_func3();
}

void test_func2() throw(int, string)
{
    cs c(22);

    cout << "test func2" << endl;
    try
    {
        test_func3_2();

        cs c2(222);
    }
    catch (int)
    {
        cout << "catch 2" << endl;
    }
}

void test_func1()
{
    cout << "test func1" << endl;
    try
    {
        test_func2();
    }
    catch (...)
    {
        cout << "catch 1" << endl;
    }
}

int main()
{
    test_func1();
    return 0;
}

