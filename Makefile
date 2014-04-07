except : cxx_except_abi.cc main.cc
	g++ -g -Wall -o $@ $^

clean:
	rm except
