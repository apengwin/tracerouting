
WEBSOCKETDIR = ../websocketpp

BOOSTDIR =

CXXFLAGS += -I$(WEBSOCKET) \
            -I$(WEBSOCKETDIR) \
            -std=c++11 \
            -Wall \
            -pedantic
CXX = g++


all: srv

srv:
	$(CXX) $(CXXFLAGS) -lpcap filter.cc -o srv

clean:
	rm srv
