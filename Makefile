CFLAGS= -pthread -g
END_NAME= overseer

all:
	g++ $(CFLAGS) *.cpp -o $(END_NAME)

clean:
	rm -rf $(END_NAME)