all: test_read test_write random_read

test_read: test_read.o
	gcc -o $@.x $^ -lpthread

test_write: test_write.o
	gcc -o $@.x $^

random_read: random_read.o
	gcc -o $@.x $^

%.o: %.c
	gcc -c $<

clean:
	$(RM) test_read.x test_write.x
	$(RM) *.o
