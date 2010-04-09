CC = gcc
LD = ld
RM = -rm -rf
AR = ar
INCLUDES = -I/usr/include
LD_LIBRARY_PATH = LD_LIBRARY_PATH:/usr/local/lib

CFLAGS =  $(INCLUDES) -Wall -g 

targets = gtmon

all: $(targets)

clean:
	$(RM) *.o $(targets)

gtmon:	sys_mon.c
		$(CC) $(CFLAGS) $(LDFLAGS) -o $@ sys_mon.c
		
.DEFAULT : all
.PHONY : clean all

