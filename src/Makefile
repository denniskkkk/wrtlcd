LDFLAGS = -lpthread -lftdi -levent -lrt -O2
CFLAGS = -lpthread -lftdi -levent -lrt -O2

all: snet.o lcd.o lcd

lcd: lcd.o
	$(CC) $(LDFLAGS) snet.o lcd.o -o lcd

lcd.o: lcd.c
	$(CC) $(CFLAGS) -c lcd.c 

snet.o: snet.c
	$(CC) $(CFLAGS) -c snet.c

clean: 
	rm *.o lcd