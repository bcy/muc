all: 
	cd src/ ; $(MAKE)
	./create_room.sh
	./create_crontab_file.sh

clean: 
	rm -f *~
	rm -f crontab_file
	rm -f include/*~
	rm -f scripts/*~
	cd src/ ; $(MAKE) clean
