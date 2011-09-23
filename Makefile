all: 
	cd src/ ; $(MAKE)

clean: 
	rm -f *~
	rm -f include/*~
	rm -f scripts/*~
	cd src/ ; $(MAKE) clean
