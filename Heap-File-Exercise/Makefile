bf:
	@echo " Compile bf_main ...";
	rm -f ./build/bf_main
	gcc -I ./include/ -L ./lib/ -Wl,-rpath,./lib/ ./examples/bf_main.c ./src/*.c -lbf -o ./build/bf_main -O2;

hp:
	@echo " Compile hp_main ...";
	rm -f ./build/hp_main
	gcc -I ./include/ -L ./lib/ -Wl,-rpath,./lib/ ./examples/hp_main.c ./src/*.c -lbf -o ./build/hp_main -O2


run-bf: bf
	@echo " Running bf_main ..."
	rm -f *.db
	./build/bf_main

run-hp: hp
	@echo " Running hp_main ..."
	rm -f *.db
	./build/hp_main






