all: helloworld32 helloworldarm elfhack hellopreloadarm.so hellopreload32.so

elfhack: elfhack.c
	gcc elfhack.c -o elfhack -g -W

helloworld64: helloworld.c my_x86_64.x
	gcc helloworld.c -o helloworld64 -Xlinker -T ./my_x86_64.x -Wl,-E

helloworld32: helloworld.c my_i386.x
	gcc helloworld.c -m32 -o helloworld32 -Xlinker -T ./my_i386.x -Wl,-E,-q,-z,now 

hellopreload32.so: hellopreload.c my_i386.x
	gcc hellopreload.c -m32 -o hellopreload32.so -Xlinker -T ./my_i386.xs -Wl,-E,-q,-z,now -fPIC -shared -ldl


helloworldarm: helloworld.c my_arm.x
	../arm-2009q1/bin/arm-none-linux-gnueabi-gcc helloworld.c -o helloworldarm -Xlinker -T ./my_arm.x -Wl,-E,-q,-z,now

hellopreloadarm.so: hellopreload.c my_arm.x
	../arm-2009q1/bin/arm-none-linux-gnueabi-gcc hellopreload.c -fPIC -shared -o hellopreloadarm.so -Xlinker -T ./my_arm.x -Wl,-E,-q,-z,now -ldl
