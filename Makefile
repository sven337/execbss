all: helloworld64 helloworld32 elfhack

elfhack: elfhack.c
	gcc elfhack.c -o elfhack -g -W

helloworld64: helloworld.c
	gcc helloworld.c -o helloworld64 -Xlinker -T ./my_x86_64.x

helloworld32: helloworld.c
	gcc helloworld.c -m32 -o helloworld32 -Xlinker -T ./my_i386.x

helloworld: helloworld.c
	gcc helloworld.c -o helloworld -g
