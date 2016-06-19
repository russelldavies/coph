static:
	gcc -c streamprint.c
	ar -rcs libstreamprint.a streamprint.o
	go build --ldflags '-linkmode external -extldflags "-static"' coph.go

dynamic:
	gcc -shared -o libstreamprint.so streamprint.c
	go build coph.go
