static:
	git clone --depth 1 https://github.com/apple/cups
	cd cups && ./configure --enable-static --disable-shared && cd cups && make libcups.a && cd ../../
	go build --ldflags '"-s" -linkmode external -extldflags "-static"' coph.go

dynamic:
	git clone --depth 1 https://github.com/apple/cups
	cd cups && ./configure && cd cups && make libcups.a & cd ../../
	go build --ldflags '"-s"' coph.go

clean:
	rm -rf cups coph
