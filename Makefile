all: dev

dependencies:
	sudo apt-get install gcc-arm-linux-gnueabihf

dev:
	go build main.go

release:
	CROSS_COMPILE=arm-linux-gnueabihf- GOOS=linux GOARCH=arm go build main.go
