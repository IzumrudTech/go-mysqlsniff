rel:
	go build

debug:
	go build -tags "debug"

run:
	sudo ./go-dbsniff --addr="127.0.0.1:3306"
