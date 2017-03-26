test: pf.test
	@-sudo pfctl -F all 2> /dev/null
	sudo ./pf.test -test.v -test.coverprofile=coverage.out
	@-sudo pfctl -F all 2> /dev/null

pf.test: *.go
	go test -o pf.test -cover -c -v github.com/go-freebsd/pf

cover: coverage.out
	go tool cover -html=coverage.out -o coverage.html

clean:
	@-rm -f pf.test

